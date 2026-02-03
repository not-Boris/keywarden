from datetime import datetime, timedelta
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv4_address, validate_ipv6_address
from django.db import IntegrityError, transaction
from django.http import HttpRequest
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from ninja import Body, Router, Schema
from ninja.errors import HttpError
from pydantic import Field
from guardian.shortcuts import get_users_with_perms

from apps.core.rbac import require_perms
from apps.keys.certificates import get_active_ca
from apps.keys.models import SSHKey
from apps.keys.utils import render_system_username
from apps.servers.models import (
    AgentCertificateAuthority,
    EnrollmentToken,
    Server,
    ServerAccount,
    hostname_validator,
)
from apps.telemetry.models import TelemetryEvent


class AuthorizedKeyOut(Schema):
    user_id: int
    username: str
    email: str
    public_key: str
    fingerprint: str


class AccountKeyOut(Schema):
    public_key: str
    fingerprint: str


class AccountAccessOut(Schema):
    user_id: int
    username: str
    email: str
    system_username: str
    keys: List[AccountKeyOut] = Field(default_factory=list)


class AccountSyncIn(Schema):
    user_id: int
    system_username: str
    present: bool


class SyncReportIn(Schema):
    applied_count: int = Field(default=0, ge=0)
    revoked_count: int = Field(default=0, ge=0)
    message: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
    accounts: List[AccountSyncIn] = Field(default_factory=list)


class SyncReportOut(Schema):
    status: str


class AgentEnrollIn(Schema):
    token: str
    csr_pem: str
    host: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None


class AgentEnrollOut(Schema):
    server_id: str
    client_cert_pem: str
    ca_cert_pem: str


class LogEventIn(Schema):
    timestamp: str
    category: str
    event_type: str
    unit: Optional[str] = None
    priority: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    principal: Optional[str] = None
    source_ip: Optional[str] = None
    session_id: Optional[str] = None
    message: Optional[str] = None
    raw: Optional[str] = None
    fields: Optional[dict] = None


class LogIngestOut(Schema):
    status: str
    accepted: int


class AgentHeartbeatIn(Schema):
    host: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    ping_ms: Optional[int] = None


def build_router() -> Router:
    router = Router()

    @router.post("/enroll", response=AgentEnrollOut, auth=None)
    @csrf_exempt
    def enroll_agent(request: HttpRequest, payload: AgentEnrollIn = Body(...)):
        """Enroll a server agent using a one-time enrollment token.

        Auth: token only (no session/JWT); mTLS is not yet available until
        enrollment completes.
        Inputs: enrollment token + CSR from the agent, optional host/IP hints.
        Behavior:
        - Creates a Server record (agent is the source of truth for host/IP).
        - Marks the token as used (single-use).
        - Signs the CSR with the active Agent CA and returns client cert + CA.
        Rationale: this is the only supported server onboarding flow. If this
        endpoint is removed, agents cannot bootstrap mTLS credentials.
        """
        token_value = (payload.token or "").strip()
        if not token_value:
            raise HttpError(422, "Token required")
        try:
            token = EnrollmentToken.objects.get(token=token_value)
        except EnrollmentToken.DoesNotExist:
            raise HttpError(403, "Invalid token")
        if not token.is_valid():
            raise HttpError(403, "Token expired or already used")

        host = (payload.host or "").strip()[:253]
        display_name = host or "server"
        hostname = None
        if host:
            try:
                hostname_validator(host)
                hostname = host
            except ValidationError:
                hostname = None
        ipv4 = _normalize_ip(payload.ipv4, 4)
        ipv6 = _normalize_ip(payload.ipv6, 6)

        csr = _load_csr((payload.csr_pem or "").strip())
        try:
            with transaction.atomic():
                server = Server.objects.create(
                    display_name=display_name,
                    hostname=hostname,
                    ipv4=ipv4,
                    ipv6=ipv6,
                )
                token.mark_used(server)
                token.save(update_fields=["used_at", "server"])
                cert_pem, ca_pem, fingerprint, serial = _issue_client_cert(csr, host, server.id)
                server.agent_enrolled_at = timezone.now()
                server.agent_cert_fingerprint = fingerprint
                server.agent_cert_serial = serial
                server.save(update_fields=["agent_enrolled_at", "agent_cert_fingerprint", "agent_cert_serial"])
        except IntegrityError:
            raise HttpError(409, "Server already enrolled")

        return AgentEnrollOut(
            server_id=str(server.id),
            client_cert_pem=cert_pem,
            ca_cert_pem=ca_pem,
        )

    @router.get("/servers/{server_id}/authorized-keys", response=List[AuthorizedKeyOut])
    def authorized_keys(request: HttpRequest, server_id: int):
        """Resolve the effective authorized_keys list for a server.

        Auth: required (admin/operator via API).
        Permissions: requires view access to servers and keys.
        Behavior: uses server object permissions + active SSH keys to produce
        the exact key list the agent should deploy to the server.
        Rationale: this is the policy enforcement point for per-user access.
        """
        require_perms(
            request,
            "servers.view_server",
            "keys.view_sshkey",
        )
        server = _get_server_or_404(server_id)
        users = _resolve_access_users(server)
        key_map = _key_map_for_users(users)
        output: list[AuthorizedKeyOut] = []
        for user in users:
            for key in key_map.get(user.id, []):
                output.append(
                    AuthorizedKeyOut(
                        user_id=user.id,
                        username=user.username,
                        email=user.email or "",
                        public_key=key.public_key,
                        fingerprint=key.fingerprint,
                    )
                )
        return output

    @router.get("/servers/{server_id}/accounts", response=List[AccountAccessOut], auth=None)
    def account_access(request: HttpRequest, server_id: int):
        """List accounts that should exist on a server.

        Auth: mTLS expected at the edge (no session/JWT).
        Behavior: resolves active users with server object perms and their keys.
        Rationale: drives agent-side account provisioning.
        """
        server = _get_server_or_404(server_id)
        users = _resolve_access_users(server)
        return [
            AccountAccessOut(
                user_id=user.id,
                username=user.username,
                email=user.email or "",
                system_username=render_system_username(user.username, user.id),
                keys=[],
            )
            for user in users
        ]

    @router.get("/servers/{server_id}/ssh-ca", auth=None)
    @csrf_exempt
    def ssh_ca(request: HttpRequest, server_id: int):
        """Return the active SSH user CA public key for agents.

        Auth: mTLS expected at the edge (no session/JWT).
        """
        _ = _get_server_or_404(server_id)
        ca = get_active_ca()
        if not ca.public_key:
            raise HttpError(404, "SSH CA not configured")
        return {"public_key": ca.public_key, "fingerprint": ca.fingerprint}

    @router.post("/servers/{server_id}/sync-report", response=SyncReportOut, auth=None)
    @csrf_exempt
    def sync_report(request: HttpRequest, server_id: int, payload: SyncReportIn = Body(...)):
        """Record an agent sync report for a server.

        Auth: mTLS expected at the edge (no session/JWT).
        Behavior: stores a telemetry event with counts of applied/revoked keys.
        Rationale: provides an audit trail of enforcement actions without
        requiring full log ingestion for every sync cycle.
        """
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Server not found")
        TelemetryEvent.objects.create(
            event_type="agent_sync",
            server=server,
            success=True,
            source=TelemetryEvent.Source.AGENT,
            message=(payload.message or "").strip(),
            metadata={
                "applied_count": payload.applied_count,
                "revoked_count": payload.revoked_count,
                **(payload.metadata or {}),
            },
        )
        if payload.accounts:
            _update_server_accounts(server, payload.accounts)
        return SyncReportOut(status="ok")

    @router.post("/servers/{server_id}/logs", response=LogIngestOut, auth=None)
    @csrf_exempt
    def ingest_logs(request: HttpRequest, server_id: int, payload: List[LogEventIn] = Body(...)):
        """Accept log batches from agents for audit collection.

        Auth: mTLS expected at the edge (no session/JWT).
        Behavior: accepts structured log events for later storage and indexing.
        Storage: raw logs are persisted separately per-server (SQLite shards),
        not in the primary Postgres database.
        Rationale: this is the ingestion pipe for security audit logging.
        """
        try:
            Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Server not found")
        # TODO: enqueue to Valkey and persist to SQLite slices.
        return LogIngestOut(status="accepted", accepted=len(payload))

    @router.post("/servers/{server_id}/heartbeat", response=SyncReportOut, auth=None)
    @csrf_exempt
    def heartbeat(request: HttpRequest, server_id: int, payload: AgentHeartbeatIn = Body(...)):
        """Update server host metadata (hostname/IPs) reported by the agent.

        Auth: mTLS expected at the edge (no session/JWT).
        Behavior: updates hostname/IPv4/IPv6 when they change (e.g., DHCP).
        Conflict: unique constraints are enforced; conflicts return 409.
        Rationale: keeps the server inventory accurate without manual edits.
        """
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Server not found")
        updates: dict[str, str | int | datetime] = {}
        host = (payload.host or "").strip()[:253]
        if host:
            try:
                hostname_validator(host)
                if server.hostname != host:
                    updates["hostname"] = host
            except ValidationError:
                pass
        ipv4 = _normalize_ip(payload.ipv4, 4)
        if ipv4 and server.ipv4 != ipv4:
            updates["ipv4"] = ipv4
        ipv6 = _normalize_ip(payload.ipv6, 6)
        if ipv6 and server.ipv6 != ipv6:
            updates["ipv6"] = ipv6
        now = timezone.now()
        updates["last_heartbeat_at"] = now
        if payload.ping_ms is not None:
            updates["last_ping_ms"] = max(0, int(payload.ping_ms))
        if updates:
            for field, value in updates.items():
                setattr(server, field, value)
            try:
                server.save(update_fields=list(updates.keys()))
            except IntegrityError:
                raise HttpError(409, "Server address already in use")
        return SyncReportOut(status="ok")

    return router


def _get_server_or_404(server_id: int) -> Server:
    try:
        return Server.objects.get(id=server_id)
    except Server.DoesNotExist:
        raise HttpError(404, "Server not found")


def _resolve_access_users(server: Server) -> list:
    users = list(
        get_users_with_perms(
            server,
            only_with_perms_in=["view_server"],
            with_group_users=True,
            with_superusers=False,
        )
    )
    active = [user for user in users if getattr(user, "is_active", False)]
    return sorted(active, key=lambda user: (user.username or "", user.id))


def _key_map_for_users(users: list) -> dict[int, list[SSHKey]]:
    if not users:
        return {}
    keys = SSHKey.objects.select_related("user").filter(
        user__in=users,
        is_active=True,
        revoked_at__isnull=True,
    )
    key_map: dict[int, list[SSHKey]] = {}
    for key in keys:
        key_map.setdefault(key.user_id, []).append(key)
    return key_map


def _update_server_accounts(server: Server, accounts: list[AccountSyncIn]) -> None:
    user_ids = {account.user_id for account in accounts}
    if not user_ids:
        return
    User = get_user_model()
    users = {user.id: user for user in User.objects.filter(id__in=user_ids)}
    now = timezone.now()
    for account in accounts:
        user = users.get(account.user_id)
        if not user:
            continue
        ServerAccount.objects.update_or_create(
            server=server,
            user=user,
            defaults={
                "system_username": account.system_username,
                "is_present": account.present,
                "last_synced_at": now,
            },
        )


def _load_agent_ca() -> tuple[x509.Certificate, object, str]:
    ca = (
        AgentCertificateAuthority.objects.filter(is_active=True, revoked_at__isnull=True)
        .order_by("-created_at")
        .first()
    )
    if not ca:
        raise HttpError(500, "Agent CA not configured")
    try:
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))
        ca_key = serialization.load_pem_private_key(ca.key_pem.encode("utf-8"), password=None)
    except (ValueError, TypeError):
        raise HttpError(500, "Invalid agent CA material")
    return ca_cert, ca_key, ca.cert_pem


def _load_csr(csr_pem: str) -> x509.CertificateSigningRequest:
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except ValueError:
        raise HttpError(422, "Invalid CSR")
    if not csr.is_signature_valid:
        raise HttpError(422, "Invalid CSR signature")
    return csr


def _issue_client_cert(
    csr: x509.CertificateSigningRequest, host: str | None, server_id: int
) -> tuple[str, str, str, str]:
    ca_cert, ca_key, ca_pem = _load_agent_ca()
    now = datetime.utcnow()
    subject = csr.subject
    if len(subject) == 0:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"keywarden-agent-{server_id}")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=settings.KEYWARDEN_AGENT_CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    )
    if host:
        try:
            hostname_validator(host)
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        except ValidationError:
            pass
    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    serial = format(cert.serial_number, "x")
    return cert_pem, ca_pem, fingerprint, serial


def _normalize_ip(value: Optional[str], version: int) -> Optional[str]:
    if not value:
        return None
    try:
        if version == 4:
            validate_ipv4_address(value)
        else:
            validate_ipv6_address(value)
    except ValidationError:
        return None
    return value


router = build_router()
