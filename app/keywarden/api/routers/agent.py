import secrets
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv4_address, validate_ipv6_address
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.http import HttpRequest
from django.utils.dateparse import parse_datetime
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from ninja import Body, Router, Schema
from ninja.errors import HttpError
from pydantic import Field
from guardian.shortcuts import get_users_with_perms

from apps.access.models import AccessRequest
from apps.core.rbac import require_perms
from apps.keys.certificates import get_active_ca
from apps.keys.models import SSHKey
from apps.keys.utils import render_system_username
from apps.servers.models import (
    AgentCertificateAuthority,
    EnrollmentToken,
    Server,
    ServerAuditLog,
    ServerAccount,
    ServerLogSource,
    hostname_validator,
)
from apps.telemetry.models import TelemetryEvent
from keywarden.api.security import AgentPrincipal, AgentTokenAuth, hash_agent_token


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
    agent_api_token: str


class LogEventIn(Schema):
    timestamp: str
    category: str
    event_type: str
    source_kind: Optional[str] = None
    source_name: Optional[str] = None
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


class LogSourceConfigOut(Schema):
    source_id: str
    kind: str
    name: str
    service_unit: Optional[str] = None
    file_path: Optional[str] = None
    parser: str = "none"
    include_matches: dict = Field(default_factory=dict)
    exclude_matches: dict = Field(default_factory=dict)
    category: str
    event_type: str


class AgentHeartbeatIn(Schema):
    host: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    ping_ms: Optional[int] = None


def build_router() -> Router:
    router = Router()
    agent_auth = AgentTokenAuth()

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
                agent_api_token = _issue_agent_api_token()
                server.agent_enrolled_at = timezone.now()
                server.agent_cert_fingerprint = fingerprint
                server.agent_cert_serial = serial
                server.agent_api_token_hash = hash_agent_token(agent_api_token)
                server.save(
                    update_fields=[
                        "agent_enrolled_at",
                        "agent_cert_fingerprint",
                        "agent_cert_serial",
                        "agent_api_token_hash",
                    ]
                )
        except IntegrityError:
            raise HttpError(409, "Server already enrolled")

        return AgentEnrollOut(
            server_id=str(server.id),
            client_cert_pem=cert_pem,
            ca_cert_pem=ca_pem,
            agent_api_token=agent_api_token,
        )

    @router.get("/servers/{server_id}/authorized-keys", response=List[AuthorizedKeyOut])
    def authorized_keys(request: HttpRequest, server_id: int):
        """Resolve the effective authorized_keys list for a server.

        Auth: required (admin/operator via API).
        Permissions: requires view access to servers and keys.
        Behavior: uses access request scopes + active SSH keys to produce
        the exact key list the agent should deploy to the server.
        Rationale: this is the policy enforcement point for per-user access.
        """
        require_perms(
            request,
            "servers.view_server",
            "keys.view_sshkey",
        )
        server = _get_server_or_404(server_id)
        users = _resolve_access_users(server, include_shell=True, include_users=False)
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

    @router.get("/servers/{server_id}/accounts", response=List[AccountAccessOut], auth=agent_auth)
    def account_access(request: HttpRequest, server_id: int):
        """List accounts that should exist on a server.

        Auth: per-agent bearer token issued at enrollment.
        Behavior: resolves active users with approved shell/users scopes.
        Rationale: drives agent-side account provisioning.
        """
        _require_agent_access(request, server_id)
        server = _get_server_or_404(server_id)
        users = _resolve_access_users(server, include_shell=True, include_users=True)
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

    @router.get("/servers/{server_id}/ssh-ca", auth=agent_auth)
    @csrf_exempt
    def ssh_ca(request: HttpRequest, server_id: int):
        """Return the active SSH user CA public key for agents.

        Auth: per-agent bearer token issued at enrollment.
        """
        _require_agent_access(request, server_id)
        _ = _get_server_or_404(server_id)
        ca = get_active_ca()
        if not ca.public_key:
            raise HttpError(404, "SSH CA not configured")
        return {"public_key": ca.public_key, "fingerprint": ca.fingerprint}

    @router.post("/servers/{server_id}/sync-report", response=SyncReportOut, auth=agent_auth)
    @csrf_exempt
    def sync_report(request: HttpRequest, server_id: int, payload: SyncReportIn = Body(...)):
        """Record an agent sync report for a server.

        Auth: per-agent bearer token issued at enrollment.
        Behavior: stores a telemetry event with counts of applied/revoked keys.
        Rationale: provides an audit trail of enforcement actions without
        requiring full log ingestion for every sync cycle.
        """
        _require_agent_access(request, server_id)
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

    @router.post("/servers/{server_id}/logs", response=LogIngestOut, auth=agent_auth)
    @csrf_exempt
    def ingest_logs(request: HttpRequest, server_id: int, payload: List[LogEventIn] = Body(...)):
        """Accept log batches from agents for audit collection.

        Auth: per-agent bearer token issued at enrollment.
        Behavior: accepts structured log events for later storage and indexing.
        Storage: events are persisted in the primary datastore and indexed per
        server for filtering in the server audit view.
        Rationale: this is the ingestion pipe for security audit logging.
        """
        _require_agent_access(request, server_id)
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Server not found")
        if not payload:
            return LogIngestOut(status="accepted", accepted=0)

        now = timezone.now()
        records: list[ServerAuditLog] = []
        for event in payload:
            records.append(
                ServerAuditLog(
                    server=server,
                    event_at=_parse_event_at(event.timestamp, now),
                    category=_truncate(event.category, 64, default="system"),
                    event_type=_truncate(event.event_type, 128, default="system"),
                    source_kind=_normalize_source_kind(event.source_kind, event.unit, event.fields),
                    source_name=_normalize_source_name(event.source_name, event.unit, event.fields),
                    unit=_truncate(event.unit, 128),
                    priority=_truncate(event.priority, 16),
                    hostname=_truncate(event.hostname, 253),
                    username=_truncate(event.username, 150),
                    principal=_truncate(event.principal, 255),
                    source_ip=_normalize_ip_any(event.source_ip),
                    session_id=_truncate(event.session_id, 128),
                    message=(event.message or "").strip(),
                    raw=event.raw or "",
                    fields=_coerce_fields(event.fields),
                )
            )
        ServerAuditLog.objects.bulk_create(records, batch_size=500)
        return LogIngestOut(status="accepted", accepted=len(records))

    @router.get("/servers/{server_id}/log-config", response=List[LogSourceConfigOut], auth=agent_auth)
    def log_config(request: HttpRequest, server_id: int):
        """Return server log-source configuration consumed by the agent.

        Auth: per-agent bearer token issued at enrollment.
        Behavior: returns enabled journal/service/file log sources for this server.
        Default: when no sources are defined, an empty list is returned and
        the agent falls back to current-boot journald collection.
        """
        _require_agent_access(request, server_id)
        server = _get_server_or_404(server_id)
        sources = list(server.log_sources.filter(enabled=True).order_by("kind", "name", "id"))
        if not sources:
            return []
        output: list[LogSourceConfigOut] = []
        for source in sources:
            output.append(
                LogSourceConfigOut(
                    source_id=str(source.id),
                    kind=source.kind,
                    name=(source.name or source.service_unit or source.file_path or "").strip(),
                    service_unit=(source.service_unit or "").strip() or None,
                    file_path=(source.file_path or "").strip() or None,
                    parser=(source.parser or "").strip() or "none",
                    include_matches=_clean_source_matches(source.include_matches),
                    exclude_matches=_clean_source_matches(source.exclude_matches),
                    category=(source.category_override or "").strip() or _default_category_for_source(source),
                    event_type=(source.event_type_override or "").strip() or _default_event_type_for_source(source),
                )
            )
        return output

    @router.post("/servers/{server_id}/heartbeat", response=SyncReportOut, auth=agent_auth)
    @csrf_exempt
    def heartbeat(request: HttpRequest, server_id: int, payload: AgentHeartbeatIn = Body(...)):
        """Update server host metadata (hostname/IPs) reported by the agent.

        Auth: per-agent bearer token issued at enrollment.
        Behavior: updates hostname/IPv4/IPv6 when they change (e.g., DHCP).
        Conflict: unique constraints are enforced; conflicts return 409.
        Rationale: keeps the server inventory accurate without manual edits.
        """
        _require_agent_access(request, server_id)
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


def _issue_agent_api_token() -> str:
    # Opaque, high-entropy token; only SHA-256 hash is stored server-side.
    return secrets.token_urlsafe(48)


def _require_agent_access(request: HttpRequest, server_id: int) -> None:
    principal = getattr(request, "auth", None)
    if not isinstance(principal, AgentPrincipal):
        raise HttpError(401, "Unauthorized")
    if principal.server_id is None:
        # Backward-compatibility path for legacy global token rollout.
        return
    if int(principal.server_id) != int(server_id):
        raise HttpError(403, "Forbidden")


def _resolve_access_users(server: Server, *, include_shell: bool, include_users: bool) -> list:
    now = timezone.now()
    user_ids: set[int] = set()
    active_access_qs = AccessRequest.objects.filter(
        server=server,
        status=AccessRequest.Status.APPROVED,
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
    active_access_user_ids = set(active_access_qs.values_list("requester_id", flat=True))

    scope_filter = Q()
    if include_shell:
        scope_filter |= Q(request_shell=True)
    if include_users:
        scope_filter |= Q(request_users=True)
    if scope_filter:
        scoped_access_qs = active_access_qs.filter(scope_filter)
        user_ids.update(scoped_access_qs.values_list("requester_id", flat=True))

    if include_shell:
        for user in get_users_with_perms(
            server,
            only_with_perms_in=["shell_server"],
            with_group_users=True,
            with_superusers=False,
        ):
            if getattr(user, "is_active", False):
                user_ids.add(user.id)
    if include_users:
        for user in get_users_with_perms(
            server,
            only_with_perms_in=["view_server"],
            with_group_users=True,
            with_superusers=False,
        ):
            if not getattr(user, "is_active", False):
                continue
            # If access requests exist for this user+server, scopes govern.
            if user.id in active_access_user_ids:
                continue
            user_ids.add(user.id)

    if not user_ids:
        return []

    User = get_user_model()
    users = list(User.objects.filter(id__in=user_ids, is_active=True))
    return sorted(users, key=lambda user: (user.username or "", user.id))


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


def _normalize_ip_any(value: Optional[str]) -> Optional[str]:
    candidate = (value or "").strip()
    if not candidate:
        return None
    for version in (4, 6):
        normalized = _normalize_ip(candidate, version)
        if normalized:
            return normalized
    return None


def _truncate(value: Optional[str], max_length: int, default: str = "") -> str:
    return (value or default).strip()[:max_length]


def _parse_event_at(value: Optional[str], fallback: datetime) -> datetime:
    timestamp = (value or "").strip()
    parsed = parse_datetime(timestamp) if timestamp else None
    if parsed is None:
        if timezone.is_naive(fallback):
            fallback = timezone.make_aware(fallback, dt_timezone.utc)
        return fallback.astimezone(dt_timezone.utc)
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, dt_timezone.utc)
    return parsed.astimezone(dt_timezone.utc)


def _coerce_fields(payload: Optional[dict]) -> dict:
    if not isinstance(payload, dict):
        return {}
    clean: dict[str, str] = {}
    for key, value in payload.items():
        key_text = str(key).strip()
        if not key_text:
            continue
        clean[key_text] = str(value)
    return clean


def _normalize_source_kind(kind: Optional[str], unit: Optional[str], fields: Optional[dict]) -> str:
    value = (kind or "").strip().lower()
    if value in {"service", "file", "journal"}:
        return value
    if (unit or "").strip() or ((fields or {}).get("_SYSTEMD_UNIT")):
        return "service"
    transport = (fields or {}).get("transport") or (fields or {}).get("_TRANSPORT")
    if transport:
        return "journal"
    file_path = (fields or {}).get("file_path")
    if file_path:
        return "file"
    return ""


def _normalize_source_name(name: Optional[str], unit: Optional[str], fields: Optional[dict]) -> str:
    value = _truncate(name, 512)
    if value:
        return value
    unit_value = _truncate(unit, 128)
    if unit_value:
        return unit_value
    raw_unit = _truncate((fields or {}).get("_SYSTEMD_UNIT"), 128)
    if raw_unit:
        return raw_unit
    return _truncate((fields or {}).get("file_path"), 512)


def _default_category_for_source(source: ServerLogSource) -> str:
    if source.kind == ServerLogSource.Kind.JOURNAL:
        include_matches = _clean_source_matches(source.include_matches)
        transports = include_matches.get("_TRANSPORT", [])
        if any(str(item).strip().lower() == "kernel" for item in transports):
            return "system"
        return "system"
    if source.kind == ServerLogSource.Kind.SERVICE:
        unit = (source.service_unit or "").lower()
        if unit in ("sshd.service", "ssh.service"):
            return "access"
        if unit == "sudo.service":
            return "auth"
        if unit in ("systemd-networkd.service", "networkmanager.service"):
            return "network"
    return "system"


def _default_event_type_for_source(source: ServerLogSource) -> str:
    if source.kind == ServerLogSource.Kind.JOURNAL:
        include_matches = _clean_source_matches(source.include_matches)
        transports = include_matches.get("_TRANSPORT", [])
        if any(str(item).strip().lower() == "kernel" for item in transports):
            return "kernel"
        return "system"
    if source.kind == ServerLogSource.Kind.FILE:
        return "file.line"
    if source.kind == ServerLogSource.Kind.SERVICE:
        unit = (source.service_unit or "").lower()
        if unit in ("sshd.service", "ssh.service"):
            return "ssh"
        if unit == "sudo.service":
            return "auth"
        if unit in ("systemd-networkd.service", "networkmanager.service"):
            return "network"
    return "system"


def _clean_source_matches(raw: Optional[dict]) -> dict:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, list[str]] = {}
    for key, value in raw.items():
        key_text = str(key).strip()
        if not key_text:
            continue
        values: list[str]
        if isinstance(value, list):
            values = [str(item).strip() for item in value if str(item).strip()]
        else:
            item_text = str(value).strip()
            values = [item_text] if item_text else []
        if values:
            out[key_text] = values
    return out


router = build_router()
