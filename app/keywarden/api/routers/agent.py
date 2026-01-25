from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.http import HttpRequest
from django.utils import timezone
from ninja import Router, Schema
from ninja.errors import HttpError
from pydantic import Field

from apps.core.rbac import require_perms
from apps.access.models import AccessRequest
from apps.keys.models import SSHKey
from apps.servers.models import AgentCertificateAuthority, EnrollmentToken, Server, hostname_validator
from apps.telemetry.models import TelemetryEvent


class AuthorizedKeyOut(Schema):
    user_id: int
    username: str
    email: str
    public_key: str
    fingerprint: str


class SyncReportIn(Schema):
    applied_count: int = Field(default=0, ge=0)
    revoked_count: int = Field(default=0, ge=0)
    message: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class SyncReportOut(Schema):
    status: str


class AgentEnrollIn(Schema):
    token: str
    csr_pem: str
    host: Optional[str] = None


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


def build_router() -> Router:
    router = Router()

    @router.post("/enroll", response=AgentEnrollOut, auth=None)
    def enroll_agent(request: HttpRequest, payload: AgentEnrollIn):
        """Enroll a server agent using a one-time token."""
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

        server = Server.objects.create(display_name=display_name, hostname=hostname)
        token.mark_used(server)
        token.save(update_fields=["used_at", "server"])

        csr = _load_csr((payload.csr_pem or "").strip())
        cert_pem, ca_pem, fingerprint, serial = _issue_client_cert(csr, host, server.id)
        server.agent_enrolled_at = timezone.now()
        server.agent_cert_fingerprint = fingerprint
        server.agent_cert_serial = serial
        server.save(update_fields=["agent_enrolled_at", "agent_cert_fingerprint", "agent_cert_serial"])

        return AgentEnrollOut(
            server_id=str(server.id),
            client_cert_pem=cert_pem,
            ca_cert_pem=ca_pem,
        )

    @router.get("/servers/{server_id}/authorized-keys", response=List[AuthorizedKeyOut])
    def authorized_keys(request: HttpRequest, server_id: int):
        """Return authorized public keys for a server (admin or operator)."""
        require_perms(
            request,
            "servers.view_server",
            "keys.view_sshkey",
            "access.view_accessrequest",
        )
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Server not found")
        now = timezone.now()
        access_qs = AccessRequest.objects.select_related("requester").filter(
            server=server,
            status=AccessRequest.Status.APPROVED,
        )
        access_qs = access_qs.filter(models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now))
        users = [req.requester for req in access_qs if req.requester and req.requester.is_active]
        keys = SSHKey.objects.select_related("user").filter(
            user__in=users,
            is_active=True,
            revoked_at__isnull=True,
        )
        return [
            AuthorizedKeyOut(
                user_id=key.user_id,
                username=key.user.username,
                email=key.user.email or "",
                public_key=key.public_key,
                fingerprint=key.fingerprint,
            )
            for key in keys
        ]

    @router.post("/servers/{server_id}/sync-report", response=SyncReportOut)
    def sync_report(request: HttpRequest, server_id: int, payload: SyncReportIn):
        """Record an agent sync report for a server (admin or operator)."""
        require_perms(request, "servers.view_server", "telemetry.add_telemetryevent")
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
        return SyncReportOut(status="ok")

    @router.post("/servers/{server_id}/logs", response=LogIngestOut, auth=None)
    def ingest_logs(request: HttpRequest, server_id: int, payload: List[LogEventIn]):
        """Accept log batches from agents (mTLS required at the edge)."""
        try:
            Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Server not found")
        # TODO: enqueue to Valkey and persist to SQLite slices.
        return LogIngestOut(status="accepted", accepted=len(payload))

    return router


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


router = build_router()
