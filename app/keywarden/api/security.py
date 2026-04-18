from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone
from secrets import compare_digest
from typing import Optional
from urllib.parse import unquote

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
from django.http import HttpRequest
from ninja.security import HttpBearer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed

from apps.servers.models import AgentCertificateAuthority, Server

logger = logging.getLogger(__name__)
_AGENT_AUTH_LOG_TTL_SECONDS = 60.0
_agent_auth_log_cache: dict[str, float] = {}


def _log_agent_auth_rejection(request: HttpRequest, reason: str, verify: str, cert_present: bool) -> None:
    path = str(getattr(request, "path", "") or "")
    key = f"{reason}|{path}"
    now = time.monotonic()
    previous = _agent_auth_log_cache.get(key)
    if previous is not None and (now - previous) < _AGENT_AUTH_LOG_TTL_SECONDS:
        return
    _agent_auth_log_cache[key] = now
    forwarded_for = str(request.META.get("HTTP_X_FORWARDED_FOR", "")).strip()
    remote_addr = str(request.META.get("REMOTE_ADDR", "")).strip()
    logger.warning(
        "agent auth rejected: reason=%s path=%s verify=%s cert_present=%s remote_addr=%s x_forwarded_for=%s",
        reason,
        path or "-",
        verify or "-",
        "yes" if cert_present else "no",
        remote_addr or "-",
        forwarded_for or "-",
    )


class JWTAuth(HttpBearer):
    """
    Auth via Authorization: Bearer <JWT>.
    Validates tokens using DRF SimpleJWT and returns the associated Django user.
    """

    def __init__(self) -> None:
        super().__init__()
        self._jwt_auth = JWTAuthentication()

    def authenticate(self, request: HttpRequest, token: str) -> Optional[AbstractBaseUser]:
        try:
            validated = self._jwt_auth.get_validated_token(token)
            user = self._jwt_auth.get_user(validated)
            return user
        except (InvalidToken, AuthenticationFailed):
            return None


class AgentTokenAuth(HttpBearer):
    """
    Auth via Authorization: Bearer <agent token>.
    Validates enrollment-issued per-server tokens first, with an optional
    global fallback from KEYWARDEN_AGENT_API_TOKEN for migration.
    """

    def authenticate(self, request: HttpRequest, token: str) -> Optional["AgentPrincipal"]:
        candidate = _normalize_agent_token(token)
        if not candidate:
            return None

        token_hash = hash_agent_token(candidate)
        server = Server.objects.filter(agent_api_token_hash=token_hash).only("id").first()
        if server:
            return AgentPrincipal(server_id=server.id, mode="server-token")

        configured = _normalize_agent_token(getattr(settings, "KEYWARDEN_AGENT_API_TOKEN", ""))
        if configured and compare_digest(candidate, configured):
            return AgentPrincipal(server_id=None, mode="global-token")
        return None


class AgentRuntimeAuth:
    """
    Runtime agent auth: prefer mTLS, with bearer-token compatibility fallback.

    Behavior:
    - If a mTLS context appears present, attempt mTLS validation first.
    - If mTLS is absent/invalid, fall back to enrollment-issued bearer token.
    """

    def __init__(self) -> None:
        self._mtls = AgentMTLSAuth()
        self._token = AgentTokenAuth()

    def __call__(self, request: HttpRequest) -> Optional["AgentPrincipal"]:
        return self.authenticate(request)

    def authenticate(self, request: HttpRequest) -> Optional["AgentPrincipal"]:
        bearer = _extract_bearer_token_from_request(request)
        allow_fallback = bool(
            getattr(settings, "KEYWARDEN_AGENT_RUNTIME_ALLOW_TOKEN_FALLBACK", True)
        )

        if not allow_fallback:
            return self._mtls.authenticate(request)

        # Fast path: no mTLS headers at all but bearer token is present.
        # This avoids noisy mTLS "missing verify" rejection logs on every poll.
        if bearer and not _request_has_mtls_context(request):
            return self._token.authenticate(request, bearer)

        principal = self._mtls.authenticate(request)
        if principal:
            return principal
        if bearer:
            return self._token.authenticate(request, bearer)
        return None


class AgentMTLSAuth:
    """
    Auth via mTLS client certificate details forwarded by nginx.
    Requires:
    - X-Keywarden-TLS-Client-Verify: SUCCESS or FAILED:* (client cert presented)
    - X-Keywarden-TLS-Client-Cert: URL-escaped PEM certificate
    """

    verify_header = "HTTP_X_KEYWARDEN_TLS_CLIENT_VERIFY"
    cert_header = "HTTP_X_KEYWARDEN_TLS_CLIENT_CERT"
    fingerprint_header = "HTTP_X_KEYWARDEN_TLS_CLIENT_FINGERPRINT"

    def __call__(self, request: HttpRequest) -> Optional["AgentPrincipal"]:
        return self.authenticate(request)

    def authenticate(self, request: HttpRequest) -> Optional["AgentPrincipal"]:
        verify = str(request.META.get(self.verify_header, "")).strip().upper()
        # With nginx `ssl_verify_client optional_no_ca`, a presented client cert
        # can arrive as SUCCESS or FAILED:<reason> depending on local CA trust.
        # Treat NONE/missing as unauthenticated, then enforce trust in-app.
        if not verify or verify == "NONE":
            _log_agent_auth_rejection(request, "missing_or_none_verify", verify, cert_present=False)
            return None
        if not (verify == "SUCCESS" or verify.startswith("FAILED")):
            _log_agent_auth_rejection(request, "unexpected_verify_state", verify, cert_present=False)
            return None

        cert_payload = str(request.META.get(self.cert_header, "")).strip()
        if not cert_payload:
            _log_agent_auth_rejection(request, "missing_client_cert_header", verify, cert_present=False)
            return None
        try:
            cert_pem = unquote(cert_payload)
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        except Exception:
            _log_agent_auth_rejection(request, "invalid_client_cert_payload", verify, cert_present=True)
            return None

        now = datetime.now(dt_timezone.utc)
        if hasattr(cert, "not_valid_before_utc"):
            not_valid_before = cert.not_valid_before_utc
            not_valid_after = cert.not_valid_after_utc
        else:
            not_valid_before = cert.not_valid_before.replace(tzinfo=dt_timezone.utc)
            not_valid_after = cert.not_valid_after.replace(tzinfo=dt_timezone.utc)
        if not_valid_before > now or not_valid_after <= now:
            _log_agent_auth_rejection(request, "client_cert_outside_validity_window", verify, cert_present=True)
            return None

        cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        cert_fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex()
        header_fingerprint = _normalize_fingerprint(request.META.get(self.fingerprint_header, ""))
        if header_fingerprint and not (
            compare_digest(header_fingerprint, cert_fingerprint)
            or compare_digest(header_fingerprint, cert_fingerprint_sha1)
        ):
            _log_agent_auth_rejection(request, "fingerprint_header_mismatch", verify, cert_present=True)
            return None

        if not _signed_by_active_agent_ca(cert):
            _log_agent_auth_rejection(request, "client_cert_not_signed_by_active_agent_ca", verify, cert_present=True)
            return None

        cert_serial = format(cert.serial_number, "x").lower().lstrip("0") or "0"
        server = (
            Server.objects.filter(agent_cert_fingerprint=cert_fingerprint)
            .only("id", "agent_cert_serial")
            .first()
        )
        if not server:
            _log_agent_auth_rejection(request, "no_server_for_cert_fingerprint", verify, cert_present=True)
            return None
        expected_serial = (server.agent_cert_serial or "").strip().lower().lstrip("0") or "0"
        if expected_serial and expected_serial != cert_serial:
            _log_agent_auth_rejection(request, "server_serial_mismatch", verify, cert_present=True)
            return None

        return AgentPrincipal(server_id=server.id, mode="mtls")


@dataclass(frozen=True)
class AgentPrincipal:
    server_id: Optional[int]
    mode: str


def _normalize_agent_token(value: object) -> str:
    token = str(value or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _extract_bearer_token_from_request(request: HttpRequest) -> str:
    authz = str(request.META.get("HTTP_AUTHORIZATION", "")).strip()
    if not authz:
        return ""
    parts = authz.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return _normalize_agent_token(parts[1])


def _request_has_mtls_context(request: HttpRequest) -> bool:
    verify = str(request.META.get(AgentMTLSAuth.verify_header, "")).strip().upper()
    cert_payload = str(request.META.get(AgentMTLSAuth.cert_header, "")).strip()
    if cert_payload:
        return True
    if verify and verify != "NONE":
        return True
    return False


def hash_agent_token(value: str) -> str:
    normalized = _normalize_agent_token(value)
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _normalize_fingerprint(value: object) -> str:
    return str(value or "").strip().lower().replace(":", "")


def _signed_by_active_agent_ca(cert: x509.Certificate) -> bool:
    active_cas = AgentCertificateAuthority.objects.filter(
        is_active=True, revoked_at__isnull=True
    ).only("cert_pem")
    for ca in active_cas:
        try:
            ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))
        except Exception:
            continue
        if cert.issuer != ca_cert.subject:
            continue
        if _verify_signed_by(cert, ca_cert):
            return True
    return False


def _verify_signed_by(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    public_key = ca_cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
