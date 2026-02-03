from __future__ import annotations

import os
import re
import secrets
import subprocess
import tempfile
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from .models import SSHCertificate, SSHCertificateAuthority, SSHKey
from .utils import render_system_username


def get_active_ca(created_by=None) -> SSHCertificateAuthority:
    # Reuse the most recent active CA, or lazily create one if missing.
    ca = (
        SSHCertificateAuthority.objects.filter(is_active=True, revoked_at__isnull=True)
        .order_by("-created_at")
        .first()
    )
    if not ca:
        ca = SSHCertificateAuthority(created_by=created_by)
    ca.ensure_material()
    ca.save()
    return ca


def issue_certificate_for_key(key: SSHKey, created_by=None) -> SSHCertificate:
    if not key or not key.user_id:
        raise ValueError("key must have a user")
    ca = get_active_ca(created_by=created_by)
    # Principal must match the system account used for SSH logins.
    principal = render_system_username(key.user.username, key.user_id)
    now = timezone.now()
    valid_before = now + timedelta(days=settings.KEYWARDEN_USER_CERT_VALIDITY_DAYS)
    # Serial should be unique and non-guessable for audit purposes.
    serial = secrets.randbits(63)
    safe_name = _sanitize_label(key.name or "key")
    identity = f"keywarden-cert-{key.user_id}-{safe_name}-{key.id}"
    cert_text = _sign_public_key(
        ca_private_key=ca.private_key,
        ca_public_key=ca.public_key,
        public_key=key.public_key,
        identity=identity,
        principal=principal,
        serial=serial,
        validity_days=settings.KEYWARDEN_USER_CERT_VALIDITY_DAYS,
        comment=identity,
    )
    cert, _ = SSHCertificate.objects.update_or_create(
        key=key,
        defaults={
            "user": key.user,
            "certificate": cert_text,
            "serial": serial,
            "principals": [principal],
            "valid_after": now,
            "valid_before": valid_before,
            "revoked_at": None,
            "is_active": True,
        },
    )
    return cert


def revoke_certificate_for_key(key: SSHKey) -> None:
    if not key:
        return
    try:
        cert = key.certificate
    except SSHCertificate.DoesNotExist:
        return
    # Mark the cert as revoked but keep the record for audit/history.
    cert.revoke()
    cert.save(update_fields=["is_active", "revoked_at"])


def _sign_public_key(
    ca_private_key: str,
    ca_public_key: str,
    public_key: str,
    identity: str,
    principal: str,
    serial: int,
    validity_days: int,
    comment: str,
    validity_override: str | None = None,
) -> str:
    if not ca_private_key or not ca_public_key:
        raise RuntimeError("CA material missing")
    # Write key material into a temp dir to avoid persisting secrets.
    with tempfile.TemporaryDirectory() as tmpdir:
        ca_path = os.path.join(tmpdir, "user_ca")
        pubkey_path = os.path.join(tmpdir, "user.pub")
        _write_file(ca_path, ca_private_key, 0o600)
        _write_file(ca_path + ".pub", ca_public_key.strip() + "\n", 0o644)
        pubkey_with_comment = _ensure_comment(public_key, comment)
        _write_file(pubkey_path, pubkey_with_comment + "\n", 0o644)
        # Use ssh-keygen to sign the public key with the CA.
        cmd = [
            "ssh-keygen",
            "-s",
            ca_path,
            "-I",
            identity,
            "-n",
            principal,
            "-V",
            validity_override or f"+{validity_days}d",
            "-z",
            str(serial),
            pubkey_path,
        ]
        try:
            result = subprocess.run(cmd, check=True, capture_output=True)
        except FileNotFoundError as exc:
            raise RuntimeError("ssh-keygen not available") from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"ssh-keygen failed: {exc.stderr.decode('utf-8', 'ignore')}") from exc
        # ssh-keygen writes the cert alongside the input pubkey.
        cert_path = pubkey_path
        if cert_path.endswith(".pub"):
            cert_path = cert_path[: -len(".pub")]
        cert_path += "-cert.pub"
        if not os.path.exists(cert_path):
            stderr = result.stderr.decode("utf-8", "ignore")
            raise RuntimeError(f"ssh-keygen output missing: {cert_path} {stderr}")
        with open(cert_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()


def _ensure_comment(public_key: str, comment: str) -> str:
    # Preserve the key type and base64 payload; replace/append only the comment.
    parts = (public_key or "").strip().split()
    if len(parts) < 2:
        return public_key.strip()
    key_type, key_b64 = parts[0], parts[1]
    if not comment:
        return f"{key_type} {key_b64}"
    return f"{key_type} {key_b64} {comment}"


def _sanitize_label(value: str) -> str:
    # Reduce label to a safe, lowercase token for certificate identity.
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", (value or "").strip())
    cleaned = cleaned.strip("-_")
    if cleaned:
        return cleaned.lower()
    return "key"


def _write_file(path: str, data: str, mode: int) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(data)
    # Apply explicit permissions for key material.
    os.chmod(path, mode)
