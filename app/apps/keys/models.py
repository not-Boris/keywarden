from __future__ import annotations

import base64
import binascii
import hashlib
import os
import subprocess
import tempfile

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from apps.core.secret_files import looks_like_pem, read_secret_ref, write_secret_file


def parse_public_key(public_key: str) -> tuple[str, str, str]:
    trimmed = (public_key or "").strip()
    parts = trimmed.split()
    if len(parts) < 2:
        raise ValidationError("Invalid SSH public key format.")
    key_type, key_b64 = parts[0], parts[1]
    try:
        key_bytes = base64.b64decode(key_b64.encode("ascii"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("Invalid SSH public key format.") from exc
    digest = hashlib.sha256(key_bytes).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    return key_type, key_b64, fingerprint


class SSHKey(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="ssh_keys"
    )
    name = models.CharField(max_length=128)
    public_key = models.TextField()
    key_type = models.CharField(max_length=32)
    fingerprint = models.CharField(max_length=128, db_index=True)
    is_active = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "SSH key"
        verbose_name_plural = "SSH keys"
        indexes = [
            models.Index(fields=["user", "is_active"], name="keys_user_active_idx"),
            models.Index(fields=["fingerprint"], name="keys_fingerprint_idx"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "fingerprint"], name="unique_user_key_fingerprint"
            )
        ]
        ordering = ["-created_at"]

    def set_public_key(self, public_key: str) -> None:
        key_type, key_b64, fingerprint = parse_public_key(public_key)
        self.key_type = key_type
        self.fingerprint = fingerprint
        self.public_key = f"{key_type} {key_b64}"

    def revoke(self) -> None:
        self.is_active = False
        self.revoked_at = timezone.now()
        try:
            cert = self.certificate
        except SSHCertificate.DoesNotExist:
            return
        cert.revoke()
        cert.save(update_fields=["is_active", "revoked_at"])

    def __str__(self) -> str:
        return f"{self.name} ({self.user_id})"


class SSHCertificateAuthority(models.Model):
    name = models.CharField(max_length=128, default="Keywarden User SSH CA")
    public_key = models.TextField(blank=True)
    private_key = models.TextField(blank=True)
    fingerprint = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="ssh_certificate_authorities",
    )

    class Meta:
        verbose_name = "SSH certificate authority"
        verbose_name_plural = "SSH certificate authorities"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        status = "active" if self.is_active and not self.revoked_at else "revoked"
        return f"{self.name} ({status})"

    def revoke(self) -> None:
        self.is_active = False
        self.revoked_at = timezone.now()

    def get_private_key(self) -> str:
        file_payload = read_secret_ref(self.private_key, label="User CA private key")
        if file_payload:
            return file_payload
        inline_payload = (self.private_key or "").strip()
        if looks_like_pem(inline_payload):
            self.private_key = write_secret_file("user-ca-key", inline_payload)
            if self.pk:
                self.save(update_fields=["private_key"])
            return inline_payload
        return ""

    def ensure_material(self) -> None:
        if self.public_key and self.get_private_key():
            if not self.fingerprint:
                _, _, fingerprint = parse_public_key(self.public_key)
                self.fingerprint = fingerprint
            return
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "keywarden_user_ca")
            cmd = [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                key_path,
                "-C",
                self.name,
                "-N",
                "",
            ]
            try:
                subprocess.run(cmd, check=True, capture_output=True)
            except FileNotFoundError as exc:
                raise RuntimeError("ssh-keygen not available") from exc
            except subprocess.CalledProcessError as exc:
                raise RuntimeError(f"ssh-keygen failed: {exc.stderr.decode('utf-8', 'ignore')}") from exc
            with open(key_path, "r", encoding="utf-8") as handle:
                self.private_key = write_secret_file("user-ca-key", handle.read())
            with open(key_path + ".pub", "r", encoding="utf-8") as handle:
                self.public_key = handle.read().strip()
        _, _, fingerprint = parse_public_key(self.public_key)
        self.fingerprint = fingerprint


class SSHCertificate(models.Model):
    key = models.OneToOneField(
        SSHKey, on_delete=models.CASCADE, related_name="certificate"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="ssh_certificates"
    )
    certificate = models.TextField()
    serial = models.BigIntegerField()
    principals = models.JSONField(default=list, blank=True)
    valid_after = models.DateTimeField()
    valid_before = models.DateTimeField()
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)

    class Meta:
        verbose_name = "SSH certificate"
        verbose_name_plural = "SSH certificates"
        indexes = [
            models.Index(fields=["user", "is_active"], name="keys_cert_user_active_idx"),
            models.Index(fields=["valid_before"], name="keys_cert_valid_before_idx"),
        ]
        ordering = ["-created_at"]

    def revoke(self) -> None:
        self.is_active = False
        self.revoked_at = timezone.now()

    def __str__(self) -> str:
        return f"{self.user_id} ({self.serial})"
