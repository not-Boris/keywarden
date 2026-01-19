from __future__ import annotations

import base64
import binascii
import hashlib

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


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

    def __str__(self) -> str:
        return f"{self.name} ({self.user_id})"
