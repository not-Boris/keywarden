from __future__ import annotations

import secrets
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone


hostname_validator = RegexValidator(
    regex=r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$",
    message="Enter a valid hostname.",
)


class Server(models.Model):
    display_name = models.CharField(max_length=128)
    hostname = models.CharField(max_length=253, null=True, blank=True, unique=True, validators=[hostname_validator])
    ipv4 = models.GenericIPAddressField(null=True, blank=True, protocol="IPv4", unique=True)
    ipv6 = models.GenericIPAddressField(null=True, blank=True, protocol="IPv6", unique=True)
    image = models.ImageField(upload_to="servers/", null=True, blank=True)
    agent_enrolled_at = models.DateTimeField(null=True, blank=True)
    agent_cert_fingerprint = models.CharField(max_length=128, null=True, blank=True)
    agent_cert_serial = models.CharField(max_length=64, null=True, blank=True)
    last_heartbeat_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_ping_ms = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["display_name", "hostname", "ipv4", "ipv6"]
        verbose_name = "Server"
        verbose_name_plural = "Servers"
        permissions = [
            ("shell_server", "Can access server shell"),
        ]

    def __str__(self) -> str:
        primary = self.hostname or self.ipv4 or self.ipv6 or "unassigned"
        return f"{self.display_name} ({primary})"

    @property
    def image_url(self) -> str | None:
        try:
            return self.image.url if self.image else None
        except Exception:
            return None

    @property
    def initial(self) -> str:
        return (self.display_name or "?").strip()[:1].upper() or "?"


class EnrollmentToken(models.Model):
    token = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="server_enrollment_tokens",
    )
    used_at = models.DateTimeField(null=True, blank=True)
    server = models.ForeignKey(
        Server, null=True, blank=True, on_delete=models.SET_NULL, related_name="enrollment_tokens"
    )

    class Meta:
        verbose_name = "Enrollment token"
        verbose_name_plural = "Enrollment tokens"
        indexes = [
            models.Index(fields=["created_at"], name="servers_enroll_created_idx"),
            models.Index(fields=["used_at"], name="servers_enroll_used_idx"),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.token[:8]}... ({'used' if self.used_at else 'unused'})"

    def ensure_token(self) -> None:
        if not self.token:
            self.token = secrets.token_urlsafe(32)

    def is_valid(self) -> bool:
        if self.used_at:
            return False
        if self.expires_at and self.expires_at <= timezone.now():
            return False
        return True

    def mark_used(self, server: Server) -> None:
        self.used_at = timezone.now()
        self.server = server

    def save(self, *args, **kwargs):
        self.ensure_token()
        super().save(*args, **kwargs)


class AgentCertificateAuthority(models.Model):
    name = models.CharField(max_length=128, default="Keywarden Agent CA")
    cert_pem = models.TextField()
    key_pem = models.TextField()
    fingerprint = models.CharField(max_length=128, blank=True)
    serial = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="agent_certificate_authorities",
    )

    class Meta:
        verbose_name = "Agent certificate authority"
        verbose_name_plural = "Agent certificate authorities"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        status = "active" if self.is_active and not self.revoked_at else "revoked"
        return f"{self.name} ({status})"

    def revoke(self) -> None:
        self.is_active = False
        self.revoked_at = timezone.now()

    def ensure_material(self) -> None:
        if self.cert_pem and self.key_pem:
            return
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.name)])
        now = datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        self.cert_pem = cert_pem
        self.key_pem = key_pem
        self.fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        self.serial = format(cert.serial_number, "x")


class ServerAccount(models.Model):
    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="accounts")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="server_accounts"
    )
    system_username = models.CharField(max_length=128)
    is_present = models.BooleanField(default=False, db_index=True)
    last_synced_at = models.DateTimeField(default=timezone.now, editable=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Server account"
        verbose_name_plural = "Server accounts"
        constraints = [
            models.UniqueConstraint(fields=["server", "user"], name="unique_server_account")
        ]
        indexes = [
            models.Index(fields=["server", "user"], name="servers_account_user_idx"),
            models.Index(fields=["server", "is_present"], name="servers_account_present_idx"),
        ]
        ordering = ["server_id", "user_id"]

    def __str__(self) -> str:
        return f"{self.system_username} ({self.server_id})"
