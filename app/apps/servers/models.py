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

from apps.core.secret_files import looks_like_pem, read_secret_ref, write_secret_file


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
    agent_api_token_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True)
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

    def get_key_pem(self) -> str:
        try:
            file_payload = read_secret_ref(self.key_pem, label="Agent CA private key")
        except RuntimeError as exc:
            # Recover gracefully when a secret-file reference points to a
            # deleted key file (for example after volume resets).
            if "file missing:" in str(exc):
                file_payload = ""
            else:
                raise
        if file_payload:
            return file_payload
        inline_payload = (self.key_pem or "").strip()
        if looks_like_pem(inline_payload):
            self.key_pem = write_secret_file("agent-ca-key", inline_payload)
            if self.pk:
                self.save(update_fields=["key_pem"])
            return inline_payload
        return ""

    def ensure_material(self) -> None:
        if self.cert_pem and self.get_key_pem():
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
        self.key_pem = write_secret_file("agent-ca-key", key_pem)
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


class ServerAuditLog(models.Model):
    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="audit_logs")
    event_at = models.DateTimeField(db_index=True)
    received_at = models.DateTimeField(default=timezone.now, editable=False, db_index=True)
    category = models.CharField(max_length=64, db_index=True)
    event_type = models.CharField(max_length=128, db_index=True)
    source_kind = models.CharField(max_length=16, blank=True, db_index=True)
    source_name = models.CharField(max_length=512, blank=True, db_index=True)
    unit = models.CharField(max_length=128, blank=True)
    priority = models.CharField(max_length=16, blank=True, db_index=True)
    hostname = models.CharField(max_length=253, blank=True)
    username = models.CharField(max_length=150, blank=True, db_index=True)
    principal = models.CharField(max_length=255, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    session_id = models.CharField(max_length=128, blank=True)
    message = models.TextField(blank=True)
    raw = models.TextField(blank=True)
    fields = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Server audit log"
        verbose_name_plural = "Server audit logs"
        indexes = [
            models.Index(fields=["server", "event_at"], name="servers_audit_server_event_idx"),
            models.Index(fields=["server", "category", "event_at"], name="servers_audit_cat_event_idx"),
            models.Index(fields=["server", "event_type", "event_at"], name="servers_audit_type_event_idx"),
            models.Index(fields=["server", "source_kind", "event_at"], name="servers_audit_kind_event_idx"),
            models.Index(fields=["server", "source_name", "event_at"], name="servers_audit_name_event_idx"),
            models.Index(fields=["server", "username", "event_at"], name="servers_audit_user_event_idx"),
            models.Index(fields=["server", "source_ip", "event_at"], name="servers_audit_ip_event_idx"),
        ]
        ordering = ["-event_at", "-id"]

    def __str__(self) -> str:
        return f"{self.server_id}:{self.category}/{self.event_type}@{self.event_at.isoformat()}"


class ServerLogSource(models.Model):
    class Kind(models.TextChoices):
        JOURNAL = "journal", "Journal"
        SERVICE = "service", "Service"
        FILE = "file", "File"

    class Parser(models.TextChoices):
        NONE = "none", "None"
        SYSLOG = "syslog", "Syslog"
        NGINX_ACCESS = "nginx_access", "Nginx Access"
        JSON = "json", "JSON"

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="log_sources")
    kind = models.CharField(max_length=16, choices=Kind.choices, db_index=True)
    name = models.CharField(max_length=128, blank=True)
    service_unit = models.CharField(max_length=128, blank=True)
    file_path = models.CharField(max_length=512, blank=True)
    parser = models.CharField(max_length=32, choices=Parser.choices, default=Parser.NONE)
    include_matches = models.JSONField(default=dict, blank=True)
    exclude_matches = models.JSONField(default=dict, blank=True)
    category_override = models.CharField(max_length=64, blank=True)
    event_type_override = models.CharField(max_length=128, blank=True)
    enabled = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Server log source"
        verbose_name_plural = "Server log sources"
        ordering = ["server_id", "kind", "name", "id"]
        indexes = [
            models.Index(fields=["server", "enabled", "kind"], name="srvsrc_srv_en_kind_idx"),
            models.Index(fields=["server", "service_unit"], name="srvsrc_srv_svc_idx"),
            models.Index(fields=["server", "file_path"], name="servers_src_server_file_idx"),
        ]

    def __str__(self) -> str:
        if self.kind == self.Kind.SERVICE:
            return self.name or self.service_unit or f"service:{self.id}"
        if self.kind == self.Kind.JOURNAL:
            return self.name or f"journal:{self.id}"
        return self.name or self.file_path or f"file:{self.id}"
