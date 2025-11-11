from __future__ import annotations

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils import timezone


class AuditEventType(models.Model):
    """
    Catalog of audit event types (e.g., user_login, secret_updated).
    Useful for consistent naming, severity, and descriptions.
    """

    class Severity(models.TextChoices):
        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        ERROR = "error", "Error"
        CRITICAL = "critical", "Critical"

    key = models.SlugField(max_length=64, unique=True, help_text="Stable machine key, e.g., user_login")
    title = models.CharField(max_length=128, help_text="Human-readable title")
    description = models.TextField(blank=True)
    default_severity = models.CharField(
        max_length=16, choices=Severity.choices, default=Severity.INFO, db_index=True
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        verbose_name = "Audit event type"
        verbose_name_plural = "Audit event types"
        ordering = ["key"]

    def __str__(self) -> str:
        return f"{self.key} ({self.default_severity})"


class AuditLog(models.Model):
    """
    An immutable audit record of something that happened in the system.
    """

    class Source(models.TextChoices):
        UI = "ui", "UI"
        API = "api", "API"
        SYSTEM = "system", "System"

    class Severity(models.TextChoices):
        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        ERROR = "error", "Error"
        CRITICAL = "critical", "Critical"

    created_at = models.DateTimeField(default=timezone.now, db_index=True, editable=False)

    # Who did it
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_logs",
    )

    # What happened
    event_type = models.ForeignKey(
        AuditEventType, on_delete=models.PROTECT, related_name="audit_logs", help_text="Type of event"
    )
    message = models.TextField(
        help_text="Summary describing the action in human terms, snapshot at time of event"
    )
    severity = models.CharField(
        max_length=16, choices=Severity.choices, default=Severity.INFO, db_index=True
    )
    source = models.CharField(max_length=16, choices=Source.choices, default=Source.UI, db_index=True)

    # Which object it touched (optional)
    target_content_type = models.ForeignKey(
        ContentType, null=True, blank=True, on_delete=models.SET_NULL, related_name="audit_target"
    )
    target_object_id = models.CharField(max_length=64, null=True, blank=True)
    target = GenericForeignKey("target_content_type", "target_object_id")
    object_repr = models.CharField(
        max_length=255,
        blank=True,
        help_text="String representation of the target object at event time",
    )

    # Request context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    request_id = models.CharField(max_length=64, blank=True, help_text="Correlation id, if available")

    # Arbitrary extra data
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Audit log"
        verbose_name_plural = "Audit logs"
        indexes = [
            models.Index(fields=["created_at"]),
            models.Index(fields=["severity"]),
            models.Index(fields=["source"]),
            models.Index(fields=["actor", "created_at"]),
            models.Index(fields=["target_content_type", "target_object_id"]),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        actor = getattr(self.actor, "username", "system")
        return f"[{self.created_at:%Y-%m-%d %H:%M:%S}] {actor}: {self.message}"