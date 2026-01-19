from __future__ import annotations

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.servers.models import Server


class TelemetryEvent(models.Model):
    class Source(models.TextChoices):
        AGENT = "agent", "Agent"
        API = "api", "API"
        UI = "ui", "UI"
        SYSTEM = "system", "System"

    event_type = models.CharField(max_length=64, db_index=True)
    server = models.ForeignKey(
        Server, null=True, blank=True, on_delete=models.SET_NULL, related_name="telemetry_events"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="telemetry_events",
    )
    success = models.BooleanField(default=True, db_index=True)
    source = models.CharField(
        max_length=16, choices=Source.choices, default=Source.API, db_index=True
    )
    message = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False, db_index=True)

    class Meta:
        verbose_name = "Telemetry event"
        verbose_name_plural = "Telemetry events"
        indexes = [
            models.Index(fields=["created_at"], name="telemetry_created_at_idx"),
            models.Index(fields=["event_type"], name="telemetry_event_type_idx"),
            models.Index(fields=["server", "created_at"], name="telemetry_server_created_idx"),
            models.Index(fields=["user", "created_at"], name="telemetry_user_created_idx"),
        ]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.event_type} ({'ok' if self.success else 'fail'})"
