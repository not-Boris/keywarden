from __future__ import annotations

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.servers.models import Server


class AccessRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        DENIED = "denied", "Denied"
        REVOKED = "revoked", "Revoked"
        CANCELLED = "cancelled", "Cancelled"
        EXPIRED = "expired", "Expired"

    requester = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="access_requests",
    )
    server = models.ForeignKey(
        Server, on_delete=models.CASCADE, related_name="access_requests"
    )
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING, db_index=True
    )
    reason = models.TextField(blank=True)
    request_shell = models.BooleanField(default=False)
    request_logs = models.BooleanField(default=False)
    request_users = models.BooleanField(default=False)
    requested_at = models.DateTimeField(default=timezone.now, editable=False)
    decided_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="access_decisions",
    )

    class Meta:
        verbose_name = "Access request"
        verbose_name_plural = "Access requests"
        default_permissions = ("add", "view", "change")
        indexes = [
            models.Index(fields=["status", "requested_at"], name="acc_req_status_req_idx"),
            models.Index(fields=["server", "status"], name="acc_req_server_status_idx"),
        ]
        ordering = ["-requested_at"]

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return self.expires_at <= timezone.now()

    def __str__(self) -> str:
        return f"{self.requester_id} -> {self.server_id} ({self.status})"
