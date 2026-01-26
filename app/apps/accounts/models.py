from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models, transaction
from django.utils import timezone


class ErasureRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        DENIED = "denied", "Denied"
        PROCESSED = "processed", "Processed"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="erasure_requests",
    )
    reason = models.TextField()
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING, db_index=True)
    requested_at = models.DateTimeField(default=timezone.now, editable=False)
    decided_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="erasure_decisions",
    )
    decision_reason = models.TextField(blank=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    processed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="erasure_processes",
    )

    class Meta:
        verbose_name = "Erasure request"
        verbose_name_plural = "Erasure requests"
        ordering = ["-requested_at"]
        indexes = [
            models.Index(fields=["status", "requested_at"], name="accounts_erasure_status_idx"),
            models.Index(fields=["user", "status"], name="accounts_erasure_user_status_idx"),
        ]

    def __str__(self) -> str:
        return f"Erasure request #{self.id} ({self.user_id})"

    def process(self, admin_user, decision_reason: str = "") -> None:
        if self.status == self.Status.PROCESSED:
            return
        now = timezone.now()
        with transaction.atomic():
            self._anonymize_user(admin_user, now)
            self.status = self.Status.PROCESSED
            self.decided_at = now
            self.decided_by = admin_user
            self.decision_reason = (decision_reason or "").strip()
            self.processed_at = now
            self.processed_by = admin_user
            self.save(
                update_fields=[
                    "status",
                    "decided_at",
                    "decided_by",
                    "decision_reason",
                    "processed_at",
                    "processed_by",
                ]
            )

    def _anonymize_user(self, admin_user, now) -> None:
        from guardian.models import UserObjectPermission

        from apps.access.models import AccessRequest
        from apps.keys.models import SSHKey

        user = self.user
        token = uuid.uuid4().hex
        anonymous_username = f"erased-{token}"
        anonymous_email = f"{anonymous_username}@erased.local"

        user.username = anonymous_username
        user.email = anonymous_email
        user.first_name = ""
        user.last_name = ""
        user.is_active = False
        user.is_staff = False
        user.is_superuser = False
        user.last_login = None
        user.set_unusable_password()
        user.save(
            update_fields=[
                "username",
                "email",
                "first_name",
                "last_name",
                "is_active",
                "is_staff",
                "is_superuser",
                "last_login",
                "password",
            ]
        )

        user.groups.clear()
        user.user_permissions.clear()
        UserObjectPermission.objects.filter(user=user).delete()

        SSHKey.objects.filter(user=user, is_active=True).update(is_active=False, revoked_at=now)
        AccessRequest.objects.filter(requester=user).update(reason="[redacted]")
        AccessRequest.objects.filter(
            requester=user,
            status__in=[AccessRequest.Status.PENDING, AccessRequest.Status.APPROVED],
        ).update(
            status=AccessRequest.Status.REVOKED,
            decided_at=now,
            decided_by=admin_user,
            expires_at=now,
        )
