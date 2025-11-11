from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone

from .models import AuditEventType, AuditLog

User = get_user_model()


def _get_or_create_event(key: str, title: str, severity: str = AuditEventType.Severity.INFO) -> AuditEventType:
    event, _ = AuditEventType.objects.get_or_create(
        key=key,
        defaults={"title": title, "default_severity": severity},
    )
    return event


@receiver(user_logged_in)
def on_user_logged_in(sender, request, user: User, **kwargs):
    event = _get_or_create_event("user_login", "User logged in", AuditEventType.Severity.INFO)
    AuditLog.objects.create(
        created_at=timezone.now(),
        actor=user,
        event_type=event,
        message=f"User {user} logged in",
        severity=event.default_severity,
        source=AuditLog.Source.UI,
        ip_address=(request.META.get("REMOTE_ADDR") if request else None),
        user_agent=(request.META.get("HTTP_USER_AGENT") if request else ""),
        metadata={"path": request.path} if request else {},
    )


@receiver(user_logged_out)
def on_user_logged_out(sender, request, user: User, **kwargs):
    event = _get_or_create_event("user_logout", "User logged out", AuditEventType.Severity.INFO)
    AuditLog.objects.create(
        created_at=timezone.now(),
        actor=user,
        event_type=event,
        message=f"User {user} logged out",
        severity=event.default_severity,
        source=AuditLog.Source.UI,
        ip_address=(request.META.get("REMOTE_ADDR") if request else None),
        user_agent=(request.META.get("HTTP_USER_AGENT") if request else ""),
        metadata={"path": request.path} if request else {},
    )


