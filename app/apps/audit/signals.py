from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone

from .models import AuditEventType, AuditLog
from .utils import get_client_ip

User = get_user_model()


def _get_event(key: str) -> AuditEventType | None:
    try:
        return AuditEventType.objects.get(key=key)
    except AuditEventType.DoesNotExist:
        return None


@receiver(user_logged_in)
def on_user_logged_in(sender, request, user: User, **kwargs):
    event = _get_event("user_login")
    if event is None:
        return
    AuditLog.objects.create(
        created_at=timezone.now(),
        actor=user,
        event_type=event,
        message=f"User {user} logged in",
        severity=event.default_severity,
        source=AuditLog.Source.UI,
        ip_address=get_client_ip(request),
        user_agent=(request.META.get("HTTP_USER_AGENT") if request else ""),
        metadata={"path": request.path} if request else {},
    )


@receiver(user_logged_out)
def on_user_logged_out(sender, request, user: User, **kwargs):
    event = _get_event("user_logout")
    if event is None:
        return
    AuditLog.objects.create(
        created_at=timezone.now(),
        actor=user,
        event_type=event,
        message=f"User {user} logged out",
        severity=event.default_severity,
        source=AuditLog.Source.UI,
        ip_address=get_client_ip(request),
        user_agent=(request.META.get("HTTP_USER_AGENT") if request else ""),
        metadata={"path": request.path} if request else {},
    )
