from __future__ import annotations

from django.db.models import Q
from django.utils import timezone

from apps.access.models import AccessRequest


def _active_access_requests(user, server, now):
    return AccessRequest.objects.filter(
        requester=user,
        server=server,
        status=AccessRequest.Status.APPROVED,
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))


def _is_admin_override(user) -> bool:
    if not user or not getattr(user, "is_authenticated", False):
        return False
    return user.is_superuser or user.has_perm("servers.change_server")


def _has_manual_view_access(user, server, now) -> bool:
    if not user.has_perm("servers.view_server", server):
        return False
    # If a user has active access requests on this server, scope flags govern
    # capability checks. Otherwise, object/global server grants continue to work.
    return not _active_access_requests(user, server, now).exists()


def user_has_any_access(user, server, now=None) -> bool:
    if now is None:
        now = timezone.now()
    if _is_admin_override(user) or _has_manual_view_access(user, server, now):
        return True
    return (
        _active_access_requests(user, server, now)
        .filter(Q(request_shell=True) | Q(request_logs=True) | Q(request_users=True))
        .exists()
    )


def user_can_shell(user, server, now=None) -> bool:
    if now is None:
        now = timezone.now()
    if user.has_perm("servers.shell_server", server):
        return True
    if _is_admin_override(user):
        return True
    return (
        _active_access_requests(user, server, now)
        .filter(request_shell=True)
        .exists()
    )


def user_can_logs(user, server, now=None) -> bool:
    if now is None:
        now = timezone.now()
    if _is_admin_override(user) or _has_manual_view_access(user, server, now):
        return True
    return (
        _active_access_requests(user, server, now)
        .filter(request_logs=True)
        .exists()
    )


def user_can_users(user, server, now=None) -> bool:
    if now is None:
        now = timezone.now()
    if _is_admin_override(user) or _has_manual_view_access(user, server, now):
        return True
    return (
        _active_access_requests(user, server, now)
        .filter(request_users=True)
        .exists()
    )
