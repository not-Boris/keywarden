from __future__ import annotations

from django.db.models import Q
from django.utils import timezone

from apps.access.models import AccessRequest


def user_can_shell(user, server, now=None) -> bool:
    if user.has_perm("servers.shell_server", server):
        return True
    if now is None:
        now = timezone.now()
    return (
        AccessRequest.objects.filter(
            requester=user,
            server=server,
            status=AccessRequest.Status.APPROVED,
            request_shell=True,
        )
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .exists()
    )
