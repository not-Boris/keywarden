from __future__ import annotations

from django.db.models import Q
from django.utils import timezone
from guardian.shortcuts import assign_perm, remove_perm

from .models import AccessRequest


def sync_server_view_perm(access_request: AccessRequest) -> None:
    if not access_request or not access_request.requester_id or not access_request.server_id:
        return
    now = timezone.now()
    has_valid_access = (
        AccessRequest.objects.filter(
            requester_id=access_request.requester_id,
            server_id=access_request.server_id,
            status=AccessRequest.Status.APPROVED,
        )
        .filter(Q(request_shell=True) | Q(request_logs=True) | Q(request_users=True))
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .exists()
    )
    if has_valid_access:
        assign_perm("servers.view_server", access_request.requester, access_request.server)
        return
    remove_perm("servers.view_server", access_request.requester, access_request.server)
