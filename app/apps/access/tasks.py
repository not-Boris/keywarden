from __future__ import annotations

from celery import shared_task
from django.db import transaction
from django.utils import timezone
from .models import AccessRequest
from .permissions import sync_server_view_perm


@shared_task
def expire_access_requests() -> int:
    now = timezone.now()
    expired_qs = AccessRequest.objects.select_related("server", "requester").filter(
        status=AccessRequest.Status.APPROVED,
        expires_at__isnull=False,
        expires_at__lte=now,
    )
    count = 0
    for access_request in expired_qs:
        with transaction.atomic():
            access_request.status = AccessRequest.Status.EXPIRED
            access_request.decided_at = now
            access_request.decided_by = None
            access_request.save(update_fields=["status", "decided_at", "decided_by"])
        sync_server_view_perm(access_request)
        count += 1
    return count
