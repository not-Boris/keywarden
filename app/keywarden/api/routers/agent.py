from __future__ import annotations

from typing import List, Optional

from django.db import models
from django.http import HttpRequest
from django.utils import timezone
from ninja import Router, Schema
from ninja.errors import HttpError
from pydantic import Field

from apps.core.rbac import require_perms
from apps.access.models import AccessRequest
from apps.keys.models import SSHKey
from apps.servers.models import Server
from apps.telemetry.models import TelemetryEvent


class AuthorizedKeyOut(Schema):
    user_id: int
    username: str
    email: str
    public_key: str
    fingerprint: str


class SyncReportIn(Schema):
    applied_count: int = Field(default=0, ge=0)
    revoked_count: int = Field(default=0, ge=0)
    message: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class SyncReportOut(Schema):
    status: str


def build_router() -> Router:
    router = Router()

    @router.get("/servers/{server_id}/authorized-keys", response=List[AuthorizedKeyOut])
    def authorized_keys(request: HttpRequest, server_id: int):
        """Return authorized public keys for a server (admin or operator)."""
        require_perms(
            request,
            "servers.view_server",
            "keys.view_sshkey",
            "access.view_accessrequest",
        )
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Server not found")
        now = timezone.now()
        access_qs = AccessRequest.objects.select_related("requester").filter(
            server=server,
            status=AccessRequest.Status.APPROVED,
        )
        access_qs = access_qs.filter(models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now))
        users = [req.requester for req in access_qs if req.requester and req.requester.is_active]
        keys = SSHKey.objects.select_related("user").filter(
            user__in=users,
            is_active=True,
            revoked_at__isnull=True,
        )
        return [
            AuthorizedKeyOut(
                user_id=key.user_id,
                username=key.user.username,
                email=key.user.email or "",
                public_key=key.public_key,
                fingerprint=key.fingerprint,
            )
            for key in keys
        ]

    @router.post("/servers/{server_id}/sync-report", response=SyncReportOut)
    def sync_report(request: HttpRequest, server_id: int, payload: SyncReportIn):
        """Record an agent sync report for a server (admin or operator)."""
        require_perms(request, "servers.view_server", "telemetry.add_telemetryevent")
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Server not found")
        TelemetryEvent.objects.create(
            event_type="agent_sync",
            server=server,
            success=True,
            source=TelemetryEvent.Source.AGENT,
            message=(payload.message or "").strip(),
            metadata={
                "applied_count": payload.applied_count,
                "revoked_count": payload.revoked_count,
                **(payload.metadata or {}),
            },
        )
        return SyncReportOut(status="ok")

    return router


router = build_router()
