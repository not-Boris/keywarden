from __future__ import annotations

from typing import List, Optional

from django.contrib.auth import get_user_model
from django.db import models
from django.db.models import Count
from django.http import HttpRequest
from ninja import Query, Router, Schema
from ninja.errors import HttpError
from pydantic import Field

from apps.core.rbac import ROLE_ADMIN, ROLE_OPERATOR, require_roles
from apps.servers.models import Server
from apps.telemetry.models import TelemetryEvent


class TelemetryCreateIn(Schema):
    event_type: str
    server_id: Optional[int] = None
    user_id: Optional[int] = None
    success: bool = True
    source: Optional[str] = None
    message: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class TelemetryOut(Schema):
    id: int
    event_type: str
    server_id: Optional[int] = None
    user_id: Optional[int] = None
    success: bool
    source: str
    message: str
    metadata: dict
    created_at: str


class TelemetrySummaryOut(Schema):
    total: int
    success: int
    failure: int


class TelemetryQuery(Schema):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
    event_type: Optional[str] = None
    server_id: Optional[int] = None
    user_id: Optional[int] = None
    success: Optional[bool] = None


def _event_to_out(event: TelemetryEvent) -> TelemetryOut:
    return TelemetryOut(
        id=event.id,
        event_type=event.event_type,
        server_id=event.server_id,
        user_id=event.user_id,
        success=event.success,
        source=event.source,
        message=event.message or "",
        metadata=event.metadata or {},
        created_at=event.created_at.isoformat(),
    )


def build_router() -> Router:
    router = Router()

    @router.get("/", response=List[TelemetryOut])
    def list_events(request: HttpRequest, filters: TelemetryQuery = Query(...)):
        """List telemetry events with filters (admin or operator)."""
        require_roles(request, ROLE_ADMIN, ROLE_OPERATOR)
        qs = TelemetryEvent.objects.order_by("-created_at")
        if filters.event_type:
            qs = qs.filter(event_type=filters.event_type)
        if filters.server_id:
            qs = qs.filter(server_id=filters.server_id)
        if filters.user_id:
            qs = qs.filter(user_id=filters.user_id)
        if filters.success is not None:
            qs = qs.filter(success=filters.success)
        qs = qs[filters.offset : filters.offset + filters.limit]
        return [_event_to_out(event) for event in qs]

    @router.post("/", response=TelemetryOut)
    def create_event(request: HttpRequest, payload: TelemetryCreateIn):
        """Create a telemetry event entry (admin or operator)."""
        require_roles(request, ROLE_ADMIN, ROLE_OPERATOR)
        server = None
        if payload.server_id:
            try:
                server = Server.objects.get(id=payload.server_id)
            except Server.DoesNotExist:
                raise HttpError(404, "Server not found")
        if payload.user_id:
            User = get_user_model()
            if not User.objects.filter(id=payload.user_id).exists():
                raise HttpError(404, "User not found")
        source = payload.source or TelemetryEvent.Source.API
        if source not in TelemetryEvent.Source.values:
            raise HttpError(422, {"source": ["Invalid source."]})
        event = TelemetryEvent.objects.create(
            event_type=payload.event_type.strip(),
            server=server,
            user_id=payload.user_id,
            success=payload.success,
            source=source,
            message=(payload.message or "").strip(),
            metadata=payload.metadata or {},
        )
        return _event_to_out(event)

    @router.get("/summary", response=TelemetrySummaryOut)
    def summary(request: HttpRequest):
        """Return a high-level telemetry summary (admin or operator)."""
        require_roles(request, ROLE_ADMIN, ROLE_OPERATOR)
        totals = TelemetryEvent.objects.aggregate(
            total=Count("id"),
            success=Count("id", filter=models.Q(success=True)),
        )
        total = totals.get("total") or 0
        success = totals.get("success") or 0
        return TelemetrySummaryOut(total=total, success=success, failure=total - success)

    return router


router = build_router()
