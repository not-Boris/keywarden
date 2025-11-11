from __future__ import annotations

from typing import List, Optional

from django.contrib.auth import get_user_model
from django.db.models import QuerySet
from django.http import HttpRequest
from ninja import Query, Router, Schema

from apps.audit.models import AuditEventType, AuditLog

router = Router()


class AuditEventTypeSchema(Schema):
    id: int
    key: str
    title: str
    description: str | None = None
    default_severity: str


class AuditLogSchema(Schema):
    id: int
    created_at: str
    actor_id: int | None = None
    event_type_id: int
    message: str
    severity: str
    source: str
    object_repr: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    metadata: dict


class LogsQuery(Schema):
    limit: int = 50
    offset: int = 0
    severity: Optional[str] = None
    actor_id: Optional[int] = None
    event_type_key: Optional[str] = None
    source: Optional[str] = None


@router.get("/event-types", response=List[AuditEventTypeSchema])
def list_event_types(request: HttpRequest):
    qs: QuerySet[AuditEventType] = AuditEventType.objects.all()
    return [
        {
            "id": et.id,
            "key": et.key,
            "title": et.title,
            "description": et.description or "",
            "default_severity": et.default_severity,
        }
        for et in qs
    ]


@router.get("/logs", response=List[AuditLogSchema])
def list_logs(request: HttpRequest, filters: LogsQuery = Query(...)):
    qs: QuerySet[AuditLog] = AuditLog.objects.select_related("event_type", "actor").all()
    if filters.severity:
        qs = qs.filter(severity=filters.severity)
    if filters.actor_id:
        qs = qs.filter(actor_id=filters.actor_id)
    if filters.event_type_key:
        qs = qs.filter(event_type__key=filters.event_type_key)
    if filters.source:
        qs = qs.filter(source=filters.source)
    qs = qs.order_by("-created_at")[filters.offset : filters.offset + filters.limit]
    return [
        {
            "id": al.id,
            "created_at": al.created_at.isoformat(),
            "actor_id": al.actor_id,
            "event_type_id": al.event_type_id,
            "message": al.message,
            "severity": al.severity,
            "source": al.source,
            "object_repr": al.object_repr or "",
            "ip_address": al.ip_address or "",
            "user_agent": al.user_agent or "",
            "request_id": al.request_id or "",
            "metadata": al.metadata or {},
        }
        for al in qs
    ]


