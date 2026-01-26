from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from django.http import HttpRequest
from django.utils import timezone
from guardian.shortcuts import get_objects_for_user
from ninja import Query, Router, Schema
from ninja.errors import HttpError
from pydantic import Field

from apps.access.models import AccessRequest
from apps.core.rbac import require_authenticated
from apps.servers.models import Server
from apps.access.permissions import sync_server_view_perm


class AccessRequestCreateIn(Schema):
    server_id: int
    reason: Optional[str] = None
    expires_at: Optional[datetime] = None


class AccessRequestUpdateIn(Schema):
    status: Optional[str] = None
    expires_at: Optional[datetime] = None


class AccessRequestOut(Schema):
    id: int
    requester_id: int
    server_id: int
    status: str
    reason: str
    requested_at: str
    decided_at: Optional[str] = None
    expires_at: Optional[str] = None
    decided_by_id: Optional[int] = None


class AccessQuery(Schema):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
    status: Optional[str] = None
    server_id: Optional[int] = None
    requester_id: Optional[int] = None


def _request_to_out(access_request: AccessRequest) -> AccessRequestOut:
    return AccessRequestOut(
        id=access_request.id,
        requester_id=access_request.requester_id,
        server_id=access_request.server_id,
        status=access_request.status,
        reason=access_request.reason or "",
        requested_at=access_request.requested_at.isoformat(),
        decided_at=access_request.decided_at.isoformat() if access_request.decided_at else None,
        expires_at=access_request.expires_at.isoformat() if access_request.expires_at else None,
        decided_by_id=access_request.decided_by_id,
    )


def _has_global_perm(request: HttpRequest, perm: str) -> bool:
    user = request.user
    return bool(user and user.has_perm(perm))


def build_router() -> Router:
    router = Router()

    @router.get("/", response=List[AccessRequestOut])
    def list_requests(request: HttpRequest, filters: AccessQuery = Query(...)):
        """List access requests with pagination and filters.

        Auth: required.
        Permissions:
        - If user has global `access.view_accessrequest`, returns all requests.
        - Otherwise, returns only objects with `access.view_accessrequest` object permission.
        Filters: status, server_id, requester_id (requester_id is honored only with global view).
        """
        require_authenticated(request)
        user = request.user
        if _has_global_perm(request, "access.view_accessrequest"):
            qs = AccessRequest.objects.all()
        else:
            qs = get_objects_for_user(
                user,
                "access.view_accessrequest",
                klass=AccessRequest,
                accept_global_perms=False,
            )
        qs = qs.order_by("-requested_at")
        if filters.requester_id and _has_global_perm(request, "access.view_accessrequest"):
            qs = qs.filter(requester_id=filters.requester_id)
        if filters.status:
            qs = qs.filter(status=filters.status)
        if filters.server_id:
            qs = qs.filter(server_id=filters.server_id)
        qs = qs[filters.offset : filters.offset + filters.limit]
        return [_request_to_out(item) for item in qs]

    @router.post("/", response=AccessRequestOut)
    def create_request(request: HttpRequest, payload: AccessRequestCreateIn):
        """Create a new access request for the current user.

        Auth: required.
        Permissions: requires global `access.add_accessrequest`.
        Side effects: grants owner object perms on the new request.
        """
        require_authenticated(request)
        if not request.user.has_perm("access.add_accessrequest"):
            raise HttpError(403, "Forbidden")
        try:
            server = Server.objects.get(id=payload.server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Server not found")
        access_request = AccessRequest(
            requester=request.user,
            server=server,
            reason=(payload.reason or "").strip(),
        )
        if payload.expires_at:
            access_request.expires_at = payload.expires_at
            if timezone.is_naive(access_request.expires_at):
                access_request.expires_at = timezone.make_aware(access_request.expires_at)
        access_request.save()
        return _request_to_out(access_request)

    @router.get("/{request_id}", response=AccessRequestOut)
    def get_request(request: HttpRequest, request_id: int):
        """Get a single access request by id.

        Auth: required.
        Permissions: requires `access.view_accessrequest` on the object.
        """
        require_authenticated(request)
        try:
            access_request = AccessRequest.objects.get(id=request_id)
        except AccessRequest.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not request.user.has_perm("access.view_accessrequest", access_request):
            raise HttpError(403, "Forbidden")
        return _request_to_out(access_request)

    @router.patch("/{request_id}", response=AccessRequestOut)
    def update_request(request: HttpRequest, request_id: int, payload: AccessRequestUpdateIn):
        """Update request status or expiry.

        Auth: required.
        Permissions: requires `access.change_accessrequest` on the object.
        Rules:
        - Admin/operator (global change) can set status to approved/denied/revoked/cancelled and
          update expires_at.
        - Non-admin can only set status to cancelled, and only while pending.
        """
        require_authenticated(request)
        try:
            access_request = AccessRequest.objects.get(id=request_id)
        except AccessRequest.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not request.user.has_perm("access.change_accessrequest", access_request):
            raise HttpError(403, "Forbidden")
        is_admin = _has_global_perm(request, "access.change_accessrequest")
        if payload.status is None and payload.expires_at is None:
            raise HttpError(422, {"detail": "No fields provided."})
        if payload.expires_at is not None:
            if not is_admin:
                raise HttpError(403, "Forbidden")
            access_request.expires_at = payload.expires_at
            if timezone.is_naive(access_request.expires_at):
                access_request.expires_at = timezone.make_aware(access_request.expires_at)
        if payload.status is not None:
            status = payload.status
            if is_admin:
                if status not in {
                    AccessRequest.Status.APPROVED,
                    AccessRequest.Status.DENIED,
                    AccessRequest.Status.REVOKED,
                    AccessRequest.Status.CANCELLED,
                }:
                    raise HttpError(422, {"status": ["Invalid status."]})
            else:
                if status != AccessRequest.Status.CANCELLED:
                    raise HttpError(403, "Forbidden")
                if access_request.status != AccessRequest.Status.PENDING:
                    raise HttpError(422, {"status": ["Only pending requests can be cancelled."]})
            access_request.status = status
            access_request.decided_at = timezone.now()
            if is_admin:
                access_request.decided_by = request.user
            else:
                access_request.decided_by = None
        access_request.save()
        sync_server_view_perm(access_request)
        return _request_to_out(access_request)

    @router.delete("/{request_id}", response={204: None})
    def delete_request(request: HttpRequest, request_id: int):
        """Delete an access request.

        Auth: required.
        Permissions: requires `access.delete_accessrequest` on the object.
        """
        require_authenticated(request)
        try:
            access_request = AccessRequest.objects.get(id=request_id)
        except AccessRequest.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not request.user.has_perm("access.delete_accessrequest", access_request):
            raise HttpError(403, "Forbidden")
        access_request.delete()
        sync_server_view_perm(access_request)
        return 204, None

    return router


router = build_router()
