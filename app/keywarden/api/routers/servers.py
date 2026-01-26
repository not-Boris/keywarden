from __future__ import annotations

from typing import List, Optional

from django.http import HttpRequest
from ninja import Router, Schema
from ninja.errors import HttpError
from guardian.shortcuts import get_objects_for_user, get_perms
from apps.core.rbac import require_authenticated, require_perms
from apps.servers.models import Server


class ServerOut(Schema):
    id: int
    display_name: str
    hostname: str | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    image_url: str | None = None
    initial: str


class ServerUpdate(Schema):
    display_name: Optional[str] = None


def build_router() -> Router:
    router = Router()

    @router.get("/", response=List[ServerOut])
    def list_servers(request: HttpRequest):
        """List servers the caller can view.

        Auth: required.
        Permissions: requires `servers.view_server` via object permissions.
        Behavior: returns only servers the user can see via object perms.
        Rationale: drives the server dashboard and access-aware navigation.
        """
        require_authenticated(request)
        servers = get_objects_for_user(
            request.user,
            "servers.view_server",
            klass=Server,
            accept_global_perms=False,
        )
        return [
            {
                "id": s.id,
                "display_name": s.display_name,
                "hostname": s.hostname,
                "ipv4": s.ipv4,
                "ipv6": s.ipv6,
                "image_url": s.image_url,
                "initial": s.initial,
            }
            for s in servers
        ]

    @router.get("/{server_id}", response=ServerOut)
    def get_server(request: HttpRequest, server_id: int):
        """Get a server record by id.

        Auth: required.
        Permissions: requires `servers.view_server` via object permissions.
        Rationale: used by server detail views and API clients inspecting
        server metadata (hostname/IPs populated by the agent).
        """
        require_authenticated(request)
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Not Found")
        if "view_server" not in get_perms(request.user, server):
            raise HttpError(403, "Forbidden")
        return {
            "id": server.id,
            "display_name": server.display_name,
            "hostname": server.hostname,
            "ipv4": server.ipv4,
            "ipv6": server.ipv6,
            "image_url": server.image_url,
            "initial": server.initial,
        }

    @router.patch("/{server_id}", response=ServerOut)
    def update_server(request: HttpRequest, server_id: int, payload: ServerUpdate):
        """Update the server display name (admin only).

        Auth: required.
        Permissions: requires `servers.change_server`.
        Behavior: only display_name is editable via API; host/IP data is owned
        by the agent heartbeat to avoid conflicting sources of truth.
        Rationale: allows human-friendly naming without bypassing enrollment.
        """
        require_perms(request, "servers.change_server")
        if payload.display_name is None:
            raise HttpError(422, {"detail": "No fields provided."})
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Not Found")
        display_name = payload.display_name.strip()
        if not display_name:
            raise HttpError(422, {"display_name": ["Display name cannot be empty."]})
        server.display_name = display_name
        server.save(update_fields=["display_name"])
        return {
            "id": server.id,
            "display_name": server.display_name,
            "hostname": server.hostname,
            "ipv4": server.ipv4,
            "ipv6": server.ipv6,
            "image_url": server.image_url,
            "initial": server.initial,
        }

    return router


router = build_router()
