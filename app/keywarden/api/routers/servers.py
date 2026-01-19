from __future__ import annotations

from typing import List, Optional

from django.db import IntegrityError
from django.http import HttpRequest
from ninja import File, Form, Router, Schema
from ninja.files import UploadedFile
from ninja.errors import HttpError
from apps.servers.models import Server


class ServerOut(Schema):
    id: int
    display_name: str
    hostname: str | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    image_url: str | None = None
    initial: str


class ServerCreate(Schema):
    display_name: str
    hostname: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None


class ServerUpdate(Schema):
    display_name: Optional[str] = None
    hostname: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None


def _require_admin(request: HttpRequest) -> None:
    user = request.user
    if not getattr(user, "is_authenticated", False):
        raise HttpError(403, "Forbidden")
    if not (user.is_staff or user.is_superuser):
        raise HttpError(403, "Forbidden")


def build_router() -> Router:
    router = Router()

    @router.get("/", response=List[ServerOut])
    def list_servers(request: HttpRequest):
        servers = Server.objects.all()
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
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Not Found")
        return {
            "id": server.id,
            "display_name": server.display_name,
            "hostname": server.hostname,
            "ipv4": server.ipv4,
            "ipv6": server.ipv6,
            "image_url": server.image_url,
            "initial": server.initial,
        }

    @router.post("/", response=ServerOut)
    def create_server_json(request: HttpRequest, payload: ServerCreate):
        _require_admin(request)
        server = Server.objects.create(
            display_name=payload.display_name.strip(),
            hostname=(payload.hostname or "").strip() or None,
            ipv4=(payload.ipv4 or "").strip() or None,
            ipv6=(payload.ipv6 or "").strip() or None,
        )
        return {
            "id": server.id,
            "display_name": server.display_name,
            "hostname": server.hostname,
            "ipv4": server.ipv4,
            "ipv6": server.ipv6,
            "image_url": server.image_url,
            "initial": server.initial,
        }

    @router.post("/upload", response=ServerOut)
    def create_server_multipart(
        request: HttpRequest,
        display_name: str = Form(...),
        hostname: Optional[str] = Form(None),
        ipv4: Optional[str] = Form(None),
        ipv6: Optional[str] = Form(None),
        image: Optional[UploadedFile] = File(None),
    ):
        _require_admin(request)
        server = Server(
            display_name=display_name.strip(),
            hostname=(hostname or "").strip() or None,
            ipv4=(ipv4 or "").strip() or None,
            ipv6=(ipv6 or "").strip() or None,
        )
        if image:
            server.image.save(image.name, image)  # type: ignore[arg-type]
        server.save()
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
        _require_admin(request)
        if (
            payload.display_name is None
            and payload.hostname is None
            and payload.ipv4 is None
            and payload.ipv6 is None
        ):
            raise HttpError(422, {"detail": "No fields provided."})
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Not Found")
        if payload.display_name is not None:
            display_name = payload.display_name.strip()
            if not display_name:
                raise HttpError(422, {"display_name": ["Display name cannot be empty."]})
            server.display_name = display_name
        if payload.hostname is not None:
            server.hostname = (payload.hostname or "").strip() or None
        if payload.ipv4 is not None:
            server.ipv4 = (payload.ipv4 or "").strip() or None
        if payload.ipv6 is not None:
            server.ipv6 = (payload.ipv6 or "").strip() or None
        try:
            server.save()
        except IntegrityError:
            raise HttpError(422, {"detail": "Unique constraint violated."})
        return {
            "id": server.id,
            "display_name": server.display_name,
            "hostname": server.hostname,
            "ipv4": server.ipv4,
            "ipv6": server.ipv6,
            "image_url": server.image_url,
            "initial": server.initial,
        }

    @router.delete("/{server_id}", response={204: None})
    def delete_server(request: HttpRequest, server_id: int):
        _require_admin(request)
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            raise HttpError(404, "Not Found")
        server.delete()
        return 204, None

    return router


router = build_router()
