from __future__ import annotations

from typing import List, Optional

from django.http import HttpRequest
from ninja import Router, Schema, File, Form
from ninja.files import UploadedFile
from apps.servers.models import Server

router = Router()


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


@router.post("/", response=ServerOut)
def create_server_json(request: HttpRequest, payload: ServerCreate):
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


