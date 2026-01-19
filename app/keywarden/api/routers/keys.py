from __future__ import annotations

from typing import List, Optional

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.http import HttpRequest
from django.utils import timezone
from ninja import Query, Router, Schema
from ninja.errors import HttpError
from pydantic import Field

from apps.keys.models import SSHKey


class KeyCreateIn(Schema):
    name: str
    public_key: str
    user_id: Optional[int] = None


class KeyUpdateIn(Schema):
    name: Optional[str] = None
    is_active: Optional[bool] = None


class KeyOut(Schema):
    id: int
    user_id: int
    name: str
    public_key: str
    key_type: str
    fingerprint: str
    is_active: bool
    created_at: str
    revoked_at: Optional[str] = None


class KeysQuery(Schema):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
    user_id: Optional[int] = None


def _require_authenticated(request: HttpRequest) -> None:
    if not getattr(request.user, "is_authenticated", False):
        raise HttpError(403, "Forbidden")


def _is_admin(request: HttpRequest) -> bool:
    user = request.user
    return bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))


def _key_to_out(key: SSHKey) -> KeyOut:
    return KeyOut(
        id=key.id,
        user_id=key.user_id,
        name=key.name,
        public_key=key.public_key,
        key_type=key.key_type,
        fingerprint=key.fingerprint,
        is_active=key.is_active,
        created_at=key.created_at.isoformat(),
        revoked_at=key.revoked_at.isoformat() if key.revoked_at else None,
    )


def build_router() -> Router:
    router = Router()

    @router.get("/", response=List[KeyOut])
    def list_keys(request: HttpRequest, filters: KeysQuery = Query(...)):
        """List SSH keys for the current user, or any user if admin."""
        _require_authenticated(request)
        qs = SSHKey.objects.order_by("-created_at")
        if _is_admin(request):
            if filters.user_id:
                qs = qs.filter(user_id=filters.user_id)
        else:
            qs = qs.filter(user=request.user)
        qs = qs[filters.offset : filters.offset + filters.limit]
        return [_key_to_out(key) for key in qs]

    @router.post("/", response=KeyOut)
    def create_key(request: HttpRequest, payload: KeyCreateIn):
        """Create an SSH public key for the current user (admin can specify user_id)."""
        _require_authenticated(request)
        owner = request.user
        if _is_admin(request) and payload.user_id:
            User = get_user_model()
            try:
                owner = User.objects.get(id=payload.user_id)
            except User.DoesNotExist:
                raise HttpError(404, "User not found")
        name = (payload.name or "").strip()
        if not name:
            raise HttpError(422, {"name": ["Name cannot be empty."]})
        key = SSHKey(user=owner, name=name)
        try:
            key.set_public_key(payload.public_key)
        except ValidationError as exc:
            raise HttpError(422, {"public_key": [str(exc)]})
        try:
            key.save()
        except IntegrityError:
            raise HttpError(422, {"public_key": ["Key already exists."]})
        return _key_to_out(key)

    @router.get("/{key_id}", response=KeyOut)
    def get_key(request: HttpRequest, key_id: int):
        """Get a specific SSH key if permitted."""
        _require_authenticated(request)
        try:
            key = SSHKey.objects.get(id=key_id)
        except SSHKey.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not _is_admin(request) and key.user_id != request.user.id:
            raise HttpError(403, "Forbidden")
        return _key_to_out(key)

    @router.patch("/{key_id}", response=KeyOut)
    def update_key(request: HttpRequest, key_id: int, payload: KeyUpdateIn):
        """Update key name or active state if permitted."""
        _require_authenticated(request)
        try:
            key = SSHKey.objects.get(id=key_id)
        except SSHKey.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not _is_admin(request) and key.user_id != request.user.id:
            raise HttpError(403, "Forbidden")
        if payload.name is None and payload.is_active is None:
            raise HttpError(422, {"detail": "No fields provided."})
        if payload.name is not None:
            name = payload.name.strip()
            if not name:
                raise HttpError(422, {"name": ["Name cannot be empty."]})
            key.name = name
        if payload.is_active is not None:
            key.is_active = payload.is_active
            if payload.is_active:
                key.revoked_at = None
            else:
                key.revoked_at = timezone.now()
        key.save()
        return _key_to_out(key)

    @router.delete("/{key_id}", response={204: None})
    def delete_key(request: HttpRequest, key_id: int):
        """Revoke an SSH key if permitted (soft delete)."""
        _require_authenticated(request)
        try:
            key = SSHKey.objects.get(id=key_id)
        except SSHKey.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not _is_admin(request) and key.user_id != request.user.id:
            raise HttpError(403, "Forbidden")
        if key.is_active:
            key.is_active = False
            key.revoked_at = timezone.now()
            key.save(update_fields=["is_active", "revoked_at"])
        return 204, None

    return router


router = build_router()
