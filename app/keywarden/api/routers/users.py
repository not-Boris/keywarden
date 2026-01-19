from __future__ import annotations

from typing import List, Literal

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.http import HttpRequest
from ninja import Query, Router, Schema
from ninja.errors import HttpError
from pydantic import EmailStr, Field


class UserCreateIn(Schema):
    email: EmailStr
    password: str = Field(min_length=8)
    role: Literal["admin", "user"]


class UserListOut(Schema):
    id: int
    email: str
    role: str
    is_active: bool


class UserDetailOut(Schema):
    id: int
    email: str
    role: str
    is_active: bool


class UserUpdateIn(Schema):
    email: EmailStr | None = None
    password: str | None = Field(default=None, min_length=8)
    role: Literal["admin", "user"] | None = None
    is_active: bool | None = None


class UsersQuery(Schema):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


def _require_admin(request: HttpRequest) -> None:
    user = request.user
    if not getattr(user, "is_authenticated", False):
        raise HttpError(403, "Forbidden")
    if not (user.is_staff or user.is_superuser):
        raise HttpError(403, "Forbidden")


def _role_from_user(user) -> str:
    return "admin" if (user.is_staff or user.is_superuser) else "user"


def _apply_role(user, role: str) -> None:
    if role == "admin":
        user.is_staff = True
        user.is_superuser = True
    else:
        user.is_staff = False
        user.is_superuser = False


def build_router() -> Router:
    router = Router()

    @router.post("/", response=UserDetailOut)
    def create_user(request: HttpRequest, payload: UserCreateIn):
        """Create a user with role and password (admin only)."""
        _require_admin(request)
        User = get_user_model()
        email = payload.email.strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise HttpError(422, {"email": ["Email already exists."]})
        user = User(username=email, email=email, is_active=True)
        _apply_role(user, payload.role)
        user.set_password(payload.password)
        try:
            user.save()
        except IntegrityError:
            raise HttpError(422, {"email": ["Email already exists."]})
        return {
            "id": user.id,
            "email": user.email,
            "role": _role_from_user(user),
            "is_active": user.is_active,
        }

    @router.get("/", response=List[UserListOut])
    def list_users(request: HttpRequest, pagination: UsersQuery = Query(...)):
        """List users with pagination (admin only)."""
        _require_admin(request)
        User = get_user_model()
        qs = User.objects.order_by("id")[pagination.offset : pagination.offset + pagination.limit]
        return [
            {
                "id": user.id,
                "email": user.email or "",
                "role": _role_from_user(user),
                "is_active": user.is_active,
            }
            for user in qs
        ]

    @router.get("/{user_id}", response=UserDetailOut)
    def get_user(request: HttpRequest, user_id: int):
        """Get user details by id (admin only)."""
        _require_admin(request)
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise HttpError(404, "Not Found")
        return {
            "id": user.id,
            "email": user.email or "",
            "role": _role_from_user(user),
            "is_active": user.is_active,
        }

    @router.patch("/{user_id}", response=UserDetailOut)
    def update_user(request: HttpRequest, user_id: int, payload: UserUpdateIn):
        """Update user fields such as role, email, or status (admin only)."""
        _require_admin(request)
        if payload.email is None and payload.password is None and payload.role is None and payload.is_active is None:
            raise HttpError(422, {"detail": "No fields provided."})
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise HttpError(404, "Not Found")
        if payload.email is not None:
            email = payload.email.strip().lower()
            if User.objects.filter(email__iexact=email).exclude(id=user_id).exists():
                raise HttpError(422, {"email": ["Email already exists."]})
            user.email = email
            user.username = email
        if payload.password is not None:
            user.set_password(payload.password)
        if payload.role is not None:
            _apply_role(user, payload.role)
        if payload.is_active is not None:
            user.is_active = payload.is_active
        user.save()
        return {
            "id": user.id,
            "email": user.email or "",
            "role": _role_from_user(user),
            "is_active": user.is_active,
        }

    @router.delete("/{user_id}", response={204: None})
    def delete_user(request: HttpRequest, user_id: int):
        """Delete a user by id (admin only)."""
        _require_admin(request)
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise HttpError(404, "Not Found")
        user.delete()
        return 204, None

    return router


router = build_router()
