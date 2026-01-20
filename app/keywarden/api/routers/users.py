from __future__ import annotations

from typing import List, Literal

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.http import HttpRequest
from ninja import Query, Router, Schema
from ninja.errors import HttpError
from pydantic import EmailStr, Field

from apps.core.rbac import ROLE_ADMIN, ROLE_OPERATOR, ROLE_USER, get_user_role, require_roles, set_user_role


class UserCreateIn(Schema):
    email: EmailStr
    password: str = Field(min_length=8)
    role: Literal["administrator", "operator", "auditor", "user", "admin"]


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
    role: Literal["administrator", "operator", "auditor", "user", "admin"] | None = None
    is_active: bool | None = None


class UsersQuery(Schema):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


def _role_from_user(user) -> str:
    return get_user_role(user) or ROLE_USER


def build_router() -> Router:
    router = Router()

    @router.post("/", response=UserDetailOut)
    def create_user(request: HttpRequest, payload: UserCreateIn):
        """Create a user with role and password (admin or operator)."""
        require_roles(request, ROLE_ADMIN, ROLE_OPERATOR)
        User = get_user_model()
        email = payload.email.strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise HttpError(422, {"email": ["Email already exists."]})
        user = User(username=email, email=email, is_active=True)
        user.set_password(payload.password)
        try:
            user.save()
        except IntegrityError:
            raise HttpError(422, {"email": ["Email already exists."]})
        try:
            set_user_role(user, payload.role)
        except ValueError:
            raise HttpError(422, {"role": ["Invalid role."]})
        user.save()
        return {
            "id": user.id,
            "email": user.email,
            "role": _role_from_user(user),
            "is_active": user.is_active,
        }

    @router.get("/", response=List[UserListOut])
    def list_users(request: HttpRequest, pagination: UsersQuery = Query(...)):
        """List users with pagination (admin or operator)."""
        require_roles(request, ROLE_ADMIN, ROLE_OPERATOR)
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
        """Get user details by id (admin or operator)."""
        require_roles(request, ROLE_ADMIN, ROLE_OPERATOR)
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
        require_roles(request, ROLE_ADMIN)
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
            try:
                set_user_role(user, payload.role)
            except ValueError:
                raise HttpError(422, {"role": ["Invalid role."]})
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
        require_roles(request, ROLE_ADMIN)
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise HttpError(404, "Not Found")
        user.delete()
        return 204, None

    return router


router = build_router()
