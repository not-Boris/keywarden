from __future__ import annotations

from typing import List, Literal

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.http import HttpRequest
from ninja import Query, Router, Schema
from ninja.errors import HttpError
from pydantic import EmailStr, Field

from apps.core.rbac import ROLE_USER, get_user_role, require_perms, set_user_role


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
        """Create a platform user and assign a Keywarden role.

        Auth: required.
        Permissions: requires `auth.add_user` (admin/operator).
        Behavior: uses email as username, hashes the password, and assigns a
        role which maps to Keywarden group permissions.
        Rationale: enables automation and external admin workflows; mirrors
        the admin UI user creation flow.
        """
        require_perms(request, "auth.add_user")
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
        """List users for administrative visibility and access management.

        Auth: required.
        Permissions: requires `auth.view_user`.
        Pagination: limit + offset.
        Rationale: used by admin UI and automation to audit user access.
        """
        require_perms(request, "auth.view_user")
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
        """Fetch a single user record for inspection.

        Auth: required.
        Permissions: requires `auth.view_user`.
        Rationale: used by admin detail views and automation scripts.
        """
        require_perms(request, "auth.view_user")
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
        """Update user role, password, or activation state.

        Auth: required.
        Permissions: requires `auth.change_user` (admin).
        Side effects: role changes update Keywarden role/group mappings.
        Security: user email is immutable and cannot be changed.
        Rationale: required for role delegation and account lifecycle control.
        """
        require_perms(request, "auth.change_user")
        if payload.password is None and payload.role is None and payload.is_active is None:
            raise HttpError(422, {"detail": "No fields provided."})
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise HttpError(404, "Not Found")
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

    return router


router = build_router()
