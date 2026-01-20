from typing import Optional

from django.http import HttpRequest
from ninja import Router, Schema

from apps.core.rbac import require_authenticated

class UserSchema(Schema):
    id: int
    username: str
    email: str
    first_name: str
    last_name: str
    is_staff: bool
    is_superuser: bool


def build_router() -> Router:
    router = Router()

    @router.get("/me", response=UserSchema)
    def me(request: HttpRequest):
        """Return the current authenticated user's profile."""
        require_authenticated(request)
        user = request.user
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email or "",
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "is_staff": bool(user.is_staff),
            "is_superuser": bool(user.is_superuser),
        }

    return router


router = build_router()
