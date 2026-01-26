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
        """Return the authenticated user's profile and role context.

        Auth: required (session or JWT). Used by the UI to build navigation,
        display the user identity, and decide which actions are enabled.
        Fields: returns only the minimal identity and privilege flags needed
        by the client; no secrets or permissions lists are exposed here.
        Rationale: keeps the client-side state aligned with the session user.
        """
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
