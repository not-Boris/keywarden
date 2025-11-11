from typing import Optional

from django.http import HttpRequest
from ninja import Router, Schema

router = Router()


class UserSchema(Schema):
    id: int
    username: str
    email: str
    first_name: str
    last_name: str
    is_staff: bool
    is_superuser: bool


@router.get("/me", response=UserSchema)
def me(request: HttpRequest):
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


