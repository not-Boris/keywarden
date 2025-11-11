from __future__ import annotations

from typing import Optional

from django.contrib.auth.models import AbstractBaseUser
from django.http import HttpRequest
from ninja.security import HttpBearer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed


class JWTAuth(HttpBearer):
    """
    Auth via Authorization: Bearer <JWT>.
    Validates tokens using DRF SimpleJWT and returns the associated Django user.
    """

    def __init__(self) -> None:
        super().__init__()
        self._jwt_auth = JWTAuthentication()

    def authenticate(self, request: HttpRequest, token: str) -> Optional[AbstractBaseUser]:
        try:
            validated = self._jwt_auth.get_validated_token(token)
            user = self._jwt_auth.get_user(validated)
            return user
        except (InvalidToken, AuthenticationFailed):
            return None


