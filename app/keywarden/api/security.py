from __future__ import annotations

import hashlib
from dataclasses import dataclass
from secrets import compare_digest
from typing import Optional

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
from django.http import HttpRequest
from ninja.security import HttpBearer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed

from apps.servers.models import Server


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


class AgentTokenAuth(HttpBearer):
    """
    Auth via Authorization: Bearer <agent token>.
    Validates enrollment-issued per-server tokens first, with an optional
    global fallback from KEYWARDEN_AGENT_API_TOKEN for migration.
    """

    def authenticate(self, request: HttpRequest, token: str) -> Optional["AgentPrincipal"]:
        candidate = _normalize_agent_token(token)
        if not candidate:
            return None

        token_hash = hash_agent_token(candidate)
        server = Server.objects.filter(agent_api_token_hash=token_hash).only("id").first()
        if server:
            return AgentPrincipal(server_id=server.id, mode="server-token")

        configured = _normalize_agent_token(getattr(settings, "KEYWARDEN_AGENT_API_TOKEN", ""))
        if configured and compare_digest(candidate, configured):
            return AgentPrincipal(server_id=None, mode="global-token")
        return None


@dataclass(frozen=True)
class AgentPrincipal:
    server_id: Optional[int]
    mode: str


def _normalize_agent_token(value: object) -> str:
    token = str(value or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def hash_agent_token(value: str) -> str:
    normalized = _normalize_agent_token(value)
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
