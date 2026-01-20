from typing import Literal, TypedDict

from ninja import Router

from apps.core.rbac import require_authenticated


class HealthResponse(TypedDict):
    status: Literal["ok"]


def build_router() -> Router:
    router = Router()

    @router.get("/health", response=HealthResponse)
    def health(request) -> HealthResponse:
        """Health check endpoint for service monitoring."""
        require_authenticated(request)
        return {"status": "ok"}

    return router


router = build_router()
