from typing import Literal, TypedDict

from ninja import Router


class HealthResponse(TypedDict):
    status: Literal["ok"]


def build_router() -> Router:
    router = Router()

    @router.get("/health", response=HealthResponse)
    def health() -> HealthResponse:
        """Health check endpoint for service monitoring."""
        return {"status": "ok"}

    return router


router = build_router()
