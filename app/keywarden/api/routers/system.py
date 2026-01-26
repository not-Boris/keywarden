from typing import Literal, TypedDict

from ninja import Router

from apps.core.rbac import require_authenticated


class HealthResponse(TypedDict):
    status: Literal["ok"]


def build_router() -> Router:
    router = Router()

    @router.get("/health", response=HealthResponse)
    def health(request) -> HealthResponse:
        """Return application liveness for internal monitoring.

        Auth: required (session or JWT). This is intentionally protected to avoid
        exposing internal status to unauthenticated callers.
        Behavior: returns a static {"status": "ok"} if the app stack is reachable.
        Rationale: used by uptime checks and deployments to confirm the API
        process is running and can authenticate requests.
        """
        require_authenticated(request)
        return {"status": "ok"}

    return router


router = build_router()
