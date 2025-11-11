from typing import Literal, TypedDict

from ninja import Router

router = Router()


class HealthResponse(TypedDict):
    status: Literal["ok"]


@router.get("/health", response=HealthResponse)
def health() -> HealthResponse:
    return {"status": "ok"}


