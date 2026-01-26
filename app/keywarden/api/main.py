import inspect
from typing import List, Optional

from ninja import NinjaAPI, Router, Schema, Redoc
from ninja.security import django_auth

from .security import JWTAuth
from .routers.accounts import build_router as build_accounts_router
from .routers.audit import build_router as build_audit_router
from .routers.system import build_router as build_system_router
from .routers.servers import build_router as build_servers_router
from .routers.users import build_router as build_users_router
from .routers.keys import build_router as build_keys_router
from .routers.access import build_router as build_access_router
from .routers.telemetry import build_router as build_telemetry_router
from .routers.agent import build_router as build_agent_router

from django.contrib.admin.views.decorators import staff_member_required

def register_routers(target_api: NinjaAPI) -> None:
    target_api.add_router("/system", build_system_router(), tags=["System"])
    target_api.add_router("/user", build_accounts_router(), tags=["Account Context"])
    target_api.add_router("/audit", build_audit_router(), tags=["Audit Logging"])
    target_api.add_router("/servers", build_servers_router(), tags=["Servers"])
    target_api.add_router("/users", build_users_router(), tags=["User Directory"])
    target_api.add_router("/keys", build_keys_router(), tags=["SSH Keys"])
    target_api.add_router("/access-requests", build_access_router(), tags=["Access Requests"])
    target_api.add_router("/telemetry", build_telemetry_router(), tags=["Telemetry"])
    target_api.add_router("/agent", build_agent_router(), tags=["Agent"])


def build_api(**kwargs) -> NinjaAPI:
    if "csrf" in inspect.signature(NinjaAPI).parameters:
        return NinjaAPI(csrf=True, **kwargs)
    return NinjaAPI(**kwargs)


api = build_api(
    title="Keywarden API",
    version="1.0.0",
    description="Authenticated API for internal app use and external clients.",
    auth=[django_auth, JWTAuth()],
    docs=Redoc(),
    docs_decorator=staff_member_required,
)
register_routers(api)

api_v1 = build_api(
    title="Keywarden API",
    version="1.0.0",
    description="Authenticated API for internal app use and external clients.",
    auth=[django_auth, JWTAuth()],
    urls_namespace="api-v1",
    docs=Redoc(),
    docs_decorator=staff_member_required,
)
register_routers(api_v1)
