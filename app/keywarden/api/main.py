from typing import List, Optional

from ninja import NinjaAPI, Router, Schema
from ninja.security import django_auth

from .security import JWTAuth
from .routers.accounts import router as accounts_router
from .routers.audit import router as audit_router
from .routers.system import router as system_router
from .routers.servers import router as servers_router


api = NinjaAPI(
    title="Keywarden API",
    version="1.0.0",
    description="Authenticated API for internal app use and external clients.",
    auth=[django_auth, JWTAuth()],
    csrf=True,  # enforce CSRF for session-authenticated unsafe requests
)

# Mount routers
api.add_router("/system", system_router, tags=["system"])
api.add_router("/user", accounts_router, tags=["user"])
api.add_router("/audit", audit_router, tags=["audit"])
api.add_router("/servers", servers_router, tags=["servers"])


