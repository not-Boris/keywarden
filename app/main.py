from fastapi import FastAPI
from app.core.config import settings
from app.api.v1 import auth, keys

app = FastAPI(title=settings.PROJECT_NAME)
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
app.include_router(keys.router, prefix=f"{settings.API_V1_STR}/keys", tags=["keys"])

# Health endpoint (useful for docker, agent and uptime)
@app.get("/healthz")
def healthz():
    return {"status": 'ok'}