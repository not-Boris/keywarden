from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import JSONResponse

from app.api.v1 import auth, keys
from app.core.config import settings
from app.db.session import AsyncSessionLocal

app = FastAPI(
    title=settings.PROJECT_NAME
    )
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
app.include_router(keys.router, prefix=f"{settings.API_V1_STR}/keys", tags=["keys"])

# Is the API running?
@app.get("/livez")
async def livez():
    return {"status": "ok"}

# Is the application ready (including db)?
@app.get("/readyz")
async def readyz():
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "ok", "db": "up"}
    except SQLAlchemyError:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "db": "down"},
        )

# Is the application healthy (ready)?
@app.get("/healthz")
async def healthz():
    return await readyz()  # alias