# ruff was driving me crazy with imported not used, noqa on all of these..
from fastapi import Depends, HTTPException, status  # noqa: F401
from fastapi.security import HTTPBearer  # noqa: F401
from jose import JWTError, jwt  # noqa: F401
from sqlalchemy import select  # noqa: F401
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: F401

from app.core.config import settings  # noqa: F401
from app.db.session import get_session  # noqa: F401
from app.models.user import User  # noqa: F401

bearer = HTTPBearer()

async def get_db() -> AsyncSession:
    async for s in get_session():
        yield s

async def get_current_user(token=Depends(bearer), db: AsyncSession = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token.credentials, settings.SECRET_KEY, algorithms=["HS256"])
        email: str = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    res = await db.execute(select(User).where(User.email == email))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_role(*roles: str):
    async def _dep(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return _dep