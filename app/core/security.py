from datetime import datetime, timedelta, timezone
from jose import jwt
from passlib.hash import argon2
from app.core.config import settings

ALGO = "HS256"

def create_access_token(sub: str, minutes: int | None = None) -> str:
    expire = datetime.now(tz=timezone.utc) + timedelta(minutes=minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": sub, "exp": expire}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGO)

def verify_password(password: str, hashed: str) -> bool:
    return argon2.verify(password, hashed)

def hash_password(password: str) -> str:
    return argon2.hash(password)