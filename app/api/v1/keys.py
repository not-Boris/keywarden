from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_db, get_current_user
from app.models.sshkey import SSHKey
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from datetime import datetime, timezone
import base64

router = APIRouter()

ALLOWED_ALGOS = {"ssh-ed25519", "ecdsa-sha2-nistp256"}  # expand if needed

class SSHKeyIn(BaseModel):
    name: str
    public_key: str
    expires_at: datetime | None = None

    @field_validator("public_key")
    @classmethod
    def validate_pubkey(cls, v: str):
        # quick parse: "<algo> <b64> [comment]"
        parts = v.strip().split()
        if len(parts) < 2:
            raise ValueError("Invalid SSH public key format")
        algo, b64 = parts[0], parts[1]
        if algo not in ALLOWED_ALGOS:
            raise ValueError(f"Key algorithm not allowed: {algo}")
        try:
            base64.b64decode(b64)
        except Exception:
            raise ValueError("Public key is not valid base64")
        return v

class SSHKeyOut(BaseModel):
    id: int
    name: str
    algo: str
    public_key: str
    expires_at: datetime | None
    is_active: bool

@router.post("/", response_model=SSHKeyOut)
async def add_key(data: SSHKeyIn, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    algo = data.public_key.split()[0]
    key = SSHKey(user_id=user.id, name=data.name, public_key=data.public_key, algo=algo,
                 expires_at=data.expires_at)
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return SSHKeyOut(id=key.id, name=key.name, algo=key.algo, public_key=key.public_key,
                     expires_at=key.expires_at, is_active=key.is_active)

@router.get("/", response_model=list[SSHKeyOut])
async def list_keys(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    res = await db.execute(select(SSHKey).where(SSHKey.user_id == user.id))
    rows = res.scalars().all()
    return [SSHKeyOut(id=k.id, name=k.name, algo=k.algo, public_key=k.public_key,
                      expires_at=k.expires_at, is_active=k.is_active) for k in rows]