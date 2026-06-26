from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from db import get_db, User, ApiKey
from services.auth_service import (hash_password, verify_password,
                                    create_jwt, decode_jwt,
                                    generate_api_key)

router = APIRouter(tags=["auth"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class RegisterIn(BaseModel):
    email: str
    password: str

class LoginIn(BaseModel):
    email: str
    password: str

class ApiKeyIn(BaseModel):
    label: str = "default"


# ── Helpers ───────────────────────────────────────────────────────────────────

async def get_current_user(authorization: str = Header(...), db: AsyncSession = Depends(get_db)):
    try:
        token = authorization.replace("Bearer ", "")
        user_id = decode_jwt(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/register")
async def register(body: RegisterIn, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=body.email, password_hash=hash_password(body.password))
    db.add(user)
    await db.commit()
    return {"message": "Account created"}


@router.post("/login")
async def login(body: LoginIn, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": create_jwt(user.id)}


@router.post("/apikey")
async def create_api_key(body: ApiKeyIn, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    plain, hashed = generate_api_key()
    key = ApiKey(user_id=user.id, key_hash=hashed, label=body.label)
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return {"id": key.id, "key": plain, "label": key.label, "message": "Save this key — it won't be shown again"}


@router.get("/apikey")
async def list_api_keys(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ApiKey).where(ApiKey.user_id == user.id, ApiKey.is_active == True)
    )
    keys = result.scalars().all()
    return [{"id": k.id, "label": k.label, "created_at": k.created_at} for k in keys]


@router.delete("/apikey/{key_id}")
async def revoke_api_key(key_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user.id))
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    key.is_active = False
    await db.commit()
    return {"message": "Key revoked"}
