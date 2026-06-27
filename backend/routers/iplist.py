from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from pydantic import BaseModel
from typing import Optional

from db import get_db, User, ApiKey, IPList
from services.auth_service import decode_jwt

router = APIRouter(tags=["iplist"])


# ── Auth helper ───────────────────────────────────────────────────────────────

async def get_current_user(authorization: str = Header(...), db: AsyncSession = Depends(get_db)):
    try:
        token   = authorization.replace("Bearer ", "")
        user_id = decode_jwt(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    result = await db.execute(select(User).where(User.id == user_id))
    user   = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def get_user_key_ids(user: User, db: AsyncSession):
    result = await db.execute(select(ApiKey.id).where(ApiKey.user_id == user.id))
    return [r[0] for r in result.all()]


# ── Schemas ───────────────────────────────────────────────────────────────────

class IPListIn(BaseModel):
    srcip:  str
    reason: Optional[str] = None


# ── Blocklist ─────────────────────────────────────────────────────────────────

@router.post("/blocklist")
async def add_to_blocklist(
    body: IPListIn,
    user: User           = Depends(get_current_user),
    db:   AsyncSession   = Depends(get_db),
):
    key_ids = await get_user_key_ids(user, db)
    if not key_ids:
        raise HTTPException(status_code=400, detail="No API keys found")

    # Check if already exists
    existing = await db.execute(
        select(IPList).where(
            IPList.api_key_id.in_(key_ids),
            IPList.srcip      == body.srcip,
            IPList.list_type  == "block",
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="IP already in blocklist")

    entry = IPList(
        api_key_id = key_ids[0],
        srcip      = body.srcip,
        list_type  = "block",
        reason     = body.reason,
    )
    db.add(entry)
    await db.commit()
    return {"message": f"{body.srcip} added to blocklist"}


@router.get("/blocklist")
async def get_blocklist(
    user: User         = Depends(get_current_user),
    db:   AsyncSession = Depends(get_db),
):
    key_ids = await get_user_key_ids(user, db)
    if not key_ids:
        return []
    result = await db.execute(
        select(IPList).where(
            IPList.api_key_id.in_(key_ids),
            IPList.list_type == "block",
        ).order_by(IPList.created_at.desc())
    )
    entries = result.scalars().all()
    return [
        {
            "id":         e.id,
            "srcip":      e.srcip,
            "reason":     e.reason,
            "created_at": e.created_at,
        }
        for e in entries
    ]


@router.delete("/blocklist/{srcip}")
async def remove_from_blocklist(
    srcip: str,
    user:  User         = Depends(get_current_user),
    db:    AsyncSession = Depends(get_db),
):
    key_ids = await get_user_key_ids(user, db)
    result  = await db.execute(
        select(IPList).where(
            IPList.api_key_id.in_(key_ids),
            IPList.srcip     == srcip,
            IPList.list_type == "block",
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="IP not in blocklist")
    await db.delete(entry)
    await db.commit()
    return {"message": f"{srcip} removed from blocklist"}


# ── Allowlist ─────────────────────────────────────────────────────────────────

@router.post("/allowlist")
async def add_to_allowlist(
    body: IPListIn,
    user: User         = Depends(get_current_user),
    db:   AsyncSession = Depends(get_db),
):
    key_ids = await get_user_key_ids(user, db)
    if not key_ids:
        raise HTTPException(status_code=400, detail="No API keys found")

    existing = await db.execute(
        select(IPList).where(
            IPList.api_key_id.in_(key_ids),
            IPList.srcip     == body.srcip,
            IPList.list_type == "allow",
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="IP already in allowlist")

    entry = IPList(
        api_key_id = key_ids[0],
        srcip      = body.srcip,
        list_type  = "allow",
        reason     = body.reason,
    )
    db.add(entry)
    await db.commit()
    return {"message": f"{body.srcip} added to allowlist"}


@router.get("/allowlist")
async def get_allowlist(
    user: User         = Depends(get_current_user),
    db:   AsyncSession = Depends(get_db),
):
    key_ids = await get_user_key_ids(user, db)
    if not key_ids:
        return []
    result = await db.execute(
        select(IPList).where(
            IPList.api_key_id.in_(key_ids),
            IPList.list_type == "allow",
        ).order_by(IPList.created_at.desc())
    )
    entries = result.scalars().all()
    return [
        {
            "id":         e.id,
            "srcip":      e.srcip,
            "reason":     e.reason,
            "created_at": e.created_at,
        }
        for e in entries
    ]


@router.delete("/allowlist/{srcip}")
async def remove_from_allowlist(
    srcip: str,
    user:  User         = Depends(get_current_user),
    db:    AsyncSession = Depends(get_db),
):
    key_ids = await get_user_key_ids(user, db)
    result  = await db.execute(
        select(IPList).where(
            IPList.api_key_id.in_(key_ids),
            IPList.srcip     == srcip,
            IPList.list_type == "allow",
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="IP not in allowlist")
    await db.delete(entry)
    await db.commit()
    return {"message": f"{srcip} removed from allowlist"}