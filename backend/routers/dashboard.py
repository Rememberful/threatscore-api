from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from db import get_db, User, ApiKey, ScoreLog
from services.auth_service import decode_jwt

router = APIRouter(tags=["dashboard"])


async def get_current_user(authorization: str = Header(...), db: AsyncSession = Depends(get_db)):
    try:
        token = authorization.replace("Bearer ", "")
        user_id = decode_jwt(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def get_user_key_ids(user: User, db: AsyncSession):
    result = await db.execute(select(ApiKey.id).where(ApiKey.user_id == user.id))
    return [r[0] for r in result.all()]


@router.get("/feed")
async def feed(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    key_ids = await get_user_key_ids(user, db)
    if not key_ids:
        return []
    result = await db.execute(
        select(ScoreLog)
        .where(ScoreLog.api_key_id.in_(key_ids))
        .order_by(ScoreLog.created_at.desc())
        .limit(50)
    )
    logs = result.scalars().all()
    return [
        {
            "id":                    l.id,
            "srcip":                 l.srcip,
            "proto":                 l.proto,
            "service":               l.service,
            "threat_score":          l.threat_score,
            "verdict":               l.verdict,
            "closest_attack_profile":l.closest_attack_profile,
            "recommendation":        l.recommendation,
            "flags":                 l.flags,
            "created_at":            l.created_at,
        }
        for l in logs
    ]


@router.get("/stats")
async def stats(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    key_ids = await get_user_key_ids(user, db)
    if not key_ids:
        return {"total": 0, "avg_score": 0, "verdicts": {}}

    result = await db.execute(
        select(
            func.count(ScoreLog.id),
            func.avg(ScoreLog.threat_score),
        ).where(ScoreLog.api_key_id.in_(key_ids))
    )
    total, avg_score = result.one()

    verdict_result = await db.execute(
        select(ScoreLog.verdict, func.count(ScoreLog.id))
        .where(ScoreLog.api_key_id.in_(key_ids))
        .group_by(ScoreLog.verdict)
    )
    verdicts = {row[0]: row[1] for row in verdict_result.all()}

    return {
        "total":     total or 0,
        "avg_score": round(float(avg_score or 0), 1),
        "verdicts":  verdicts,
    }


@router.get("/threats")
async def threats(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    key_ids = await get_user_key_ids(user, db)
    if not key_ids:
        return []

    result = await db.execute(
        select(
            ScoreLog.srcip,
            func.count(ScoreLog.id).label("hits"),
            func.avg(ScoreLog.threat_score).label("avg_score"),
        )
        .where(ScoreLog.api_key_id.in_(key_ids))
        .group_by(ScoreLog.srcip)
        .order_by(func.count(ScoreLog.id).desc())
        .limit(10)
    )
    return [
        {"srcip": r[0], "hits": r[1], "avg_score": round(float(r[2]), 1)}
        for r in result.all()
    ]
