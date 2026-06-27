from fastapi import APIRouter, Depends, HTTPException, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from typing import Optional
import asyncio

from db import get_db, ApiKey, ScoreLog, IPList
from services.ml_service import predict
from services.feature_service import get_ct_srv_src, get_geo, get_history, get_velocity
from services.auth_service import hash_api_key

router  = APIRouter(tags=["score"])
limiter = Limiter(key_func=get_remote_address)


class ScoreIn(BaseModel):
    srcip:   str   = "0.0.0.0"
    sport:   int   = 0
    proto:   str   = "tcp"
    service: str   = "-"
    sbytes:  int   = 0
    dbytes:  int   = 0
    dur:     float = 0.0
    sttl:    int   = 64
    sinpkt:  float = 0.0


async def resolve_api_key(x_api_key: str = Header(...), db: AsyncSession = Depends(get_db)):
    hashed = hash_api_key(x_api_key)
    result = await db.execute(
        select(ApiKey).where(ApiKey.key_hash == hashed, ApiKey.is_active == True)
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    return key


async def check_ip_list(db: AsyncSession, api_key_id: int, srcip: str) -> Optional[str]:
    print(f"DEBUG: checking api_key_id={api_key_id}, srcip={srcip}")
    
    key_result = await db.execute(select(ApiKey).where(ApiKey.id == api_key_id))
    key = key_result.scalar_one_or_none()
    print(f"DEBUG: found key={key}, user_id={key.user_id if key else None}")
    if not key:
        return None

    all_keys = await db.execute(select(ApiKey.id).where(ApiKey.user_id == key.user_id))
    all_key_ids = [r[0] for r in all_keys.all()]
    print(f"DEBUG: all_key_ids={all_key_ids}")

    result = await db.execute(
        select(IPList).where(
            IPList.api_key_id.in_(all_key_ids),
            IPList.srcip == srcip,
        )
    )
    entries = result.scalars().all()
    print(f"DEBUG: entries found={len(entries)}")
    
    if not entries:
        return None
    types = {e.list_type for e in entries}
    if "allow" in types:
        return "allow"
    if "block" in types:
        return "block"
    return None


@router.post("/score")
@limiter.limit("60/minute")
async def score_request(
    request:            Request,
    body:               ScoreIn,
    api_key:            ApiKey        = Depends(resolve_api_key),
    db:                 AsyncSession  = Depends(get_db),
    x_threatscore_mode: Optional[str] = Header(default=None),
):
    is_shadow = (x_threatscore_mode or "").lower() == "shadow"

    # ── Check blocklist/allowlist first (before running ML) ──────────────────
    ip_status = await check_ip_list(db, api_key.id, body.srcip)

    if ip_status == "allow":
        return {
            "threat_score":           0,
            "verdict":                "SAFE",
            "flags":                  ["IP is in your allowlist"],
            "closest_attack_profile": "Normal",
            "confidence":             1.0,
            "recommendation":         "allow",
            "geo":                    {},
            "history":                {},
            "velocity":               {},
            "simulated":              is_shadow,
            "list_status":            "allowlisted",
        }

    if ip_status == "block":
        return {
            "threat_score":           100,
            "verdict":                "CRITICAL",
            "flags":                  ["IP is in your blocklist"],
            "closest_attack_profile": "Blocked",
            "confidence":             1.0,
            "recommendation":         "block",
            "geo":                    {},
            "history":                {},
            "velocity":               {},
            "simulated":              is_shadow,
            "list_status":            "blocklisted",
        }

    # ── Run ML pipeline ───────────────────────────────────────────────────────
    ct_srv_src, geo, history, velocity = await asyncio.gather(
        get_ct_srv_src(db, api_key.id, body.srcip, body.service),
        get_geo(body.srcip),
        get_history(db, api_key.id, body.srcip),
        get_velocity(db, api_key.id, body.srcip),
    )

    result = predict(body.dict(), ct_srv_src)

    # ── Log to DB ─────────────────────────────────────────────────────────────
    log = ScoreLog(
        api_key_id             = api_key.id,
        srcip                  = body.srcip,
        sport                  = body.sport,
        proto                  = body.proto,
        service                = body.service,
        sbytes                 = body.sbytes,
        dbytes                 = body.dbytes,
        dur                    = body.dur,
        sttl                   = body.sttl,
        threat_score           = result["threat_score"],
        verdict                = result["verdict"],
        closest_attack_profile = result["closest_attack_profile"],
        confidence             = result["confidence"],
        flags                  = result["flags"],
        recommendation         = result["recommendation"],
    )
    db.add(log)
    await db.commit()

    return {
        **result,
        "geo":         geo,
        "history":     history,
        "velocity":    velocity,
        "simulated":   is_shadow,
        "list_status": "none",
    }