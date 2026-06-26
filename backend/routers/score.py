from fastapi import APIRouter, Depends, HTTPException, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from db import get_db, ApiKey, ScoreLog
from services.ml_service import predict
from services.feature_service import get_ct_srv_src
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
    result = await db.execute(select(ApiKey).where(ApiKey.key_hash == hashed, ApiKey.is_active == True))
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    return key


@router.post("/score")
@limiter.limit("60/minute")
async def score_request(
    request: Request,
    body:    ScoreIn,
    api_key: ApiKey        = Depends(resolve_api_key),
    db:      AsyncSession  = Depends(get_db),
):
    ct_srv_src = await get_ct_srv_src(db, api_key.id, body.srcip, body.service)

    result = predict(body.dict(), ct_srv_src)

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

    return result
