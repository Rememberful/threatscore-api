from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text


async def get_ct_srv_src(db: AsyncSession, api_key_id: int, srcip: str, service: str) -> int:
    """
    Count of connections from same srcip + service in last 100 rows for this api_key.
    Mirrors the ct_srv_src feature from UNSW-NB15.
    """
    result = await db.execute(
        text("""
            SELECT COUNT(*) FROM (
                SELECT srcip, service FROM score_logs
                WHERE api_key_id = :akid
                ORDER BY created_at DESC
                LIMIT 100
            ) recent
            WHERE srcip = :ip AND service = :svc
        """),
        {"akid": api_key_id, "ip": srcip, "svc": service}
    )
    return int(result.scalar() or 0)
