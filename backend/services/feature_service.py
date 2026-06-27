import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text


# ── ct_srv_src (existing) ─────────────────────────────────────────────────────

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


# ── Geo intelligence ──────────────────────────────────────────────────────────

async def get_geo(srcip: str) -> dict:
    """
    Fetch geo + proxy/datacenter flags from ip-api.com (free, no key needed).
    Falls back to empty dict on any error so the main response is never blocked.
    """
    # Skip private/local IPs
    private_prefixes = ("10.", "192.168.", "172.16.", "127.", "0.0.0.0", "::1")
    if any(srcip.startswith(p) for p in private_prefixes):
        return {
            "country":       "Private",
            "city":          "Local",
            "is_tor":        False,
            "is_vpn":        False,
            "is_datacenter": False,
        }

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{srcip}",
                params={"fields": "status,country,city,proxy,hosting"},
            )
            data = resp.json()
            if data.get("status") != "success":
                return {}
            return {
                "country":       data.get("country", "Unknown"),
                "city":          data.get("city", "Unknown"),
                "is_tor":        bool(data.get("proxy", False)),
                "is_vpn":        bool(data.get("proxy", False)),
                "is_datacenter": bool(data.get("hosting", False)),
            }
    except Exception:
        return {}


# ── History ───────────────────────────────────────────────────────────────────

async def get_history(db: AsyncSession, api_key_id: int, srcip: str) -> dict:
    """
    Pull historical stats for this IP from score_logs for this api_key.
    """
    try:
        result = await db.execute(
            text("""
                SELECT
                    COUNT(*)                          AS times_seen,
                    ROUND(AVG(threat_score)::numeric, 1) AS avg_score,
                    MIN(created_at)                   AS first_seen,
                    MAX(created_at)                   AS last_seen,
                    SUM(CASE WHEN recommendation = 'block' THEN 1 ELSE 0 END) AS block_count
                FROM score_logs
                WHERE api_key_id = :akid AND srcip = :ip
            """),
            {"akid": api_key_id, "ip": srcip}
        )
        row = result.mappings().one()

        times_seen = int(row["times_seen"] or 0)
        if times_seen == 0:
            return {
                "times_seen":        0,
                "avg_score":         None,
                "first_seen":        None,
                "previously_blocked": False,
            }

        return {
            "times_seen":        times_seen,
            "avg_score":         float(row["avg_score"] or 0),
            "first_seen":        row["first_seen"].strftime("%Y-%m-%d") if row["first_seen"] else None,
            "previously_blocked": int(row["block_count"] or 0) > 0,
        }
    except Exception:
        return {}


# ── Velocity ──────────────────────────────────────────────────────────────────

async def get_velocity(db: AsyncSession, api_key_id: int, srcip: str) -> dict:
    """
    Count requests from this IP in last 60s and last 1h.
    Spike = last 60s count > 10.
    """
    try:
        result = await db.execute(
            text("""
                SELECT
                    SUM(CASE WHEN created_at >= NOW() - INTERVAL '60 seconds' THEN 1 ELSE 0 END) AS last_60s,
                    SUM(CASE WHEN created_at >= NOW() - INTERVAL '1 hour'    THEN 1 ELSE 0 END) AS last_1h
                FROM score_logs
                WHERE api_key_id = :akid AND srcip = :ip
            """),
            {"akid": api_key_id, "ip": srcip}
        )
        row = result.mappings().one()
        last_60s = int(row["last_60s"] or 0)
        last_1h  = int(row["last_1h"]  or 0)

        return {
            "requests_last_60s": last_60s,
            "requests_last_1h":  last_1h,
            "spike_detected":    last_60s > 10,
        }
    except Exception:
        return {}