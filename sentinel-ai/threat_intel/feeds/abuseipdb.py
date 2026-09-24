"""
threat_intel/feeds/abuseipdb.py
================================
AbuseIPDB REST API integration for real-time IP reputation checks.

Free tier: 1,000 checks/day.
Strategy: Always check local cache first (TTL 24h); call API only on miss.
Rate limiter: token bucket, max 40 req/hour internal cap (well under daily limit).

API: https://docs.abuseipdb.com/#check-endpoint
Requires: Free API key from https://www.abuseipdb.com/register
"""
from __future__ import annotations

import asyncio
import time

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from backend.config import get_settings
from threat_intel.cache import cache_get, cache_set

logger = structlog.get_logger(__name__)

_API_URL = "https://api.abuseipdb.com/api/v2/check"
_SOURCE_NAME = "abuseipdb"
_CACHE_TTL_HOURS = 24.0

# Simple token bucket: 40 requests per hour (1 per 90s on average)
_REQUEST_INTERVAL_SEC = 3.0  # Minimum seconds between API calls
_last_call_time: float = 0.0
_rate_lock = asyncio.Lock()


@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=5, max=30))
async def check_ip(ip: str) -> dict:
    """
    Returns AbuseIPDB reputation data for the given IP.
    Returns from cache if available; calls API on miss.
    Falls back to empty dict (non-blocking) if API unavailable.

    Return dict keys:
      abuse_score (0-100), total_reports, country_code, is_whitelisted
    """
    cache_key = f"ip:{ip}"

    # Check local cache first
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    settings = get_settings()
    if not settings.abuseipdb_api_key:
        logger.warning("abuseipdb_key_missing", note="Set ABUSEIPDB_API_KEY in .env")
        return {"abuse_score": 0, "source": _SOURCE_NAME, "ip": ip}

    # Rate limit: enforce minimum interval between API calls
    async with _rate_lock:
        global _last_call_time
        elapsed = time.monotonic() - _last_call_time
        if elapsed < _REQUEST_INTERVAL_SEC:
            await asyncio.sleep(_REQUEST_INTERVAL_SEC - elapsed)
        _last_call_time = time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                _API_URL,
                headers={
                    "Key": settings.abuseipdb_api_key,
                    "Accept": "application/json",
                    "User-Agent": "SentinelAI/1.0",
                },
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            )

            if resp.status_code == 429:
                logger.warning("abuseipdb_rate_limited", ip=ip)
                return {"abuse_score": 0, "source": _SOURCE_NAME, "ip": ip, "rate_limited": True}

            resp.raise_for_status()
            body = resp.json()
            d = body.get("data", {})

        data = {
            "ip": ip,
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country_code": d.get("countryCode"),
            "is_whitelisted": d.get("isWhitelisted", False),
            "usage_type": d.get("usageType"),
            "domain": d.get("domain"),
            "source": _SOURCE_NAME,
        }

        await cache_set(cache_key, "ip_reputation", data, source=_SOURCE_NAME, ttl_hours=_CACHE_TTL_HOURS)
        logger.debug("abuseipdb_checked", ip=ip, score=data["abuse_score"])
        return data

    except httpx.HTTPError as exc:
        logger.warning("abuseipdb_api_error", ip=ip, error=str(exc))
        return {"abuse_score": 0, "source": _SOURCE_NAME, "ip": ip}
