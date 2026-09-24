"""
threat_intel/feeds/abusech_hash.py
====================================
MalwareBazaar (abuse.ch) malware hash feed integration.

Two modes:
  1. Daily bulk sync: downloads recent malware additions (last 24h JSON)
  2. Real-time lookup: POST to /api/v1/ with hash for instant check

Requires: Free API key from https://auth.abuse.ch/
Feed URL (bulk): https://mb-api.abuse.ch/api/v1/ (POST query=get_recent)
Lookup URL:      https://mb-api.abuse.ch/api/v1/ (POST query=get_info&hash=SHA256)

Cache TTL: 7 days for hash lookups (malware rarely "un-maliwares")
"""
from __future__ import annotations

import structlog
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from backend.config import get_settings
from threat_intel.cache import cache_bulk_set, cache_get, cache_set

logger = structlog.get_logger(__name__)

_API_URL = "https://mb-api.abuse.ch/api/v1/"
_SOURCE_NAME = "malwarebazaar"
_HASH_TTL_HOURS = 168.0  # 7 days


def _get_headers() -> dict:
    key = get_settings().malwarebazaar_api_key
    if not key:
        raise ValueError("MALWAREBAZAAR_API_KEY not configured")
    return {"Auth-Key": key, "User-Agent": "SentinelAI/1.0"}


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=4, max=60))
async def sync_recent_hashes(limit: int = 100) -> int:
    """
    Bulk sync recent malware hashes from MalwareBazaar.
    Returns count of new entries cached.
    """
    logger.info("malwarebazaar_sync_starting")

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            _API_URL,
            headers=_get_headers(),
            data={"query": "get_recent", "selector": "time"},
        )
        resp.raise_for_status()

    body = resp.json()
    if body.get("query_status") != "ok":
        logger.warning("malwarebazaar_sync_failed", status=body.get("query_status"))
        return 0

    entries = []
    for sample in body.get("data", [])[:limit]:
        sha256 = sample.get("sha256_hash")
        if not sha256:
            continue
        entries.append({
            "key": f"hash:{sha256}",
            "data": {
                "sha256": sha256,
                "md5": sample.get("md5_hash"),
                "file_name": sample.get("file_name"),
                "file_type": sample.get("file_type"),
                "tags": sample.get("tags", []),
                "is_malicious": True,
                "first_seen": sample.get("first_seen"),
                "source": _SOURCE_NAME,
            },
        })

    if entries:
        await cache_bulk_set(entries, intel_type="malware_hash", source=_SOURCE_NAME, ttl_hours=_HASH_TTL_HOURS)

    logger.info("malwarebazaar_sync_complete", count=len(entries))
    return len(entries)


@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=10))
async def lookup_hash(sha256: str) -> dict | None:
    """
    Look up a specific SHA-256 hash in MalwareBazaar.
    Checks local cache first; calls API only on cache miss.
    Returns None if hash is clean or API unavailable.
    """
    cache_key = f"hash:{sha256}"

    # Cache hit
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    # API lookup
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                _API_URL,
                headers=_get_headers(),
                data={"query": "get_info", "hash": sha256},
            )
            resp.raise_for_status()

        body = resp.json()
        if body.get("query_status") == "hash_not_found":
            # Cache the "clean" result to avoid re-querying
            await cache_set(
                cache_key, "malware_hash",
                {"sha256": sha256, "is_malicious": False, "source": _SOURCE_NAME},
                source=_SOURCE_NAME,
                ttl_hours=24.0,
            )
            return None

        samples = body.get("data", [])
        if not samples:
            return None

        s = samples[0]
        data = {
            "sha256": sha256,
            "md5": s.get("md5_hash"),
            "file_name": s.get("file_name"),
            "file_type": s.get("file_type"),
            "tags": s.get("tags", []),
            "is_malicious": True,
            "first_seen": s.get("first_seen"),
            "source": _SOURCE_NAME,
        }
        await cache_set(cache_key, "malware_hash", data, source=_SOURCE_NAME, ttl_hours=_HASH_TTL_HOURS)
        return data

    except ValueError:
        logger.warning("malwarebazaar_key_missing")
        return None
    except httpx.HTTPError as exc:
        logger.warning("malwarebazaar_lookup_failed", hash=sha256[:16], error=str(exc))
        return None
