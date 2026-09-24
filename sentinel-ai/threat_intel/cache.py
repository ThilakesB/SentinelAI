"""
threat_intel/cache.py
=====================
SQLite-backed local threat intel cache with TTL.

Primary cache for all feed data — checked before any external API call.
Keyed as:
  "ip:{ip_address}"         → IP reputation data
  "hash:{sha256}"           → Malware hash data
  "url:{url_or_domain}"     → URLhaus malicious URL data

Cache entries expire based on feed-specific TTL:
  - IP blocklists (Feodo): 6h
  - AbuseIPDB real-time: 24h
  - Hash lookups: 7 days
  - URLhaus: 6h
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import orjson
import structlog

from database.local_db import get_local_db

logger = structlog.get_logger(__name__)


async def cache_get(key: str) -> dict | None:
    """Return cached data if it exists and has not expired. Returns None otherwise."""
    async with get_local_db() as db:
        async with db.execute(
            "SELECT data_json, expires_at FROM threat_intel_cache WHERE cache_key = ?",
            (key,),
        ) as cur:
            row = await cur.fetchone()

    if row is None:
        return None

    expires_at = datetime.fromisoformat(row["expires_at"])
    if expires_at < datetime.now(timezone.utc).replace(tzinfo=None):
        # Expired — delete stale entry
        await cache_delete(key)
        return None

    return orjson.loads(row["data_json"])


async def cache_set(
    key: str,
    intel_type: str,
    data: dict,
    source: str,
    ttl_hours: float = 6.0,
) -> None:
    """Insert or replace a cache entry with a TTL."""
    expires_at = (
        datetime.utcnow() + timedelta(hours=ttl_hours)
    ).isoformat()

    async with get_local_db() as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO threat_intel_cache
                (cache_key, intel_type, data_json, source, created_at, expires_at)
            VALUES (?, ?, ?, ?, datetime('now'), ?)
            """,
            (key, intel_type, orjson.dumps(data).decode(), source, expires_at),
        )
        await db.commit()


async def cache_delete(key: str) -> None:
    async with get_local_db() as db:
        await db.execute(
            "DELETE FROM threat_intel_cache WHERE cache_key = ?", (key,)
        )
        await db.commit()


async def cache_purge_expired() -> int:
    """Delete all expired cache entries. Returns count deleted."""
    async with get_local_db() as db:
        cur = await db.execute(
            "DELETE FROM threat_intel_cache WHERE expires_at < datetime('now')"
        )
        await db.commit()
        count = cur.rowcount
    if count:
        logger.info("cache_purged", entries_deleted=count)
    return count


async def cache_bulk_set(
    entries: list[dict[str, Any]],
    intel_type: str,
    source: str,
    ttl_hours: float = 6.0,
) -> None:
    """
    Efficiently insert many cache entries in a single transaction.
    Each entry must have a 'key' and 'data' field.
    """
    expires_at = (datetime.utcnow() + timedelta(hours=ttl_hours)).isoformat()
    rows = [
        (e["key"], intel_type, orjson.dumps(e["data"]).decode(), source, expires_at)
        for e in entries
    ]
    async with get_local_db() as db:
        await db.executemany(
            """
            INSERT OR REPLACE INTO threat_intel_cache
                (cache_key, intel_type, data_json, source, created_at, expires_at)
            VALUES (?, ?, ?, ?, datetime('now'), ?)
            """,
            rows,
        )
        await db.commit()
    logger.info("cache_bulk_set", count=len(rows), source=source)
