"""
threat_intel/feeds/abusech_ip.py
=================================
Downloads the Feodo Tracker IP blocklist from abuse.ch.
No API key required. Updated hourly upstream.

Feed URL: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
Format: plain text, one IP per line (# comments)

Refresh cadence: Every 6 hours (configured in manager.py)
Cache TTL: 6 hours
"""
from __future__ import annotations

import structlog
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from threat_intel.cache import cache_bulk_set

logger = structlog.get_logger(__name__)

_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
_SOURCE_NAME = "feodo_ip_blocklist"
_TTL_HOURS = 6.0


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30))
async def sync_feodo_ip_blocklist() -> int:
    """
    Download and cache the Feodo IP blocklist.
    Returns the number of IPs loaded.
    """
    logger.info("feodo_sync_starting", url=_FEED_URL)

    async with httpx.AsyncClient(timeout=30.0, headers={"User-Agent": "SentinelAI/1.0"}) as client:
        resp = await client.get(_FEED_URL)
        resp.raise_for_status()

    entries = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Some lines have trailing comments after a space
        ip = line.split()[0]
        entries.append({
            "key": f"ip:{ip}",
            "data": {
                "ip": ip,
                "is_malicious": True,
                "source": _SOURCE_NAME,
                "tags": ["c2", "botnet"],
                "abuse_score": 100,
            },
        })

    if entries:
        await cache_bulk_set(entries, intel_type="ip_reputation", source=_SOURCE_NAME, ttl_hours=_TTL_HOURS)

    logger.info("feodo_sync_complete", count=len(entries))
    return len(entries)


async def check_ip(ip: str) -> dict | None:
    """Check a single IP against the cached Feodo blocklist."""
    from threat_intel.cache import cache_get
    return await cache_get(f"ip:{ip}")
