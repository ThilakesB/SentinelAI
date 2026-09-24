"""
threat_intel/feeds/urlhaus.py
==============================
URLhaus (abuse.ch) malicious URL/domain feed.
No API key required. Bulk CSV download, updated every 5 minutes upstream.

Feed URL: https://urlhaus.abuse.ch/downloads/csv/
Format: CSV with columns: id, dateadded, url, url_status, tags, urlhaus_link, reporter

Refresh cadence: Every 6 hours.
Cache TTL: 6 hours.
"""
from __future__ import annotations

import csv
import io

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from threat_intel.cache import cache_bulk_set

logger = structlog.get_logger(__name__)

_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv/"
_SOURCE_NAME = "urlhaus"
_TTL_HOURS = 6.0


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30))
async def sync_urlhaus_feed() -> int:
    """
    Download and cache URLhaus malicious URL/domain list.
    Returns count of entries cached.
    """
    logger.info("urlhaus_sync_starting")

    async with httpx.AsyncClient(
        timeout=60.0,
        headers={"User-Agent": "SentinelAI/1.0"},
        follow_redirects=True,
    ) as client:
        resp = await client.get(_FEED_URL)
        resp.raise_for_status()

    entries = []
    domains_seen: set[str] = set()

    reader = csv.reader(io.StringIO(resp.text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 3:
            continue

        url = row[2].strip()
        status = row[3].strip() if len(row) > 3 else "unknown"

        # Cache the full URL
        entries.append({
            "key": f"url:{url}",
            "data": {
                "url": url,
                "status": status,
                "tags": row[4].strip() if len(row) > 4 else "",
                "is_malicious": True,
                "source": _SOURCE_NAME,
            },
        })

        # Also cache by domain for connection-level checks
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).hostname
            if domain and domain not in domains_seen:
                domains_seen.add(domain)
                entries.append({
                    "key": f"ip:{domain}",  # Use same key prefix for lookup consistency
                    "data": {
                        "domain": domain,
                        "is_malicious": True,
                        "abuse_score": 90,
                        "source": _SOURCE_NAME,
                    },
                })
        except Exception:
            pass

    if entries:
        await cache_bulk_set(entries, intel_type="malicious_url", source=_SOURCE_NAME, ttl_hours=_TTL_HOURS)

    logger.info("urlhaus_sync_complete", urls=len(entries) - len(domains_seen), domains=len(domains_seen))
    return len(entries)
