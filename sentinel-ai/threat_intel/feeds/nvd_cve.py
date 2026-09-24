"""
threat_intel/feeds/nvd_cve.py
==============================
NIST NVD API v2 integration for CVE/vulnerability data.

Strategy: Incremental daily sync — only fetch CVEs modified since last run.
Stores CVEs keyed by affected product name for process-level enrichment.

Free API key: https://nvd.nist.gov/developers/request-an-api-key
Rate limits:
  - With key:    50 req / 30s
  - Without key: 5 req / 30s

Cache TTL: 48 hours per CVE record (vulnerability info changes slowly).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from backend.config import get_settings
from threat_intel.cache import cache_bulk_set, cache_get

logger = structlog.get_logger(__name__)

_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_SOURCE_NAME = "nvd_cve"
_CACHE_TTL_HOURS = 48.0
_PAGE_SIZE = 100  # NVD max results per request


def _get_headers() -> dict:
    key = get_settings().nvd_api_key
    headers = {"User-Agent": "SentinelAI/1.0"}
    if key:
        headers["apiKey"] = key
    return headers


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=5, max=60))
async def sync_recent_cves(days_back: int = 1) -> int:
    """
    Fetch CVEs modified in the last N days and cache them.
    Returns total CVEs processed.
    """
    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    logger.info("nvd_sync_starting", days_back=days_back, start=start_date)

    total_processed = 0
    start_index = 0
    has_key = bool(get_settings().nvd_api_key)

    while True:
        params = {
            "lastModStartDate": start_date,
            "lastModEndDate": end_date,
            "resultsPerPage": _PAGE_SIZE,
            "startIndex": start_index,
        }

        # Respect rate limits (6s between requests without key)
        await asyncio.sleep(1.0 if has_key else 7.0)

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(_API_URL, headers=_get_headers(), params=params)
            if resp.status_code == 403:
                logger.warning("nvd_rate_limited", note="Backing off 35 seconds")
                await asyncio.sleep(35)
                continue
            resp.raise_for_status()

        body = resp.json()
        vulnerabilities = body.get("vulnerabilities", [])
        total_results = body.get("totalResults", 0)

        entries = _parse_cves(vulnerabilities)
        if entries:
            await cache_bulk_set(
                entries, intel_type="cve", source=_SOURCE_NAME, ttl_hours=_CACHE_TTL_HOURS
            )

        total_processed += len(vulnerabilities)
        logger.debug("nvd_page_fetched", start_index=start_index, count=len(vulnerabilities))

        start_index += _PAGE_SIZE
        if start_index >= total_results:
            break

    logger.info("nvd_sync_complete", total=total_processed)
    return total_processed


def _parse_cves(vulnerabilities: list[dict]) -> list[dict]:
    """Parse NVD response items into cache entries keyed by CVE ID and affected product."""
    entries = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        severity = _extract_severity(cve)
        affected_products = _extract_products(cve)
        description = _extract_description(cve)

        data = {
            "cve_id": cve_id,
            "severity": severity,
            "description": description,
            "affected_products": affected_products,
            "published": cve.get("published"),
            "source": _SOURCE_NAME,
        }

        # Key by CVE ID
        entries.append({"key": f"cve:{cve_id}", "data": data})

        # Also key by product name for fast process-level lookup
        for product in affected_products:
            entries.append({"key": f"product_cve:{product.lower()}", "data": data})

    return entries


def _extract_severity(cve: dict) -> str:
    """Extract highest CVSS severity string."""
    try:
        metrics = cve.get("metrics", {})
        for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            items = metrics.get(version, [])
            if items:
                return items[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
    except Exception:
        pass
    return "UNKNOWN"


def _extract_products(cve: dict) -> list[str]:
    """Extract affected product names from CPE matches."""
    products = []
    try:
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    # CPE format: cpe:2.3:a:vendor:product:version:...
                    parts = cpe.split(":")
                    if len(parts) > 4:
                        products.append(parts[4])  # product name
    except Exception:
        pass
    return list(set(products))


def _extract_description(cve: dict) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")[:500]
    return ""


async def get_cves_for_product(product_name: str) -> dict | None:
    """Look up cached CVEs for a product name (used during process enrichment)."""
    return await cache_get(f"product_cve:{product_name.lower()}")
