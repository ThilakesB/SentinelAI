"""
threat_intel/enricher.py
=========================
Public enrichment API — the single interface the rest of the codebase
uses to query threat intelligence.

Functions:
  enrich_ip(ip)       → combined reputation from all IP feeds
  enrich_hash(sha256) → malware verdict from MalwareBazaar + cache
  enrich_process(snap) → combined enrichment for a process snapshot

Priority order (fastest/cheapest first):
  1. Local SQLite cache
  2. Feodo/URLhaus bulk list (already in cache after sync)
  3. AbuseIPDB real-time API (rate-limited, cache-backed)
  4. MalwareBazaar real-time lookup (on cache miss)
"""
from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


async def enrich_ip(ip: str) -> dict[str, Any]:
    """
    Return reputation data for an IP address.
    Merges results from Feodo blocklist and AbuseIPDB.
    Never raises — returns safe defaults on error.
    """
    from threat_intel.cache import cache_get
    from threat_intel.feeds.abuseipdb import check_ip as abuseipdb_check

    result: dict[str, Any] = {
        "ip": ip,
        "is_malicious": False,
        "abuse_score": 0,
        "sources": [],
    }

    # 1. Check Feodo / URLhaus (already in cache, instant)
    cached = await cache_get(f"ip:{ip}")
    if cached:
        result.update(cached)
        result["sources"].append(cached.get("source", "cache"))
        if cached.get("is_malicious"):
            result["is_malicious"] = True
            result["abuse_score"] = max(result["abuse_score"], cached.get("abuse_score", 100))

    # 2. AbuseIPDB (cache-backed, falls through to API on miss)
    try:
        abuse = await abuseipdb_check(ip)
        if abuse:
            score = abuse.get("abuse_score", 0)
            result["abuse_score"] = max(result["abuse_score"], score)
            result["country_code"] = abuse.get("country_code")
            result["total_reports"] = abuse.get("total_reports", 0)
            result["sources"].append("abuseipdb")
            if score > 0:
                result["is_malicious"] = result["is_malicious"] or score >= 75
    except Exception as exc:
        logger.debug("abuseipdb_enrich_error", ip=ip, error=str(exc))

    return result


async def enrich_hash(sha256: str) -> dict[str, Any]:
    """
    Return malware verdict for a SHA-256 file hash.
    Checks cache first, then MalwareBazaar API.
    """
    if not sha256:
        return {"sha256": sha256, "is_malicious": False, "sources": []}

    from threat_intel.feeds.abusech_hash import lookup_hash

    result: dict[str, Any] = {
        "sha256": sha256,
        "is_malicious": False,
        "sources": [],
    }

    try:
        data = await lookup_hash(sha256)
        if data:
            result.update(data)
            result["is_malicious"] = data.get("is_malicious", False)
            result["sources"].append(data.get("source", "malwarebazaar"))
    except Exception as exc:
        logger.debug("hash_enrich_error", hash=sha256[:16], error=str(exc))

    return result


async def enrich_process(snap: dict) -> dict[str, Any]:
    """
    Full enrichment for a process snapshot dict.
    Returns enrichment metadata (not mutating the original).

    Runs concurrently:
      - Hash lookup (MalwareBazaar)
      - YARA scan (if exe_path available)
      - CVE lookup for process name
    """
    import asyncio
    from threat_intel.feeds.local_yara import scan_file
    from threat_intel.feeds.nvd_cve import get_cves_for_product

    exe_hash = snap.get("exe_hash")
    exe_path = snap.get("exe_path")
    process_name = snap.get("name", "")

    # Run enrichments concurrently
    tasks = []
    tasks.append(enrich_hash(exe_hash) if exe_hash else _noop_coro({}))
    tasks.append(scan_file(exe_path) if exe_path else _noop_coro([]))
    tasks.append(get_cves_for_product(process_name) if process_name else _noop_coro(None))

    hash_result, yara_matches, cve_data = await asyncio.gather(*tasks, return_exceptions=True)

    return {
        "hash_intel": hash_result if not isinstance(hash_result, Exception) else {},
        "yara_matches": yara_matches if not isinstance(yara_matches, Exception) else [],
        "cve_data": cve_data if not isinstance(cve_data, Exception) else None,
        "hash_is_malicious": (
            isinstance(hash_result, dict) and hash_result.get("is_malicious", False)
        ),
        "yara_hit": bool(yara_matches) if not isinstance(yara_matches, Exception) else False,
    }


async def _noop_coro(default):
    return default
