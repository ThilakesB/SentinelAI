"""
threat_intel/manager.py
========================
Orchestrates all threat intel feed refresh jobs via APScheduler.

Schedule (all times UTC, configurable via settings):
  - Feodo IP blocklist:      Every 6 hours
  - URLhaus URL feed:        Every 6 hours
  - MalwareBazaar hashes:    Daily at 03:00
  - NVD CVE incremental:     Daily at 04:00
  - Cache cleanup:           Every 12 hours

Each job logs its own sync result to the threat_intel_sync_log table.
Failed jobs back off and retry — they never block the monitoring cycle.
"""
from __future__ import annotations

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from backend.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

_scheduler: AsyncIOScheduler | None = None


async def start_intel_manager() -> None:
    """Start all feed refresh jobs. Called from app lifespan."""
    global _scheduler
    _scheduler = AsyncIOScheduler(timezone="UTC")

    # ── Feodo IP Blocklist ─────────────────────────────────────────────────────
    _scheduler.add_job(
        _run_feed("feodo_ip", _sync_feodo),
        trigger=IntervalTrigger(hours=settings.threat_intel_refresh_hours),
        id="sync_feodo_ip",
        max_instances=1,
        coalesce=True,
    )

    # ── URLhaus ────────────────────────────────────────────────────────────────
    _scheduler.add_job(
        _run_feed("urlhaus", _sync_urlhaus),
        trigger=IntervalTrigger(hours=settings.threat_intel_refresh_hours),
        id="sync_urlhaus",
        max_instances=1,
        coalesce=True,
    )

    # ── MalwareBazaar daily bulk ───────────────────────────────────────────────
    _scheduler.add_job(
        _run_feed("malwarebazaar", _sync_malwarebazaar),
        trigger=CronTrigger(hour=settings.malwarebazaar_sync_hour, minute=0),
        id="sync_malwarebazaar",
        max_instances=1,
    )

    # ── NVD CVE daily incremental ──────────────────────────────────────────────
    _scheduler.add_job(
        _run_feed("nvd_cve", _sync_nvd),
        trigger=CronTrigger(hour=settings.nvd_sync_hour, minute=0),
        id="sync_nvd_cve",
        max_instances=1,
    )

    # ── Cache cleanup ──────────────────────────────────────────────────────────
    _scheduler.add_job(
        _purge_expired_cache,
        trigger=IntervalTrigger(hours=12),
        id="cache_purge",
        max_instances=1,
    )

    _scheduler.start()
    logger.info("intel_manager_started")

    # Run Feodo and URLhaus immediately on startup (no-key, fast)
    import asyncio
    asyncio.create_task(_run_feed("feodo_ip", _sync_feodo)(), name="feodo_init")
    asyncio.create_task(_run_feed("urlhaus", _sync_urlhaus)(), name="urlhaus_init")


async def stop_intel_manager() -> None:
    if _scheduler:
        _scheduler.shutdown(wait=False)
    logger.info("intel_manager_stopped")


# ── Feed wrappers ─────────────────────────────────────────────────────────────

def _run_feed(name: str, coro_fn):
    """Wrap a feed sync coroutine with logging and error handling."""
    async def _inner():
        logger.info("feed_sync_starting", feed=name)
        try:
            count = await coro_fn()
            logger.info("feed_sync_complete", feed=name, records=count)
            await _log_sync(name, "success", count)
        except Exception as exc:
            logger.error("feed_sync_failed", feed=name, error=str(exc))
            await _log_sync(name, "failed", 0, error_msg=str(exc))
    return _inner


async def _sync_feodo() -> int:
    from threat_intel.feeds.abusech_ip import sync_feodo_ip_blocklist
    return await sync_feodo_ip_blocklist()


async def _sync_urlhaus() -> int:
    from threat_intel.feeds.urlhaus import sync_urlhaus_feed
    return await sync_urlhaus_feed()


async def _sync_malwarebazaar() -> int:
    from threat_intel.feeds.abusech_hash import sync_recent_hashes
    return await sync_recent_hashes()


async def _sync_nvd() -> int:
    from threat_intel.feeds.nvd_cve import sync_recent_cves
    return await sync_recent_cves(days_back=1)


async def _purge_expired_cache() -> None:
    from threat_intel.cache import cache_purge_expired
    count = await cache_purge_expired()
    logger.info("cache_purge_complete", deleted=count)


async def _log_sync(
    feed_name: str,
    status: str,
    records_added: int,
    error_msg: str | None = None,
) -> None:
    """Log sync result to DB. Non-blocking — never raises."""
    try:
        from database.connection import get_db_session
        from sqlalchemy import text
        async with get_db_session() as db:
            await db.execute(
                text(
                    "INSERT INTO threat_intel_sync_log "
                    "(feed_name, status, records_added, error_msg) "
                    "VALUES (:f, :s, :r, :e)"
                ),
                {"f": feed_name, "s": status, "r": records_added, "e": error_msg},
            )
    except Exception:
        pass
