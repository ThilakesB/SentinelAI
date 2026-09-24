"""
monitoring/collector.py
========================
Orchestrator for all monitoring sub-systems.

Responsibilities:
  1. Schedule psutil process + network snapshots every N seconds (APScheduler)
  2. Start ETW monitor thread (catches short-lived processes)
  3. Pipe each snapshot through the AI engine for classification
  4. Persist results (process, network, threat events) to DB
  5. Push classified events to the WebSocket broadcaster queue

Start/stop called from FastAPI app lifespan (backend/main.py).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from backend.config import get_settings
from monitoring.etw_monitor import start_etw_monitor, stop_etw_monitor
from monitoring.network_monitor import collect_network_snapshot
from monitoring.process_monitor import collect_process_snapshot
from monitoring.resource_baseline import baseline

logger = structlog.get_logger(__name__)
settings = get_settings()

_scheduler: AsyncIOScheduler | None = None
_event_queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)
# WebSocket broadcaster queue — set by realtime.py after startup
_ws_queue: asyncio.Queue | None = None


def set_ws_queue(q: asyncio.Queue) -> None:
    """Called by websocket/realtime.py to wire in the WS broadcast queue."""
    global _ws_queue
    _ws_queue = q


async def start_collector() -> None:
    """Start the scheduler and ETW monitor. Called from app lifespan."""
    global _scheduler

    # Restore baseline from previous run
    await baseline.load_from_local_db()

    _scheduler = AsyncIOScheduler(timezone="UTC")
    _scheduler.add_job(
        _monitoring_cycle,
        trigger=IntervalTrigger(seconds=settings.monitoring_interval_sec),
        id="monitoring_cycle",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=settings.monitoring_interval_sec,
    )
    # Persist baseline every 5 minutes
    _scheduler.add_job(
        baseline.persist_to_local_db,
        trigger=IntervalTrigger(minutes=5),
        id="baseline_persist",
        max_instances=1,
    )
    _scheduler.start()

    # Start ETW in background thread
    start_etw_monitor(_event_queue)

    # Start ETW event consumer
    asyncio.create_task(_etw_event_consumer(), name="etw_consumer")

    logger.info(
        "collector_started",
        interval_sec=settings.monitoring_interval_sec,
    )


async def stop_collector() -> None:
    """Stop the scheduler and ETW monitor cleanly."""
    if _scheduler:
        _scheduler.shutdown(wait=False)
    stop_etw_monitor()
    await baseline.persist_to_local_db()
    logger.info("collector_stopped")


async def _monitoring_cycle() -> None:
    """
    One full monitoring + classification + persistence cycle.
    Target: < 500ms total.
    """
    import time
    start = time.monotonic()

    try:
        # 1. Collect process and network data concurrently
        proc_snaps, net_snaps = await asyncio.gather(
            collect_process_snapshot(),
            collect_network_snapshot(),
        )

        # 2. Classify with AI engine (batched)
        from ai_engine.isolation_forest import classify_batch
        classified = await classify_batch(proc_snaps, net_snaps)

        # 3. Persist to DB and push to WebSocket
        from database.connection import get_db_session
        from database.repositories import process_repo, network_repo, threat_repo
        from response_engine.rule_evaluator import evaluate_and_respond

        async with get_db_session() as db:
            # Persist process snapshots
            proc_ids = []
            for snap in proc_snaps:
                clean = {k: v for k, v in snap.items()
                         if k not in ("conn_count", "parent_chain")}
                rec = await process_repo.insert_process_snapshot(db, clean)
                proc_ids.append(rec["id"])

            # Persist network connections
            net_ids = []
            for conn in net_snaps:
                rec = await network_repo.insert_connection(db, conn)
                net_ids.append(rec["id"])

            # Persist threat events
            for event in classified:
                if event["threat_level"] == "Normal":
                    continue  # Don't persist normal events to reduce DB noise
                threat_rec = await threat_repo.insert_threat_event(db, event)

                # Auto-response evaluation
                asyncio.create_task(
                    evaluate_and_respond(threat_rec),
                    name=f"respond_{threat_rec['id']}",
                )

                # Push to WebSocket clients
                _push_to_ws({
                    "type": "threat",
                    "data": {**threat_rec,
                             "detected_at": threat_rec["detected_at"].isoformat()
                             if isinstance(threat_rec.get("detected_at"), datetime) else None},
                })

        elapsed_ms = round((time.monotonic() - start) * 1000, 1)
        logger.debug("monitoring_cycle_complete", elapsed_ms=elapsed_ms,
                     processes=len(proc_snaps), threats=len(classified))

        if elapsed_ms > 500:
            logger.warning("monitoring_cycle_slow", elapsed_ms=elapsed_ms,
                           note="Exceeds 500ms target")

    except Exception as exc:
        logger.error("monitoring_cycle_error", error=str(exc), exc_info=True)


async def _etw_event_consumer() -> None:
    """
    Drain the ETW event queue and log/handle short-lived process events
    that psutil would have missed.
    """
    while True:
        try:
            event = await asyncio.wait_for(_event_queue.get(), timeout=1.0)
            if event.get("event_type") == "ProcessStart":
                logger.info(
                    "etw_process_start",
                    pid=event.get("pid"),
                    name=event.get("name"),
                    parent_pid=event.get("parent_pid"),
                )
                # Push to WebSocket as a lightweight process event
                _push_to_ws({"type": "process", "data": event})
            _event_queue.task_done()
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.debug("etw_consumer_error", error=str(exc))


def _push_to_ws(event: dict) -> None:
    """Non-blocking push to the WebSocket broadcast queue."""
    if _ws_queue is not None:
        try:
            _ws_queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.debug("ws_queue_full", dropped_event_type=event.get("type"))
