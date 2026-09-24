"""
monitoring/etw_monitor.py
=========================
Event Tracing for Windows (ETW) consumer for kernel-level process events.

Uses pywintrace (FireEye) to subscribe to the Microsoft-Windows-Kernel-Process
provider. This catches short-lived processes that psutil polling misses.

Events emitted:
  - ProcessStart: new process created
  - ProcessStop: process terminated

Events are placed into the shared asyncio event queue for the collector
to pick up alongside psutil snapshots.

IMPORTANT:
  - Requires Administrator privileges to start an ETW session.
  - Runs in a background daemon thread (ETW callback is synchronous).
  - pywintrace: https://github.com/fireeye/pywintrace

If pywintrace is not available or ETW session fails, this module
degrades gracefully — psutil polling continues without ETW augmentation.
"""
from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ETW Provider GUID for kernel process events
_KERNEL_PROCESS_PROVIDER = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"

_etw_thread: threading.Thread | None = None
_stop_event = threading.Event()
_event_queue: asyncio.Queue | None = None


def start_etw_monitor(queue: asyncio.Queue) -> bool:
    """
    Start the ETW monitor in a background daemon thread.
    Returns True if started successfully, False if pywintrace unavailable.
    """
    global _etw_thread, _event_queue
    _event_queue = queue

    try:
        import etw  # pywintrace
    except ImportError:
        logger.warning(
            "etw_unavailable",
            note="pywintrace not installed or not importable. ETW monitoring disabled. "
                 "Install with: pip install pywintrace",
        )
        return False

    _stop_event.clear()
    _etw_thread = threading.Thread(
        target=_etw_consumer_thread,
        args=(queue,),
        daemon=True,
        name="etw_kernel_process",
    )
    _etw_thread.start()
    logger.info("etw_monitor_started", provider=_KERNEL_PROCESS_PROVIDER)
    return True


def stop_etw_monitor() -> None:
    """Signal the ETW consumer thread to stop."""
    _stop_event.set()
    if _etw_thread and _etw_thread.is_alive():
        _etw_thread.join(timeout=5)
    logger.info("etw_monitor_stopped")


def _etw_consumer_thread(queue: asyncio.Queue) -> None:
    """
    Runs in a daemon thread. Subscribes to kernel process events via ETW
    and pushes structured dicts into the asyncio queue.
    """
    try:
        import etw
        import etw.evntrace as evntrace

        def on_event(event_tuple: tuple) -> None:
            try:
                event_id, props = event_tuple[0], event_tuple[1]

                if event_id not in (1, 2):  # 1=ProcessStart, 2=ProcessStop
                    return

                event_type = "ProcessStart" if event_id == 1 else "ProcessStop"
                data: dict[str, Any] = {
                    "source": "etw",
                    "event_type": event_type,
                    "pid": props.get("ProcessID"),
                    "parent_pid": props.get("ParentProcessID"),
                    "name": props.get("ImageFileName", ""),
                    "exe_path": props.get("FullProcessImageName", ""),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

                # Thread-safe queue put (from non-async context)
                try:
                    loop = asyncio.get_event_loop()
                    loop.call_soon_threadsafe(queue.put_nowait, data)
                except RuntimeError:
                    pass  # Loop closed — agent is shutting down

            except Exception as exc:
                logger.debug("etw_event_parse_error", error=str(exc))

        session = etw.ETW(
            providers=[
                etw.ProviderInfo(
                    "Microsoft-Windows-Kernel-Process",
                    etw.GUID(_KERNEL_PROCESS_PROVIDER),
                )
            ],
            event_callback=on_event,
            session_name="SentinelAI_KernelProcess",
        )

        with session:
            while not _stop_event.is_set():
                _stop_event.wait(timeout=0.5)

    except Exception as exc:
        logger.error("etw_consumer_failed", error=str(exc), note="ETW monitoring disabled for this session")
