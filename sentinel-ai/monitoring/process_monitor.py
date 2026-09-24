"""
monitoring/process_monitor.py
==============================
Collects real-time process snapshots using psutil + WMI enrichment.

Polling interval: configured via settings.monitoring_interval_sec (default: 5s)

Per-cycle actions:
  1. psutil.process_iter() → resource metrics for every running process
  2. For NEW PIDs (not seen before): SHA-256 exe hash + Authenticode check
  3. Persist snapshots to DB
  4. Update resource baseline
  5. Enqueue snapshot data for AI engine classification

Runs in a thread pool executor to avoid blocking the asyncio event loop.
Requires: psutil, pywin32, wmi
Privilege: Standard user for most fields; Admin for full connection table.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil
import structlog

from backend.config import get_settings
from monitoring.resource_baseline import baseline
from monitoring.wmi_helper import get_authenticode_status, get_parent_chain

logger = structlog.get_logger(__name__)
settings = get_settings()

# PIDs seen in previous cycle (for detecting new processes)
_seen_pids: set[int] = set()
# Cached exe hash to avoid re-hashing on every cycle
_exe_hash_cache: dict[str, str] = {}  # exe_path → sha256
# Thread pool for blocking WMI/hash operations
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="proc_monitor")

# Process fields that psutil.process_iter should collect
_PSUTIL_ATTRS = [
    "pid", "name", "exe", "status",
    "cpu_percent", "memory_info",
    "io_counters", "net_connections",
    "create_time", "ppid",
]


async def collect_process_snapshot() -> list[dict]:
    """
    Collect one snapshot of all running processes.
    Returns a list of process dicts ready for DB insertion + AI classification.
    Target: < 400ms per call on a typical Windows host with ~200 processes.
    """
    loop = asyncio.get_event_loop()
    start = time.monotonic()

    # Run psutil iteration in thread pool (it's I/O bound)
    snapshots = await loop.run_in_executor(_executor, _collect_psutil_snapshots)

    # Enrich new PIDs with WMI data (exe hash + signing) — also in thread pool
    new_pids = {s["pid"] for s in snapshots} - _seen_pids
    if new_pids:
        new_snap_map = {s["pid"]: s for s in snapshots if s["pid"] in new_pids}
        enriched = await loop.run_in_executor(
            _executor, _enrich_new_processes, new_snap_map
        )
        # Merge enrichment back
        for snap in snapshots:
            if snap["pid"] in enriched:
                snap.update(enriched[snap["pid"]])

    # Update seen PIDs
    _seen_pids.clear()
    _seen_pids.update(s["pid"] for s in snapshots)

    # Update resource baseline (async)
    for snap in snapshots:
        await baseline.update(
            process_name=snap["name"],
            cpu=snap.get("cpu_percent", 0.0),
            ram_mb=snap.get("ram_mb", 0.0),
            net_sent=snap.get("net_sent_mb", 0.0),
            net_recv=snap.get("net_recv_mb", 0.0),
            conn_count=snap.get("conn_count", 0),
        )

    elapsed_ms = round((time.monotonic() - start) * 1000, 1)
    logger.debug("process_snapshot_collected", count=len(snapshots), elapsed_ms=elapsed_ms)
    return snapshots


def _collect_psutil_snapshots() -> list[dict]:
    """Synchronous psutil collection — runs in thread pool."""
    snapshots: list[dict] = []

    for proc in psutil.process_iter(attrs=_PSUTIL_ATTRS, ad_value=None):
        try:
            info = proc.info
            if info["pid"] is None:
                continue

            mem = info.get("memory_info")
            io = info.get("io_counters")

            snap: dict[str, Any] = {
                "pid": info["pid"],
                "name": info.get("name") or "unknown",
                "exe_path": info.get("exe"),
                "status": info.get("status"),
                "cpu_percent": info.get("cpu_percent") or 0.0,
                "ram_mb": round(mem.rss / 1_048_576, 2) if mem else 0.0,
                "disk_read_mb": round(io.read_bytes / 1_048_576, 2) if io else 0.0,
                "disk_write_mb": round(io.write_bytes / 1_048_576, 2) if io else 0.0,
                "net_sent_mb": 0.0,   # Filled from network monitor
                "net_recv_mb": 0.0,
                "start_time": datetime.fromtimestamp(info["create_time"], tz=timezone.utc)
                    if info.get("create_time") else None,
                "parent_pid": info.get("ppid"),
                "conn_count": len(info.get("net_connections") or []),
                # Enrichment fields (filled below for new PIDs)
                "exe_hash": None,
                "is_signed": None,
                "signer_name": None,
                "captured_at": datetime.now(timezone.utc),
            }
            snapshots.append(snap)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return snapshots


def _enrich_new_processes(snap_map: dict[int, dict]) -> dict[int, dict]:
    """
    Synchronous WMI/hash enrichment for newly seen PIDs.
    Called in thread pool. Returns {pid: enrichment_dict}.
    """
    enriched: dict[int, dict] = {}

    for pid, snap in snap_map.items():
        exe_path = snap.get("exe_path")
        result: dict[str, Any] = {}

        # SHA-256 hash
        if exe_path:
            if exe_path in _exe_hash_cache:
                result["exe_hash"] = _exe_hash_cache[exe_path]
            else:
                sha256 = _hash_file(exe_path)
                if sha256:
                    _exe_hash_cache[exe_path] = sha256
                    result["exe_hash"] = sha256

        # Authenticode signing
        if exe_path:
            is_signed, signer_name = get_authenticode_status(exe_path)
            result["is_signed"] = is_signed
            result["signer_name"] = signer_name

        # Parent chain (for has_suspicious_parent feature)
        result["parent_chain"] = get_parent_chain(pid)

        enriched[pid] = result

    return enriched


def _hash_file(path: str) -> str | None:
    """SHA-256 hash a file. Returns None on error (locked file, access denied, etc.)."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None
