"""
monitoring/network_monitor.py
==============================
Collects network connection data using psutil.net_connections()
and enriches each destination IP against the threat intel cache.

Optionally uses pydivert (WinDivert) for packet-level byte counts
when available and running with admin privileges.

Output: list of connection dicts ready for DB insertion + AI features.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
from datetime import datetime, timezone
from typing import Any

import psutil
import structlog

logger = structlog.get_logger(__name__)

# IP ranges that should never be flagged (RFC 1918 + loopback + link-local)
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return True  # Malformed IP — treat as private (safe default)


async def collect_network_snapshot() -> list[dict]:
    """
    Collect current network connections and enrich external IPs.
    Returns list of connection dicts.
    """
    start = time.monotonic()

    loop = asyncio.get_event_loop()
    raw_conns = await loop.run_in_executor(None, _get_connections_psutil)

    # Enrich external IPs against threat intel cache
    enriched = await _enrich_connections(raw_conns)

    elapsed_ms = round((time.monotonic() - start) * 1000, 1)
    logger.debug("network_snapshot_collected", count=len(enriched), elapsed_ms=elapsed_ms)
    return enriched


def _get_connections_psutil() -> list[dict[str, Any]]:
    """
    Synchronous psutil connection collection.
    Requires admin on Windows for full system-wide connection table.
    Falls back to user-level (own process only) on access denied.
    """
    connections: list[dict[str, Any]] = []

    try:
        conns = psutil.net_connections(kind="all")
    except psutil.AccessDenied:
        logger.warning("network_access_denied", note="Running without admin — only own connections visible")
        conns = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                conns.extend(proc.connections(kind="all"))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

    now = datetime.now(timezone.utc)
    for conn in conns:
        if conn.laddr is None:
            continue
        src_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
        src_port = conn.laddr.port if conn.laddr else None
        dst_ip = conn.raddr.ip if conn.raddr else None
        dst_port = conn.raddr.port if conn.raddr else None

        if dst_ip is None:
            continue  # Skip listening-only sockets with no remote

        connections.append({
            "captured_at": now,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "TCP" if conn.type.name == "SOCK_STREAM" else "UDP",
            "bytes_sent": 0,
            "bytes_recv": 0,
            "packet_count": 0,
            "pid": conn.pid,
            "process_name": _pid_to_name(conn.pid),
            "status": conn.status if hasattr(conn, "status") else None,
            "is_suspicious": False,
            "intel_score": None,
            "threat_event_id": None,
        })

    return connections


def _pid_to_name(pid: int | None) -> str | None:
    if pid is None:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


async def _enrich_connections(conns: list[dict]) -> list[dict]:
    """
    Cross-reference each external destination IP against the local
    threat intel cache. Marks connection as suspicious if score > threshold.
    """
    from backend.config import get_settings
    from threat_intel.enricher import enrich_ip

    cfg = get_settings()

    for conn in conns:
        dst = conn.get("dst_ip", "")
        if not dst or _is_private_ip(dst):
            continue
        try:
            intel = await enrich_ip(dst)
            score = intel.get("abuse_score", 0)
            conn["intel_score"] = score
            if score >= cfg.abuseipdb_confidence_threshold:
                conn["is_suspicious"] = True
        except Exception as exc:
            logger.debug("ip_enrichment_failed", ip=dst, error=str(exc))

    return conns
