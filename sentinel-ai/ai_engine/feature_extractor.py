"""
ai_engine/feature_extractor.py
================================
Converts raw process + network snapshot dicts into a fixed 18-feature
vector for Isolation Forest inference.

Feature vector (index → name):
  0  cpu_percent           (MinMax 0–100, normalized to 0–1)
  1  ram_mb                (log1p scaled)
  2  disk_read_rate        (log1p scaled MB/s)
  3  disk_write_rate       (log1p scaled MB/s)
  4  net_sent_rate         (log1p scaled MB/s)
  5  net_recv_rate         (log1p scaled MB/s)
  6  connection_count      (MinMax, cap 200)
  7  unique_remote_ips     (MinMax, cap 50)
  8  high_port_ratio       (0–1 fraction of connections > port 1024)
  9  process_age_sec       (log1p scaled)
  10 is_signed             (binary 0/1, 0.5 if unknown)
  11 hash_is_malicious     (binary 0/1)
  12 max_dst_abuse_score   (0–100 normalized to 0–1)
  13 has_suspicious_parent (binary 0/1)
  14 cpu_deviation_zscore  (capped ±10)
  15 ram_deviation_zscore  (capped ±10)
  16 net_sent_deviation    (capped ±10)
  17 listening_port_count  (MinMax, cap 50)
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

import numpy as np

FEATURE_NAMES = [
    "cpu_percent",
    "ram_mb",
    "disk_read_rate",
    "disk_write_rate",
    "net_sent_rate",
    "net_recv_rate",
    "connection_count",
    "unique_remote_ips",
    "high_port_ratio",
    "process_age_sec",
    "is_signed",
    "hash_is_malicious",
    "max_dst_abuse_score",
    "has_suspicious_parent",
    "cpu_deviation_zscore",
    "ram_deviation_zscore",
    "net_sent_deviation",
    "listening_port_count",
]

N_FEATURES = len(FEATURE_NAMES)  # 18


def extract_features(
    process_snap: dict[str, Any],
    net_connections: list[dict[str, Any]],
    enrichment: dict[str, Any] | None,
    deviations: dict[str, float] | None,
) -> np.ndarray:
    """
    Build the 18-feature vector from raw monitoring data + enrichment.

    Args:
        process_snap:   Dict from process_monitor.collect_process_snapshot()
        net_connections: Network connections for this PID
        enrichment:     Output of threat_intel.enricher.enrich_process()
        deviations:     Output of resource_baseline.get_deviations()

    Returns:
        np.ndarray of shape (18,), dtype float32
    """
    pid_conns = [c for c in net_connections if c.get("pid") == process_snap.get("pid")]
    enrichment = enrichment or {}
    deviations = deviations or {}

    # ── Basic metrics ──────────────────────────────────────────────────────────
    cpu = float(process_snap.get("cpu_percent") or 0.0)
    ram = float(process_snap.get("ram_mb") or 0.0)
    disk_read = float(process_snap.get("disk_read_mb") or 0.0)
    disk_write = float(process_snap.get("disk_write_mb") or 0.0)
    net_sent = float(process_snap.get("net_sent_mb") or 0.0)
    net_recv = float(process_snap.get("net_recv_mb") or 0.0)

    # ── Connection-level features ──────────────────────────────────────────────
    conn_count = len(pid_conns)
    remote_ips = {c.get("dst_ip") for c in pid_conns if c.get("dst_ip")}
    unique_ips = len(remote_ips)

    high_port_count = sum(
        1 for c in pid_conns
        if (c.get("dst_port") or 0) > 1024 and (c.get("dst_port") or 0) != 443
    )
    high_port_ratio = high_port_count / max(conn_count, 1)

    listening_count = sum(
        1 for c in pid_conns if c.get("status") in ("LISTEN", "LISTENING")
    )

    # ── Temporal ──────────────────────────────────────────────────────────────
    start_time = process_snap.get("start_time")
    if isinstance(start_time, datetime):
        age_sec = max(0.0, (datetime.now(timezone.utc) - start_time).total_seconds())
    else:
        age_sec = 0.0

    # ── Signing ───────────────────────────────────────────────────────────────
    is_signed_raw = process_snap.get("is_signed")
    if is_signed_raw is True:
        is_signed = 1.0
    elif is_signed_raw is False:
        is_signed = 0.0
    else:
        is_signed = 0.5  # Unknown — neutral

    # ── Threat intel ──────────────────────────────────────────────────────────
    hash_malicious = 1.0 if enrichment.get("hash_is_malicious") or enrichment.get("yara_hit") else 0.0

    # Max abuse score across all remote IPs for this process
    max_abuse = max(
        (c.get("intel_score") or 0.0 for c in pid_conns),
        default=0.0,
    )

    # Suspicious parent (e.g., cmd.exe spawned by browser)
    parent_chain = process_snap.get("parent_chain", [])
    suspicious_parents = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
    has_suspicious_parent = 1.0 if any(
        p.get("name", "").lower() in suspicious_parents for p in parent_chain
    ) else 0.0

    # ── Baseline deviations ───────────────────────────────────────────────────
    cpu_dev = _cap_zscore(deviations.get("cpu_deviation", 0.0))
    ram_dev = _cap_zscore(deviations.get("ram_deviation", 0.0))
    net_dev = _cap_zscore(deviations.get("net_sent_deviation", 0.0))

    # ── Assemble & normalize ──────────────────────────────────────────────────
    vector = np.array([
        cpu / 100.0,                          # 0
        math.log1p(ram) / 10.0,              # 1
        math.log1p(disk_read) / 5.0,         # 2
        math.log1p(disk_write) / 5.0,        # 3
        math.log1p(net_sent) / 5.0,          # 4
        math.log1p(net_recv) / 5.0,          # 5
        min(conn_count, 200) / 200.0,        # 6
        min(unique_ips, 50) / 50.0,          # 7
        high_port_ratio,                      # 8
        math.log1p(age_sec) / 15.0,          # 9
        is_signed,                            # 10
        hash_malicious,                       # 11
        max_abuse / 100.0,                    # 12
        has_suspicious_parent,                # 13
        cpu_dev / 10.0,                       # 14 (capped ±10, normalized to ±1)
        ram_dev / 10.0,                       # 15
        net_dev / 10.0,                       # 16
        min(listening_count, 50) / 50.0,     # 17
    ], dtype=np.float32)

    return vector


def _cap_zscore(z: float, cap: float = 10.0) -> float:
    return max(-cap, min(cap, z))


def features_to_dict(vector: np.ndarray) -> dict[str, float]:
    """Convert a feature vector back to a named dict for storage/display."""
    return {name: round(float(v), 6) for name, v in zip(FEATURE_NAMES, vector)}
