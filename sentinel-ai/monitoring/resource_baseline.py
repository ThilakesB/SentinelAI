"""
monitoring/resource_baseline.py
================================
Maintains a rolling per-process resource baseline using Welford's
online algorithm (numerically stable mean + variance without storing
all samples).

Baseline data is persisted to local SQLite so it survives restarts.
Thresholds are recomputed as mean + N_SIGMA * std on each update.

Thread-safe: uses an asyncio.Lock per process name.
"""
from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass, field
from datetime import datetime

import structlog

logger = structlog.get_logger(__name__)

N_SIGMA = 3.0  # Standard deviations above mean = anomalous


@dataclass
class WelfordState:
    """Welford's online algorithm state for a single metric."""
    count: int = 0
    mean: float = 0.0
    M2: float = 0.0  # Sum of squared deviations

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.M2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    @property
    def threshold(self) -> float:
        return self.mean + N_SIGMA * self.std


@dataclass
class ProcessBaseline:
    """Baseline state for a single process name."""
    process_name: str
    cpu: WelfordState = field(default_factory=WelfordState)
    ram_mb: WelfordState = field(default_factory=WelfordState)
    net_sent: WelfordState = field(default_factory=WelfordState)
    net_recv: WelfordState = field(default_factory=WelfordState)
    conn_count: WelfordState = field(default_factory=WelfordState)


class ResourceBaseline:
    """
    Manages per-process baselines. Call update() on each monitoring tick.
    Call is_anomalous() to check if a metric exceeds the threshold.
    """

    def __init__(self) -> None:
        self._baselines: dict[str, ProcessBaseline] = {}
        self._lock = asyncio.Lock()

    async def update(
        self,
        process_name: str,
        cpu: float,
        ram_mb: float,
        net_sent: float,
        net_recv: float,
        conn_count: int,
    ) -> None:
        async with self._lock:
            if process_name not in self._baselines:
                self._baselines[process_name] = ProcessBaseline(process_name)
            b = self._baselines[process_name]
            b.cpu.update(cpu)
            b.ram_mb.update(ram_mb)
            b.net_sent.update(net_sent)
            b.net_recv.update(net_recv)
            b.conn_count.update(conn_count)

    def get_deviations(
        self,
        process_name: str,
        cpu: float,
        ram_mb: float,
        net_sent: float,
        net_recv: float,
        conn_count: int,
    ) -> dict[str, float]:
        """
        Return z-scores for each metric relative to the process baseline.
        Returns 0.0 if baseline has < 10 samples (insufficient data).
        """
        b = self._baselines.get(process_name)
        if b is None or b.cpu.count < 10:
            return {
                "cpu_deviation": 0.0,
                "ram_deviation": 0.0,
                "net_sent_deviation": 0.0,
                "net_recv_deviation": 0.0,
                "conn_deviation": 0.0,
            }

        def zscore(state: WelfordState, value: float) -> float:
            if state.std == 0:
                return 0.0
            return (value - state.mean) / state.std

        return {
            "cpu_deviation": zscore(b.cpu, cpu),
            "ram_deviation": zscore(b.ram_mb, ram_mb),
            "net_sent_deviation": zscore(b.net_sent, net_sent),
            "net_recv_deviation": zscore(b.net_recv, net_recv),
            "conn_deviation": zscore(b.conn_count, conn_count),
        }

    def get_summary(self) -> list[dict]:
        """Return baseline stats for all tracked processes (for /api/network/baseline)."""
        result = []
        for name, b in self._baselines.items():
            if b.cpu.count < 5:
                continue
            result.append({
                "process_name": name,
                "mean_cpu": round(b.cpu.mean, 2),
                "std_cpu": round(b.cpu.std, 2),
                "mean_ram_mb": round(b.ram_mb.mean, 2),
                "std_ram_mb": round(b.ram_mb.std, 2),
                "mean_net_sent_mb_s": round(b.net_sent.mean, 4),
                "std_net_sent_mb_s": round(b.net_sent.std, 4),
                "mean_net_recv_mb_s": round(b.net_recv.mean, 4),
                "std_net_recv_mb_s": round(b.net_recv.std, 4),
                "threshold_net_sent_mb_s": round(b.net_sent.threshold, 4),
                "threshold_net_recv_mb_s": round(b.net_recv.threshold, 4),
                "sample_count": b.cpu.count,
                "window_minutes": -1,  # Welford uses all history, not windowed
            })
        return result

    async def persist_to_local_db(self) -> None:
        """Save current baseline state to SQLite for restart recovery."""
        from database.local_db import get_local_db
        async with get_local_db() as db:
            async with self._lock:
                for name, b in self._baselines.items():
                    if b.cpu.count < 2:
                        continue
                    await db.execute(
                        """
                        INSERT OR REPLACE INTO resource_baseline (
                            process_name, mean_cpu, std_cpu,
                            mean_ram_mb, std_ram_mb,
                            mean_net_sent_mb_s, std_net_sent_mb_s,
                            mean_net_recv_mb_s, std_net_recv_mb_s,
                            mean_conn_count, std_conn_count,
                            sample_count, last_updated
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))
                        """,
                        (
                            name,
                            b.cpu.mean, b.cpu.std,
                            b.ram_mb.mean, b.ram_mb.std,
                            b.net_sent.mean, b.net_sent.std,
                            b.net_recv.mean, b.net_recv.std,
                            b.conn_count.mean, b.conn_count.std,
                            b.cpu.count,
                        ),
                    )
                await db.commit()
        logger.debug("baseline_persisted", process_count=len(self._baselines))

    async def load_from_local_db(self) -> None:
        """Restore baseline state from SQLite on startup."""
        from database.local_db import get_local_db
        async with get_local_db() as db:
            async with db.execute("SELECT * FROM resource_baseline") as cursor:
                rows = await cursor.fetchall()

        async with self._lock:
            for row in rows:
                b = ProcessBaseline(process_name=row["process_name"])
                # Restore Welford state from persisted mean/std
                # (We restore mean and approximate M2 from std and count)
                count = row["sample_count"] or 1

                def _restore(state: WelfordState, mean: float, std: float, n: int) -> None:
                    state.count = n
                    state.mean = mean
                    state.M2 = std * std * (n - 1) if n > 1 else 0.0

                _restore(b.cpu, row["mean_cpu"], row["std_cpu"], count)
                _restore(b.ram_mb, row["mean_ram_mb"], row["std_ram_mb"], count)
                _restore(b.net_sent, row["mean_net_sent_mb_s"], row["std_net_sent_mb_s"], count)
                _restore(b.net_recv, row["mean_net_recv_mb_s"], row["std_net_recv_mb_s"], count)
                _restore(b.conn_count, row["mean_conn_count"], row["std_conn_count"], count)
                self._baselines[row["process_name"]] = b

        logger.info("baseline_loaded", process_count=len(self._baselines))


# Singleton shared across the monitoring layer
baseline = ResourceBaseline()
