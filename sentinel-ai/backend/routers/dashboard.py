"""
backend/routers/dashboard.py
==============================
GET /api/dashboard — aggregated system-wide summary for the dashboard domain.
No UI dependency: returns a machine-readable JSON snapshot of current state.
"""
from __future__ import annotations

from fastapi import APIRouter

from backend.dependencies import AuthUser, DBSession

router = APIRouter()


@router.get("", summary="Real-time dashboard summary")
async def get_dashboard(current_user: AuthUser, db: DBSession) -> dict:
    """
    Returns an aggregated snapshot:
      - Threat counts by level (Normal / Suspicious / Critical)
      - 5 most recent unresolved Critical threats
      - Current process count
      - Top 5 suspicious remote IPs
      - ML model version in use
    """
    from database.repositories.threat_repo import (
        get_threat_counts_by_level,
        get_recent_critical_threats,
    )
    from database.repositories.process_repo import get_latest_snapshots
    from database.repositories.network_repo import get_suspicious_connections
    from ai_engine.model_store import get_model_version
    import psutil

    counts, critical, (proc_total, _), (_, suspicious_conns) = (
        await get_threat_counts_by_level(db),
        await get_recent_critical_threats(db, limit=5),
        await get_latest_snapshots(db, page=1, limit=1),
        await get_suspicious_connections(db, page=1, limit=5),
    )

    # System resource snapshot (live, from psutil — not persisted)
    cpu_usage = psutil.cpu_percent(interval=0)
    ram = psutil.virtual_memory()

    return {
        "threat_counts": counts,
        "recent_critical": [
            {
                "id": str(e["id"]),
                "detected_at": e["detected_at"].isoformat() if e.get("detected_at") else None,
                "threat_level": e["threat_level"],
                "trigger_type": e.get("trigger_type"),
                "ml_model_version": e.get("ml_model_version"),
            }
            for e in critical
        ],
        "process_count": proc_total,
        "suspicious_connections": len(suspicious_conns),
        "system_snapshot": {
            "cpu_percent": cpu_usage,
            "ram_total_mb": round(ram.total / 1_048_576, 1),
            "ram_used_mb": round(ram.used / 1_048_576, 1),
            "ram_percent": ram.percent,
        },
        "ml_model_version": get_model_version(),
    }
