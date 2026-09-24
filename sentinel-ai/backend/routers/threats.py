"""
backend/routers/threats.py
============================
Threat detection API domain.

GET  /api/threats           Paginated threat events with filters
GET  /api/threats/{id}      Single threat with feature explanation
POST /api/threats/rescan    Trigger an immediate monitoring + classification cycle
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from backend.dependencies import AnalystUser, AuthUser, DBSession
from backend.schemas.threat import RescanRequest, RescanResponse, ThreatEvent, ThreatListResponse

router = APIRouter()


@router.get("", response_model=ThreatListResponse, summary="List threat events")
async def list_threats(
    current_user: AuthUser,
    db: DBSession,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    level: Optional[str] = Query(None, pattern="^(Normal|Suspicious|Critical)$"),
    from_ts: Optional[datetime] = Query(None),
    to_ts: Optional[datetime] = Query(None),
    resolved: Optional[bool] = Query(None),
) -> ThreatListResponse:
    from database.repositories.threat_repo import get_threats
    total, items = await get_threats(
        db, page=page, limit=limit,
        level=level, from_ts=from_ts, to_ts=to_ts, resolved=resolved,
    )
    return ThreatListResponse(total=total, page=page, limit=limit, items=items)


@router.get("/{threat_id}", response_model=ThreatEvent, summary="Get a single threat event")
async def get_threat(
    threat_id: UUID,
    current_user: AuthUser,
    db: DBSession,
) -> ThreatEvent:
    from database.repositories.threat_repo import get_threat_by_id
    event = await get_threat_by_id(db, threat_id)
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat event not found")
    return ThreatEvent(**event)


@router.post("/rescan", response_model=RescanResponse, summary="Trigger immediate rescan")
async def rescan(
    req: RescanRequest,
    current_user: AnalystUser,
) -> RescanResponse:
    """
    Triggers a fresh monitoring + classification cycle immediately.
    If req.pid is specified, only that PID is rescanned.
    """
    from monitoring.process_monitor import collect_process_snapshot
    from monitoring.network_monitor import collect_network_snapshot
    from ai_engine.isolation_forest import classify_batch
    import asyncio

    proc_snaps, net_snaps = await asyncio.gather(
        collect_process_snapshot(),
        collect_network_snapshot(),
    )

    if req.pid:
        proc_snaps = [s for s in proc_snaps if s.get("pid") == req.pid]

    classified = await classify_batch(proc_snaps, net_snaps)
    return RescanResponse(
        message="Rescan complete.",
        events_generated=len(classified),
    )
