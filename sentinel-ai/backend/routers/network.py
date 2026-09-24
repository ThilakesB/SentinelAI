"""
backend/routers/network.py
============================
Network monitoring API domain endpoints.

GET /api/network/connections    Paginated connection table with intel scores
GET /api/network/baseline       Per-process network baseline thresholds
GET /api/network/suspicious     Connections flagged as suspicious
"""
from __future__ import annotations

from fastapi import APIRouter, Query

from backend.dependencies import AuthUser, DBSession
from backend.schemas.network import (
    NetworkConnectionListResponse,
    SuspiciousNetworkResponse,
)

router = APIRouter()


@router.get("/connections", response_model=NetworkConnectionListResponse,
            summary="Current network connection table")
async def list_connections(
    current_user: AuthUser,
    db: DBSession,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
) -> NetworkConnectionListResponse:
    from database.repositories.network_repo import get_connections
    total, items = await get_connections(db, page=page, limit=limit)
    return NetworkConnectionListResponse(total=total, page=page, limit=limit, items=items)


@router.get("/baseline", summary="Per-process network baseline thresholds")
async def get_baseline(current_user: AuthUser) -> dict:
    """
    Returns the current rolling baseline for all tracked processes.
    Used by clients to understand 'normal' thresholds.
    """
    from monitoring.resource_baseline import baseline
    return {"baselines": baseline.get_summary()}


@router.get("/suspicious", response_model=SuspiciousNetworkResponse,
            summary="Connections flagged as suspicious")
async def get_suspicious_connections(
    current_user: AuthUser,
    db: DBSession,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
) -> SuspiciousNetworkResponse:
    from database.repositories.network_repo import get_suspicious_connections
    total, items = await get_suspicious_connections(db, page=page, limit=limit)
    return SuspiciousNetworkResponse(total=total, items=items)
