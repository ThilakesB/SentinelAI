"""
backend/routers/processes.py
==============================
Process monitoring API domain endpoints.

GET /api/processes              Paginated process list
GET /api/processes/{pid}        Latest snapshot for a single PID
GET /api/processes/{pid}/history  Historical snapshots for a PID
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status

from backend.dependencies import AuthUser, DBSession
from backend.schemas.process import ProcessListResponse, ProcessSnapshot, ProcessHistoryResponse

router = APIRouter()


@router.get("", response_model=ProcessListResponse, summary="List all running processes")
async def list_processes(
    current_user: AuthUser,
    db: DBSession,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    sort_by: str = Query("captured_at", pattern="^(cpu_percent|ram_mb|name|captured_at|pid)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> ProcessListResponse:
    from database.repositories.process_repo import get_latest_snapshots
    total, items = await get_latest_snapshots(db, page=page, limit=limit, sort_by=sort_by, order=order)
    return ProcessListResponse(total=total, page=page, limit=limit, items=items)


@router.get("/{pid}", response_model=ProcessSnapshot, summary="Get latest snapshot for a PID")
async def get_process(pid: int, current_user: AuthUser, db: DBSession) -> ProcessSnapshot:
    from database.repositories.process_repo import get_process_by_pid
    snap = await get_process_by_pid(db, pid)
    if not snap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"PID {pid} not found")
    return ProcessSnapshot(**snap)


@router.get("/{pid}/history", response_model=ProcessHistoryResponse, summary="Historical snapshots for a PID")
async def get_process_history(
    pid: int,
    current_user: AuthUser,
    db: DBSession,
    from_ts: Optional[datetime] = Query(None),
    to_ts: Optional[datetime] = Query(None),
) -> ProcessHistoryResponse:
    from database.repositories.process_repo import get_process_history
    snapshots = await get_process_history(db, pid=pid, from_ts=from_ts, to_ts=to_ts)
    return ProcessHistoryResponse(pid=pid, snapshots=snapshots)
