"""
backend/routers/logs.py
=========================
Logs & reports API domain.

GET /api/logs          Paginated incident history with date/level filters
GET /api/logs/search   Full-text search on action/resource fields
GET /api/logs/export   Bulk CSV or JSON download
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, Query
from fastapi.responses import Response

from backend.dependencies import AuthUser, DBSession

router = APIRouter()


@router.get("", summary="Paginated audit log history")
async def list_logs(
    current_user: AuthUser,
    db: DBSession,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    from_ts: Optional[datetime] = Query(None),
    to_ts: Optional[datetime] = Query(None),
    outcome: Optional[str] = Query(None, pattern="^(success|failed|denied)$"),
) -> dict:
    from database.repositories.log_repo import get_audit_logs
    total, items = await get_audit_logs(
        db, page=page, limit=limit, from_ts=from_ts, to_ts=to_ts, level=outcome
    )
    return {"total": total, "page": page, "limit": limit, "items": items}


@router.get("/search", summary="Full-text search audit logs")
async def search_logs(
    current_user: AuthUser,
    db: DBSession,
    q: str = Query(..., min_length=2),
    from_ts: Optional[datetime] = Query(None),
    to_ts: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
) -> dict:
    from database.repositories.log_repo import search_audit_logs
    total, items = await search_audit_logs(
        db, query=q, from_ts=from_ts, to_ts=to_ts, page=page, limit=limit
    )
    return {"total": total, "page": page, "limit": limit, "items": items}


@router.get("/export", summary="Export audit logs as CSV or JSON")
async def export_logs(
    current_user: AuthUser,
    db: DBSession,
    from_ts: Optional[datetime] = Query(None),
    to_ts: Optional[datetime] = Query(None),
    fmt: Literal["csv", "json"] = Query("json"),
) -> Response:
    from database.repositories.log_repo import export_audit_logs
    data = await export_audit_logs(db, from_ts=from_ts, to_ts=to_ts, fmt=fmt)

    if fmt == "csv":
        return Response(
            content=data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=sentinel_logs.csv"},
        )
    return Response(
        content=data,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=sentinel_logs.json"},
    )
