"""
database/repositories/log_repo.py
===================================
Data access for audit_log table.
Includes: paginated list, full-text search, CSV/JSON export, write_audit_log helper.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Literal

import orjson
from sqlalchemy import desc, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import AuditLog


async def write_audit_log(
    actor: str,
    action: str,
    resource: str | None = None,
    payload: str | None = None,
    ip_address: str | None = None,
    outcome: str = "success",
) -> None:
    """
    Fire-and-forget audit log writer.
    Gets its own DB session to avoid coupling to request session lifecycle.
    """
    try:
        from database.connection import get_db_session
        import orjson

        parsed_payload = None
        if payload:
            try:
                parsed_payload = orjson.loads(payload)
            except Exception:
                parsed_payload = {"raw": payload[:512]}

        async with get_db_session() as db:
            entry = AuditLog(
                actor=actor,
                action=action,
                resource=resource,
                payload=parsed_payload,
                ip_address=ip_address,
                outcome=outcome,
            )
            db.add(entry)
    except Exception:
        pass  # Never let audit write fail a user request


async def get_audit_logs(
    db: AsyncSession,
    page: int = 1,
    limit: int = 50,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    level: str | None = None,
) -> tuple[int, list[dict]]:
    q = select(AuditLog)
    if from_ts:
        q = q.where(AuditLog.logged_at >= from_ts)
    if to_ts:
        q = q.where(AuditLog.logged_at <= to_ts)
    if level:
        q = q.where(AuditLog.outcome == level)

    count = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    result = await db.execute(
        q.order_by(desc(AuditLog.logged_at)).offset((page - 1) * limit).limit(limit)
    )
    return count, [_to_dict(r) for r in result.scalars().all()]


async def search_audit_logs(
    db: AsyncSession,
    query: str,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    page: int = 1,
    limit: int = 50,
) -> tuple[int, list[dict]]:
    """Full-text search using PostgreSQL tsvector index on action + resource columns."""
    base_q = select(AuditLog).where(
        text("search_vector @@ plainto_tsquery('english', :q)")
    ).params(q=query)
    if from_ts:
        base_q = base_q.where(AuditLog.logged_at >= from_ts)
    if to_ts:
        base_q = base_q.where(AuditLog.logged_at <= to_ts)

    count = (await db.execute(select(func.count()).select_from(base_q.subquery()))).scalar_one()
    result = await db.execute(
        base_q.order_by(desc(AuditLog.logged_at)).offset((page - 1) * limit).limit(limit)
    )
    return count, [_to_dict(r) for r in result.scalars().all()]


async def export_audit_logs(
    db: AsyncSession,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    fmt: Literal["csv", "json"] = "json",
) -> bytes:
    """Return all matching logs as CSV or JSON bytes for streaming download."""
    q = select(AuditLog)
    if from_ts:
        q = q.where(AuditLog.logged_at >= from_ts)
    if to_ts:
        q = q.where(AuditLog.logged_at <= to_ts)
    q = q.order_by(desc(AuditLog.logged_at))

    result = await db.execute(q)
    rows = [_to_dict(r) for r in result.scalars().all()]

    if fmt == "json":
        return orjson.dumps(rows)

    # CSV export
    if not rows:
        return b""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    for row in rows:
        writer.writerow({k: str(v) if v is not None else "" for k, v in row.items()})
    return buf.getvalue().encode("utf-8")


def _to_dict(e: AuditLog) -> dict:
    return {col.key: getattr(e, col.key) for col in e.__table__.columns}
