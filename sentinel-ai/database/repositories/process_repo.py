"""
database/repositories/process_repo.py
======================================
Data access for processes_snapshot table.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import ProcessSnapshot


async def insert_process_snapshot(db: AsyncSession, data: dict) -> dict:
    snap = ProcessSnapshot(**data)
    db.add(snap)
    await db.flush()
    await db.refresh(snap)
    return _to_dict(snap)


async def get_latest_snapshots(
    db: AsyncSession,
    page: int = 1,
    limit: int = 50,
    sort_by: str = "captured_at",
    order: str = "desc",
) -> tuple[int, list[dict]]:
    from sqlalchemy import func

    col = getattr(ProcessSnapshot, sort_by, ProcessSnapshot.captured_at)
    order_fn = desc(col) if order == "desc" else col

    count_q = await db.execute(select(func.count()).select_from(ProcessSnapshot))
    total = count_q.scalar_one()

    result = await db.execute(
        select(ProcessSnapshot)
        .order_by(order_fn)
        .offset((page - 1) * limit)
        .limit(limit)
    )
    return total, [_to_dict(r) for r in result.scalars().all()]


async def get_process_by_pid(db: AsyncSession, pid: int) -> dict | None:
    result = await db.execute(
        select(ProcessSnapshot)
        .where(ProcessSnapshot.pid == pid)
        .order_by(desc(ProcessSnapshot.captured_at))
        .limit(1)
    )
    snap = result.scalar_one_or_none()
    return _to_dict(snap) if snap else None


async def get_process_history(
    db: AsyncSession,
    pid: int,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
) -> list[dict]:
    q = select(ProcessSnapshot).where(ProcessSnapshot.pid == pid)
    if from_ts:
        q = q.where(ProcessSnapshot.captured_at >= from_ts)
    if to_ts:
        q = q.where(ProcessSnapshot.captured_at <= to_ts)
    q = q.order_by(desc(ProcessSnapshot.captured_at))
    result = await db.execute(q)
    return [_to_dict(r) for r in result.scalars().all()]


def _to_dict(snap: ProcessSnapshot | None) -> dict | None:
    if snap is None:
        return None
    return {c.key: getattr(snap, c.key) for c in snap.__table__.columns}
