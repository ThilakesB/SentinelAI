"""
database/repositories/threat_repo.py
======================================
Data access for threat_events table.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import ThreatEvent


async def insert_threat_event(db: AsyncSession, data: dict) -> dict:
    event = ThreatEvent(**data)
    db.add(event)
    await db.flush()
    await db.refresh(event)
    return _to_dict(event)


async def get_threats(
    db: AsyncSession,
    page: int = 1,
    limit: int = 50,
    level: str | None = None,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    resolved: bool | None = None,
) -> tuple[int, list[dict]]:
    q = select(ThreatEvent)
    if level:
        q = q.where(ThreatEvent.threat_level == level)
    if from_ts:
        q = q.where(ThreatEvent.detected_at >= from_ts)
    if to_ts:
        q = q.where(ThreatEvent.detected_at <= to_ts)
    if resolved is not None:
        q = q.where(ThreatEvent.is_resolved == resolved)

    count = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    result = await db.execute(
        q.order_by(desc(ThreatEvent.detected_at))
        .offset((page - 1) * limit)
        .limit(limit)
    )
    return count, [_to_dict(r) for r in result.scalars().all()]


async def get_threat_by_id(db: AsyncSession, threat_id: UUID) -> dict | None:
    result = await db.execute(select(ThreatEvent).where(ThreatEvent.id == threat_id))
    event = result.scalar_one_or_none()
    return _to_dict(event) if event else None


async def resolve_threat(db: AsyncSession, threat_id: UUID, notes: str | None = None) -> None:
    await db.execute(
        update(ThreatEvent)
        .where(ThreatEvent.id == threat_id)
        .values(is_resolved=True, resolved_at=func.now(), notes=notes)
    )


async def get_threat_counts_by_level(db: AsyncSession) -> dict[str, int]:
    result = await db.execute(
        select(ThreatEvent.threat_level, func.count().label("cnt"))
        .where(ThreatEvent.is_resolved == False)
        .group_by(ThreatEvent.threat_level)
    )
    counts = {"Normal": 0, "Suspicious": 0, "Critical": 0}
    for row in result.all():
        counts[row.threat_level] = row.cnt
    return counts


async def get_recent_critical_threats(db: AsyncSession, limit: int = 5) -> list[dict]:
    result = await db.execute(
        select(ThreatEvent)
        .where(ThreatEvent.threat_level == "Critical", ThreatEvent.is_resolved == False)
        .order_by(desc(ThreatEvent.detected_at))
        .limit(limit)
    )
    return [_to_dict(r) for r in result.scalars().all()]


def _to_dict(e: ThreatEvent | None) -> dict | None:
    if e is None:
        return None
    return {col.key: getattr(e, col.key) for col in e.__table__.columns}
