"""
database/repositories/network_repo.py
======================================
Data access for network_connections table.
"""
from __future__ import annotations

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import NetworkConnection


async def insert_connection(db: AsyncSession, data: dict) -> dict:
    conn = NetworkConnection(**data)
    db.add(conn)
    await db.flush()
    await db.refresh(conn)
    return _to_dict(conn)


async def get_connections(
    db: AsyncSession, page: int = 1, limit: int = 50
) -> tuple[int, list[dict]]:
    count = (await db.execute(select(func.count()).select_from(NetworkConnection))).scalar_one()
    result = await db.execute(
        select(NetworkConnection)
        .order_by(desc(NetworkConnection.captured_at))
        .offset((page - 1) * limit)
        .limit(limit)
    )
    return count, [_to_dict(r) for r in result.scalars().all()]


async def get_suspicious_connections(
    db: AsyncSession, page: int = 1, limit: int = 50
) -> tuple[int, list[dict]]:
    q = select(NetworkConnection).where(NetworkConnection.is_suspicious == True)
    count = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    result = await db.execute(
        q.order_by(desc(NetworkConnection.captured_at))
        .offset((page - 1) * limit)
        .limit(limit)
    )
    return count, [_to_dict(r) for r in result.scalars().all()]


async def mark_suspicious(db: AsyncSession, connection_id, intel_score: float) -> None:
    from sqlalchemy import update
    await db.execute(
        update(NetworkConnection)
        .where(NetworkConnection.id == connection_id)
        .values(is_suspicious=True, intel_score=intel_score)
    )


def _to_dict(c: NetworkConnection | None) -> dict | None:
    if c is None:
        return None
    return {col.key: getattr(c, col.key) for col in c.__table__.columns}
