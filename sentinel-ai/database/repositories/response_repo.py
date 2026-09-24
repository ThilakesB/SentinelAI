"""
database/repositories/response_repo.py
========================================
Data access for response_actions and response_rules tables.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import ResponseAction, ResponseRule


# ── Response Actions ──────────────────────────────────────────────────────────

async def insert_response_action(db: AsyncSession, data: dict) -> dict:
    action = ResponseAction(**data)
    db.add(action)
    await db.flush()
    await db.refresh(action)
    return _action_to_dict(action)


async def get_actions_for_threat(db: AsyncSession, threat_id: UUID) -> list[dict]:
    result = await db.execute(
        select(ResponseAction)
        .where(ResponseAction.threat_event_id == threat_id)
        .order_by(desc(ResponseAction.executed_at))
    )
    return [_action_to_dict(r) for r in result.scalars().all()]


async def mark_action_rolled_back(db: AsyncSession, action_id: UUID) -> None:
    await db.execute(
        update(ResponseAction)
        .where(ResponseAction.id == action_id)
        .values(rolled_back=True)
    )


# ── Response Rules ────────────────────────────────────────────────────────────

async def list_rules(db: AsyncSession) -> list[dict]:
    result = await db.execute(
        select(ResponseRule)
        .where(ResponseRule.is_active == True)
        .order_by(ResponseRule.created_at)
    )
    return [_rule_to_dict(r) for r in result.scalars().all()]


async def get_rule_by_id(db: AsyncSession, rule_id: UUID) -> dict | None:
    result = await db.execute(select(ResponseRule).where(ResponseRule.id == rule_id))
    rule = result.scalar_one_or_none()
    return _rule_to_dict(rule) if rule else None


async def create_rule(db: AsyncSession, data: dict) -> dict:
    rule = ResponseRule(**data)
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return _rule_to_dict(rule)


async def delete_rule(db: AsyncSession, rule_id: UUID) -> None:
    await db.execute(
        update(ResponseRule)
        .where(ResponseRule.id == rule_id)
        .values(is_active=False)
    )


async def get_active_rules_for_level(db: AsyncSession, threat_level: str) -> list[dict]:
    result = await db.execute(
        select(ResponseRule).where(
            ResponseRule.threat_level == threat_level,
            ResponseRule.is_active == True,
            ResponseRule.auto_execute == True,
        )
    )
    return [_rule_to_dict(r) for r in result.scalars().all()]


def _action_to_dict(a: ResponseAction) -> dict:
    return {col.key: getattr(a, col.key) for col in a.__table__.columns}


def _rule_to_dict(r: ResponseRule) -> dict:
    return {col.key: getattr(r, col.key) for col in r.__table__.columns}
