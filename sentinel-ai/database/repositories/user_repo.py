"""
database/repositories/user_repo.py
===================================
Data access for users table: create, lookup by email/API key, update.
"""
from __future__ import annotations

from uuid import UUID

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import User

logger = structlog.get_logger(__name__)


async def get_user_by_email(db: AsyncSession, email: str) -> dict | None:
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    return _row_to_dict(user)


async def get_user_by_api_key(db: AsyncSession, api_key: str) -> dict | None:
    result = await db.execute(select(User).where(User.api_key == api_key))
    user = result.scalar_one_or_none()
    return _row_to_dict(user)


async def get_user_by_id(db: AsyncSession, user_id: UUID) -> dict | None:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    return _row_to_dict(user)


async def list_users(db: AsyncSession) -> list[dict]:
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return [_row_to_dict(u) for u in result.scalars().all()]


async def create_user(db: AsyncSession, email: str, hashed_pw: str, role: str) -> dict:
    user = User(email=email, hashed_pw=hashed_pw, role=role)
    db.add(user)
    await db.flush()
    await db.refresh(user)
    logger.info("user_created", email=email, role=role)
    return _row_to_dict(user)


async def deactivate_user(db: AsyncSession, user_id: UUID) -> None:
    await db.execute(update(User).where(User.id == user_id).values(is_active=False))


async def update_user_api_key(db: AsyncSession, user_id: UUID, hashed_key: str) -> None:
    await db.execute(update(User).where(User.id == user_id).values(api_key=hashed_key))


async def update_last_login(db: AsyncSession, user_id: UUID) -> None:
    from sqlalchemy import func
    await db.execute(update(User).where(User.id == user_id).values(last_login=func.now()))


def _row_to_dict(user: User | None) -> dict | None:
    if user is None:
        return None
    return {
        "id": user.id,
        "email": user.email,
        "hashed_pw": user.hashed_pw,
        "api_key": user.api_key,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "last_login": user.last_login,
    }
