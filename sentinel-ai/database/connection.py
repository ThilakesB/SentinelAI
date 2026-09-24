"""
database/connection.py
======================
Async PostgreSQL connection management via asyncpg + SQLAlchemy.

- Uses a connection pool sized via config.
- Provides get_db_session() context manager for use in FastAPI DI.
- init_db() / close_db() called from app lifespan.
"""
from __future__ import annotations

import contextlib
from typing import AsyncGenerator

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


async def init_db() -> None:
    """
    Create the async engine and session factory.
    Called once during app lifespan startup.
    """
    global _engine, _session_factory

    _engine = create_async_engine(
        settings.database_url,
        pool_size=settings.database_pool_min_size,
        max_overflow=settings.database_pool_max_size - settings.database_pool_min_size,
        pool_pre_ping=True,           # Detect stale connections
        pool_recycle=3600,            # Recycle after 1 h
        echo=not settings.is_production,
        json_serializer=_json_serializer,
    )

    _session_factory = async_sessionmaker(
        _engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )

    logger.info("database_pool_initialized", url=_redact_url(settings.database_url))


async def close_db() -> None:
    """Dispose the engine pool on shutdown."""
    global _engine
    if _engine:
        await _engine.dispose()
        logger.info("database_pool_closed")


@contextlib.asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Yields a database session. Commits on success, rolls back on exception.
    Use as a FastAPI dependency via backend.dependencies.get_db.
    """
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("Database engine not initialized.")
    return _engine


# ── Helpers ──────────────────────────────────────────────────────────────────

def _json_serializer(obj: object) -> str:
    import orjson
    return orjson.dumps(obj).decode()


def _redact_url(url: str) -> str:
    """Replace password in URL for safe logging."""
    try:
        from urllib.parse import urlparse, urlunparse
        p = urlparse(url)
        safe = p._replace(netloc=p.netloc.replace(p.password or "", "***"))
        return urlunparse(safe)
    except Exception:
        return "<url_redacted>"
