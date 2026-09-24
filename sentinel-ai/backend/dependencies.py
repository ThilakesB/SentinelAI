"""
backend/dependencies.py
=======================
FastAPI dependency injection.

Provides:
  - get_db()          → async PostgreSQL session
  - get_current_user() → decoded JWT → User model
  - require_admin()   → enforces admin role
  - require_analyst() → enforces analyst or admin role
"""
from __future__ import annotations

from typing import Annotated
from uuid import UUID

import structlog
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer

from backend.auth.service import decode_jwt
from backend.config import get_settings
from database.connection import get_db_session

logger = structlog.get_logger(__name__)
settings = get_settings()

# ── Database session ──────────────────────────────────────────────────────────

async def get_db():
    """
    Yields an async database connection from the pool.
    The connection is returned to the pool after the request completes.
    """
    async with get_db_session() as session:
        yield session


# ── Auth schemes ──────────────────────────────────────────────────────────────

_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class CurrentUser:
    """Lightweight user identity attached to every authenticated request."""
    __slots__ = ("id", "email", "role")

    def __init__(self, id: UUID, email: str, role: str) -> None:
        self.id = id
        self.email = email
        self.role = role

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_analyst(self) -> bool:
        return self.role in ("admin", "analyst")


async def get_current_user(
    token: Annotated[str | None, Depends(_oauth2)],
    api_key: Annotated[str | None, Security(_api_key_header)],
    db=Depends(get_db),
) -> CurrentUser:
    """
    Resolve identity from either a JWT bearer token OR an X-API-Key header.
    Returns CurrentUser or raises 401.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if token:
        payload = decode_jwt(token)
        if not payload:
            raise credentials_exception
        return CurrentUser(
            id=UUID(payload["sub"]),
            email=payload["email"],
            role=payload["role"],
        )

    if api_key:
        from database.repositories.user_repo import get_user_by_api_key
        user = await get_user_by_api_key(db, api_key)
        if not user or not user["is_active"]:
            raise credentials_exception
        return CurrentUser(id=user["id"], email=user["email"], role=user["role"])

    raise credentials_exception


async def require_admin(user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
    """Dependency that enforces the admin role."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return user


async def require_analyst(user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
    """Dependency that enforces analyst or admin role."""
    if not user.is_analyst:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or Admin role required",
        )
    return user


# ── Type aliases for cleaner route signatures ──────────────────────────────────
DBSession = Annotated[object, Depends(get_db)]
AuthUser = Annotated[CurrentUser, Depends(get_current_user)]
AdminUser = Annotated[CurrentUser, Depends(require_admin)]
AnalystUser = Annotated[CurrentUser, Depends(require_analyst)]
