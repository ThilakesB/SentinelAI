"""
backend/auth/service.py
=======================
JWT creation/verification and API-key hashing utilities.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import structlog
import bcrypt
from jose import JWTError, jwt

from backend.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt. Truncates to 72 bytes (bcrypt limit)."""
    return bcrypt.hashpw(plain[:72].encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time bcrypt verification."""
    try:
        return bcrypt.checkpw(plain[:72].encode(), hashed.encode())
    except Exception:
        return False


# ── JWT helpers ───────────────────────────────────────────────────────────────

def create_access_token(user_id: UUID, email: str, role: str) -> str:
    """Return a signed JWT access token valid for configured minutes."""
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_jwt(token: str) -> dict[str, Any] | None:
    """
    Decode and verify a JWT. Returns payload dict on success, None on failure.
    Logs failures at DEBUG to avoid leaking timing info.
    """
    try:
        return jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as exc:
        logger.debug("jwt_decode_failed", error=str(exc))
        return None
