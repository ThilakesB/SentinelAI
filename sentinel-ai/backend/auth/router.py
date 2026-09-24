"""
backend/auth/router.py
======================
Authentication endpoints:
  POST /api/auth/login    → JWT access token
  POST /api/auth/logout   → (stateless; client discards token)
  POST /api/auth/api-key  → generate API key for service accounts
"""
from __future__ import annotations

import secrets
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from backend.auth.models import APIKeyResponse, LoginRequest, TokenResponse
from backend.auth.service import (
    create_access_token,
    hash_password,
    verify_password,
)
from backend.config import get_settings
from backend.dependencies import AdminUser, DBSession

logger = structlog.get_logger(__name__)
settings = get_settings()
router = APIRouter()


@router.post("/login", response_model=TokenResponse, summary="Obtain a JWT access token")
async def login(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DBSession,
) -> TokenResponse:
    """
    Accepts application/x-www-form-urlencoded (OAuth2 standard) OR JSON.
    Returns a JWT access token on success.
    """
    from database.repositories.user_repo import get_user_by_email

    user = await get_user_by_email(db, form.username)
    if not user or not user["is_active"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not verify_password(form.password, user["hashed_pw"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(
        user_id=user["id"],
        email=user["email"],
        role=user["role"],
    )
    logger.info("user_logged_in", email=user["email"], role=user["role"])
    return TokenResponse(
        access_token=token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Logout (client-side token discard)")
async def logout() -> None:
    """
    Stateless — instructs the client to discard the token.
    For true revocation, implement a token blocklist via Redis/DB.
    """
    return None


@router.post("/api-key", response_model=APIKeyResponse, summary="Generate an API key (admin only)")
async def generate_api_key(
    current_user: AdminUser,
    db: DBSession,
) -> APIKeyResponse:
    """
    Generates a cryptographically random API key for the requesting admin user.
    The raw key is returned ONCE — only the hash is stored.
    """
    from database.repositories.user_repo import update_user_api_key

    raw_key = secrets.token_urlsafe(40)
    hashed_key = hash_password(raw_key)
    await update_user_api_key(db, current_user.id, hashed_key)
    logger.info("api_key_generated", actor=current_user.email)
    return APIKeyResponse(api_key=raw_key)
