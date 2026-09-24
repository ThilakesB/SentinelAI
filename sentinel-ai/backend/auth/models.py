"""
backend/auth/models.py
======================
Pydantic schemas for auth-related request/response payloads.
"""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class APIKeyResponse(BaseModel):
    api_key: str
    message: str = "Store this key securely — it will not be shown again."
