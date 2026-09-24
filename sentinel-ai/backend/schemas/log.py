"""
backend/schemas/log.py
======================
Pydantic models for the logs & reports domain.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class AuditLogEntry(BaseModel):
    id: UUID
    logged_at: datetime
    actor: str
    action: str
    resource: str | None = None
    payload: dict | None = None
    ip_address: str | None = None
    outcome: Literal["success", "failed", "denied"]

    model_config = {"from_attributes": True}


class LogListResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: list[AuditLogEntry]


class LogSearchRequest(BaseModel):
    q: str = Field(..., min_length=2, description="Full-text search term")
    from_ts: datetime | None = None
    to_ts: datetime | None = None
    page: int = Field(1, ge=1)
    limit: int = Field(50, ge=1, le=200)


class ExportFormat(str):
    pass
