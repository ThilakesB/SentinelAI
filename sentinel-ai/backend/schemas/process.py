"""
backend/schemas/process.py
==========================
Pydantic models for the process monitoring domain.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class ProcessSnapshot(BaseModel):
    """A single captured process state."""
    id: UUID
    captured_at: datetime
    pid: int
    name: str
    exe_path: str | None = None
    exe_hash: str | None = Field(None, description="SHA-256 of the executable")
    cpu_percent: float = Field(ge=0.0, le=100.0)
    ram_mb: float = Field(ge=0.0)
    disk_read_mb: float = 0.0
    disk_write_mb: float = 0.0
    net_sent_mb: float = 0.0
    net_recv_mb: float = 0.0
    start_time: datetime | None = None
    parent_pid: int | None = None
    is_signed: bool | None = None
    signer_name: str | None = None
    status: str | None = None
    threat_event_id: UUID | None = None

    model_config = {"from_attributes": True}


class ProcessListResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: list[ProcessSnapshot]


class ProcessHistoryResponse(BaseModel):
    pid: int
    snapshots: list[ProcessSnapshot]
