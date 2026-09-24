"""
backend/schemas/network.py
==========================
Pydantic models for the network monitoring domain.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class NetworkConnection(BaseModel):
    id: UUID
    captured_at: datetime
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    bytes_sent: int = 0
    bytes_recv: int = 0
    packet_count: int = 0
    pid: int | None = None
    process_name: str | None = None
    status: str | None = None
    is_suspicious: bool = False
    intel_score: float | None = Field(None, ge=0.0, le=100.0, description="AbuseIPDB score 0–100")
    threat_event_id: UUID | None = None

    model_config = {"from_attributes": True}


class NetworkBaseline(BaseModel):
    """Per-process network baseline statistics."""
    process_name: str
    mean_sent_mb_s: float
    mean_recv_mb_s: float
    std_sent_mb_s: float
    std_recv_mb_s: float
    threshold_sent_mb_s: float  # mean + 3σ
    threshold_recv_mb_s: float
    sample_count: int
    window_minutes: int


class NetworkConnectionListResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: list[NetworkConnection]


class SuspiciousNetworkResponse(BaseModel):
    """Connections flagged as suspicious."""
    total: int
    items: list[NetworkConnection]
