"""
backend/schemas/settings.py
===========================
Pydantic models for the settings & user management domain.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class SettingsResponse(BaseModel):
    """Full settings key-value map."""
    monitoring_interval_sec: int
    cpu_anomaly_threshold: float
    ram_anomaly_threshold: float
    auto_kill_critical: bool
    auto_block_ip_critical: bool
    abuseipdb_score_threshold: int
    threat_intel_refresh_hours: int
    ml_anomaly_suspicious_threshold: float
    ml_anomaly_critical_threshold: float
    ml_retrain_hour: int


class SettingsUpdateRequest(BaseModel):
    """Partial update — only supplied keys are changed."""
    monitoring_interval_sec: int | None = Field(None, ge=1, le=60)
    cpu_anomaly_threshold: float | None = Field(None, ge=0.0, le=100.0)
    ram_anomaly_threshold: float | None = Field(None, ge=0.0, le=100.0)
    auto_kill_critical: bool | None = None
    auto_block_ip_critical: bool | None = None
    abuseipdb_score_threshold: int | None = Field(None, ge=0, le=100)
    threat_intel_refresh_hours: int | None = Field(None, ge=1, le=24)
    ml_anomaly_suspicious_threshold: float | None = Field(None, le=0.0)
    ml_anomaly_critical_threshold: float | None = Field(None, le=0.0)
    ml_retrain_hour: int | None = Field(None, ge=0, le=23)


class UserResponse(BaseModel):
    id: UUID
    email: str
    role: Literal["admin", "analyst", "viewer"]
    is_active: bool
    created_at: datetime
    last_login: datetime | None = None

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=10)
    role: Literal["admin", "analyst", "viewer"] = "analyst"
