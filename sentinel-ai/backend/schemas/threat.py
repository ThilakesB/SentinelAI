"""
backend/schemas/threat.py
=========================
Pydantic models for the threat detection domain.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


ThreatLevel = Literal["Normal", "Suspicious", "Critical"]
TriggerType = Literal["process", "network", "hash_match", "yara_match"]


class FeatureContribution(BaseModel):
    """Top-N feature explanation for a threat event."""
    feature: str
    value: float
    baseline_mean: float
    deviation: float  # z-score
    direction: Literal["above", "below"]


class ThreatEvent(BaseModel):
    id: UUID
    detected_at: datetime
    threat_level: ThreatLevel
    anomaly_score: float | None = None
    trigger_type: TriggerType | None = None
    feature_vector: dict | None = Field(None, description="Raw 18-feature vector used for inference")
    top_features: list[FeatureContribution] = Field(default_factory=list)
    process_id: UUID | None = None
    network_id: UUID | None = None
    ml_model_version: str | None = None
    is_resolved: bool = False
    resolved_at: datetime | None = None
    notes: str | None = None

    model_config = {"from_attributes": True}


class ThreatListResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: list[ThreatEvent]


class RescanRequest(BaseModel):
    """Request a fresh monitoring + classification cycle."""
    pid: int | None = Field(None, description="If provided, rescan only this PID")


class RescanResponse(BaseModel):
    message: str
    events_generated: int
