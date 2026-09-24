"""
backend/schemas/response.py
===========================
Pydantic models for the automated response domain.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator
import ipaddress


ActionType = Literal["kill_process", "block_ip", "alert"]
ActionStatus = Literal["success", "failed", "skipped_protected", "pending_confirmation"]


class RespondRequest(BaseModel):
    action: ActionType
    confirm_token: str | None = Field(
        None,
        description=(
            "Required for kill_process actions targeting processes in the protected list. "
            "Obtain via GET /api/threats/{id} which returns a confirmation_required flag."
        ),
    )
    force_override: bool = Field(
        False,
        description="Admin-only override for protected process kill. Requires admin JWT role.",
    )


class ResponseAction(BaseModel):
    id: UUID
    executed_at: datetime
    action_type: ActionType
    threat_event_id: UUID
    target_pid: int | None = None
    target_ip: str | None = None
    firewall_rule: str | None = None
    actor: str
    status: ActionStatus
    failure_reason: str | None = None
    rolled_back: bool = False

    model_config = {"from_attributes": True}


class ResponseRule(BaseModel):
    """A configurable auto-response rule."""
    id: UUID
    name: str
    threat_level: Literal["Suspicious", "Critical"]
    action: ActionType
    auto_execute: bool = False       # Requires explicit opt-in
    protected_override: bool = False
    is_active: bool = True
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CreateRuleRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    threat_level: Literal["Suspicious", "Critical"]
    action: ActionType
    auto_execute: bool = False
    protected_override: bool = False


class RollbackRequest(BaseModel):
    reason: str = Field(..., min_length=5, description="Reason for rollback (stored in audit log)")
