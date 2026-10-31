"""
Pydantic schemas for Human-in-the-Loop Response Actions.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import ActionStatus, ActionType


class ResponseActionCreate(BaseModel):
    alert_id: uuid.UUID
    action_type: ActionType
    target: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=1000)
    required_role: str = "analyst"
    blast_radius: str = "LOW"
    rationale: str | None = None
    rollback_plan: str | None = None


class ResponseActionDecision(BaseModel):
    decision: ActionStatus  # "approved" or "rejected"
    notes: str | None = Field(default=None, max_length=1000)


class ResponseActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_id: uuid.UUID
    action_type: str
    target: str
    status: str
    required_role: str
    blast_radius: str
    description: str
    rationale: str | None
    rollback_plan: str | None
    created_by: str
    approved_by_id: uuid.UUID | None
    approved_at: datetime | None
    executed_at: datetime | None
    execution_log: dict | None
    created_at: datetime
    updated_at: datetime


class ResponseActionListResponse(BaseModel):
    items: list[ResponseActionResponse]
    total: int

