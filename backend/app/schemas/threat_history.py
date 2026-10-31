"""
Pydantic schemas for ThreatHistory (alert investigation timeline).
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import ThreatHistoryEventType


class ThreatHistoryCreate(BaseModel):
    event_type: ThreatHistoryEventType
    description: str = Field(min_length=1, max_length=2000)
    event_metadata: dict | None = None


class ThreatHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_id: uuid.UUID
    event_type: str
    description: str
    actor_id: uuid.UUID | None
    actor_label: str | None
    event_metadata: dict | None
    created_at: datetime
