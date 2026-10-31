"""
Pydantic schemas for incident Reports.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ReportCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    summary: str = Field(min_length=1, max_length=4000)
    root_cause: str | None = Field(default=None, max_length=4000)
    mitigation: str | None = Field(default=None, max_length=4000)
    file_path: str | None = None
    generated_by: str = "system"


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_id: uuid.UUID
    title: str
    summary: str
    root_cause: str | None
    mitigation: str | None
    file_path: str | None
    generated_by: str
    created_by_id: uuid.UUID | None
    created_at: datetime
