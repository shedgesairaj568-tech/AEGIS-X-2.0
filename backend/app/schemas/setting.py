"""
Pydantic schemas for Settings.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import SettingScope


class SettingUpsert(BaseModel):
    value: dict = Field(description="Arbitrary JSON value for this setting key")


class SettingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scope: SettingScope
    user_id: uuid.UUID | None
    key: str
    value: dict
    updated_at: datetime
