"""
Pydantic schemas for Alert resources.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import AlertSeverity, AlertSource, AlertStatus, AttackType


class AlertCreate(BaseModel):
    """
    Shape the AI pipeline (Module 6+) will POST to create an alert.
    Scoring/MITRE fields are optional at creation time since a fast
    detection may arrive before classification/enrichment finishes.
    """

    title: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)

    source: AlertSource
    attack_type: AttackType = "normal"
    severity: AlertSeverity = "low"

    anomaly_score: float | None = Field(default=None, ge=0, le=1)
    risk_score: float | None = Field(default=None, ge=0, le=100)
    confidence: float | None = Field(default=None, ge=0, le=1)

    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None

    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None

    raw_event: dict | None = None


class AlertUpdate(BaseModel):
    """Partial update — only status/severity/assignment are analyst-editable."""

    status: AlertStatus | None = None
    severity: AlertSeverity | None = None
    assigned_to_id: uuid.UUID | None = None


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    description: str | None

    source: str
    attack_type: str
    status: str
    severity: str

    anomaly_score: float | None
    risk_score: float | None
    confidence: float | None

    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None

    mitre_technique_id: str | None
    mitre_technique_name: str | None

    assigned_to_id: uuid.UUID | None

    detected_at: datetime
    created_at: datetime
    updated_at: datetime


class AlertListResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    page: int
    page_size: int
