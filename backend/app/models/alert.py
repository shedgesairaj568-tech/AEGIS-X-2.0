"""
Alert ORM model.

This is the central table of the platform: every detection produced by the
AI pipeline (Module 6+) becomes a row here, and Reports / ThreatHistory
both hang off of it. Deliberately denormalized with the raw network
5-tuple (source/dest ip/port, protocol) inline rather than a separate
"network_event" table, since alerts are read far more often than written
and the dashboard needs these fields on every list view.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.db_types import GUID, JSONB_OR_JSON


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    # --- Classification (populated by the AI pipeline, Module 6) ---
    source: Mapped[str] = mapped_column(String(50), nullable=False)  # AlertSource
    attack_type: Mapped[str] = mapped_column(String(50), nullable=False, default="normal")  # AttackType
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="open")  # AlertStatus
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="low")  # AlertSeverity

    # --- Scoring (populated by Isolation Forest / XGBoost, Module 6) ---
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    # --- Network context ---
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)  # IPv4/IPv6
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(nullable=True)
    destination_port: Mapped[int | None] = mapped_column(nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # --- MITRE ATT&CK mapping (populated by the Knowledge Agent, Module 8) ---
    mitre_technique_id: Mapped[str | None] = mapped_column(String(20), nullable=True)  # e.g. "T1110"
    mitre_technique_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Raw feature vector / original event payload — kept as JSON since its
    # shape depends on the input source (NetFlow vs auth log vs IDS alert).
    raw_event: Mapped[dict | None] = mapped_column(JSONB_OR_JSON(), nullable=True)

    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    assigned_to = relationship("User", foreign_keys=[assigned_to_id])
    history = relationship("ThreatHistory", back_populates="alert", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="alert", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Alert id={self.id} attack_type={self.attack_type!r} severity={self.severity!r} status={self.status!r}>"
