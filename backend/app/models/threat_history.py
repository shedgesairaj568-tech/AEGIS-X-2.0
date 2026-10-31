"""
ThreatHistory ORM model.

An append-only timeline of everything that happens to an Alert after
detection — status changes, analyst notes, agent correlation results,
report generation. This is what powers the "Threat Timeline" dashboard
page from the spec, and gives the Investigation Agent (Module 8) a place
to record its reasoning steps.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.db_types import GUID, JSONB_OR_JSON


class ThreatHistory(Base):
    __tablename__ = "threat_history"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)

    alert_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )

    event_type: Mapped[str] = mapped_column(String(50), nullable=False)  # ThreatHistoryEventType
    description: Mapped[str] = mapped_column(String(2000), nullable=False)

    # Who/what caused this entry: a human analyst, or an agent name like
    # "threat_detection_agent" / "investigation_agent". Null actor_id with
    # a non-null actor_label means it was a system/agent action.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_label: Mapped[str | None] = mapped_column(String(100), nullable=True)

    event_metadata: Mapped[dict | None] = mapped_column(JSONB_OR_JSON(), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    alert = relationship("Alert", back_populates="history")
    actor = relationship("User", foreign_keys=[actor_id])

    def __repr__(self) -> str:
        return f"<ThreatHistory id={self.id} alert_id={self.alert_id} event_type={self.event_type!r}>"
