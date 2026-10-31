"""
ResponseAction ORM model for Human-in-the-Loop Incident Response.

Guarantees:
- Destructive containment actions (block IP, isolate host, disable user) are
  never auto-executed.
- Actions default to status="pending_approval".
- Execution requires explicit authorized analyst approval with audit logging.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.db_types import GUID, JSONB_OR_JSON


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)

    alert_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )

    action_type: Mapped[str] = mapped_column(String(50), nullable=False)  # ActionType
    target: Mapped[str] = mapped_column(String(255), nullable=False)  # IP, username, hostname, etc.
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending_approval")  # ActionStatus

    required_role: Mapped[str] = mapped_column(String(50), nullable=False, default="analyst")
    blast_radius: Mapped[str] = mapped_column(String(20), nullable=False, default="LOW")

    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    rationale: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    rollback_plan: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    created_by: Mapped[str] = mapped_column(String(100), nullable=False, default="ai_response_agent")
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_log: Mapped[dict | None] = mapped_column(JSONB_OR_JSON(), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    alert = relationship("Alert", backref="response_actions")
    approved_by = relationship("User", foreign_keys=[approved_by_id])

    def __repr__(self) -> str:
        return f"<ResponseAction id={self.id} type={self.action_type} target={self.target} status={self.status}>"

