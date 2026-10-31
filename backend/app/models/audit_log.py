"""
AuditLog ORM model.

Append-only log of security-relevant actions (login, register, alert
status changes, settings changes, report downloads). Distinct from
ThreatHistory: ThreatHistory is about an *alert's* investigation timeline;
AuditLog is about *user/system actions* platform-wide, for compliance and
forensics on the SOC tool itself (who logged in when, who changed what).
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.db_types import GUID, JSONB_OR_JSON


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)

    # Null user_id = system-initiated action (e.g. AI pipeline auto-creating an alert).
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    action: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g. "user.login", "alert.status_changed"
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)  # e.g. "alert", "report"
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    log_metadata: Mapped[dict | None] = mapped_column(JSONB_OR_JSON(), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    user = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action!r} user_id={self.user_id}>"
