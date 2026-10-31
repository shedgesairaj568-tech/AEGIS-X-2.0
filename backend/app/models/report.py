"""
Report ORM model.

An AI-generated (or analyst-authored) incident report for an Alert —
root cause, explanation, mitigation, and an optional downloadable PDF.
Produced by the Response Agent (Module 8) but the table exists now so the
API contract is stable before that agent exists.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.db_types import GUID


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)

    alert_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(String(4000), nullable=False)
    root_cause: Mapped[str | None] = mapped_column(String(4000), nullable=True)
    mitigation: Mapped[str | None] = mapped_column(String(4000), nullable=True)

    # Path/URL to a generated PDF (reports/generated/ locally, or object
    # storage key in production). Nullable because a report can exist as
    # structured text before a PDF has been rendered.
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)

    generated_by: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    alert = relationship("Alert", back_populates="reports")
    created_by = relationship("User", foreign_keys=[created_by_id])

    def __repr__(self) -> str:
        return f"<Report id={self.id} alert_id={self.alert_id} title={self.title!r}>"
