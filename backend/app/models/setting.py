"""
Setting ORM model.

Simple key/value settings store, scoped either to a single user
("dark_mode", "alert_email_notifications") or the whole system
("risk_score_threshold", "retention_days"). A generic key/value table
(rather than a rigid settings schema) means new settings can be added
from the frontend or AI pipeline without a migration.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.db_types import GUID, JSONB_OR_JSON


class Setting(Base):
    __tablename__ = "settings"
    __table_args__ = (
        UniqueConstraint("scope", "user_id", "key", name="uq_settings_scope_user_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)

    scope: Mapped[str] = mapped_column(String(20), nullable=False)  # SettingScope: "user" | "system"
    # Null for system-scoped settings; set for user-scoped settings.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )

    key: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[dict] = mapped_column(JSONB_OR_JSON(), nullable=False)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    user = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<Setting scope={self.scope!r} user_id={self.user_id} key={self.key!r}>"
