"""
ThreatHistory repository.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_history import ThreatHistory


class ThreatHistoryRepository:
    def __init__(self, db: AsyncSession):
        self._db = db

    async def create(self, **fields) -> ThreatHistory:
        entry = ThreatHistory(**fields)
        self._db.add(entry)
        await self._db.flush()
        await self._db.refresh(entry)
        return entry

    async def list_for_alert(self, alert_id: uuid.UUID) -> list[ThreatHistory]:
        result = await self._db.execute(
            select(ThreatHistory)
            .where(ThreatHistory.alert_id == alert_id)
            .order_by(ThreatHistory.created_at.asc())
        )
        return list(result.scalars().all())
