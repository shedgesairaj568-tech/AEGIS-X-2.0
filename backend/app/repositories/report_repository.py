"""
Report repository.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.report import Report


class ReportRepository:
    def __init__(self, db: AsyncSession):
        self._db = db

    async def get_by_id(self, report_id: uuid.UUID) -> Report | None:
        result = await self._db.execute(select(Report).where(Report.id == report_id))
        return result.scalar_one_or_none()

    async def create(self, **fields) -> Report:
        report = Report(**fields)
        self._db.add(report)
        await self._db.flush()
        await self._db.refresh(report)
        return report

    async def list_for_alert(self, alert_id: uuid.UUID) -> list[Report]:
        result = await self._db.execute(
            select(Report).where(Report.alert_id == alert_id).order_by(Report.created_at.desc())
        )
        return list(result.scalars().all())
