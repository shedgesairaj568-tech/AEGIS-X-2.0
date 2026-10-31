"""
Alert repository — isolates all DB access for Alert, including the
filtered/paginated listing the dashboard's "Threat Monitoring" page needs.
"""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert


class AlertRepository:
    def __init__(self, db: AsyncSession):
        self._db = db

    async def get_by_id(self, alert_id: uuid.UUID) -> Alert | None:
        result = await self._db.execute(select(Alert).where(Alert.id == alert_id))
        return result.scalar_one_or_none()

    async def create(self, **fields) -> Alert:
        alert = Alert(**fields)
        self._db.add(alert)
        await self._db.flush()
        await self._db.refresh(alert)
        return alert

    async def update(self, alert: Alert, **fields) -> Alert:
        for key, value in fields.items():
            if value is not None:
                setattr(alert, key, value)
        await self._db.flush()
        await self._db.refresh(alert)
        return alert

    async def list_filtered(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        attack_type: str | None = None,
        source: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Alert], int]:
        query = select(Alert)
        count_query = select(func.count()).select_from(Alert)

        if status:
            query = query.where(Alert.status == status)
            count_query = count_query.where(Alert.status == status)
        if severity:
            query = query.where(Alert.severity == severity)
            count_query = count_query.where(Alert.severity == severity)
        if attack_type:
            query = query.where(Alert.attack_type == attack_type)
            count_query = count_query.where(Alert.attack_type == attack_type)
        if source:
            query = query.where(Alert.source == source)
            count_query = count_query.where(Alert.source == source)

        total = (await self._db.execute(count_query)).scalar_one()

        query = query.order_by(Alert.detected_at.desc()).offset((page - 1) * page_size).limit(page_size)
        result = await self._db.execute(query)
        items = list(result.scalars().all())

        return items, total
