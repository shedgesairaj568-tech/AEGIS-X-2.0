"""
Setting repository.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.setting import Setting


class SettingRepository:
    def __init__(self, db: AsyncSession):
        self._db = db

    async def get(self, *, scope: str, key: str, user_id: uuid.UUID | None) -> Setting | None:
        query = select(Setting).where(Setting.scope == scope, Setting.key == key)
        query = query.where(Setting.user_id == user_id) if user_id else query.where(Setting.user_id.is_(None))
        result = await self._db.execute(query)
        return result.scalar_one_or_none()

    async def list_for_scope(self, *, scope: str, user_id: uuid.UUID | None) -> list[Setting]:
        query = select(Setting).where(Setting.scope == scope)
        query = query.where(Setting.user_id == user_id) if user_id else query.where(Setting.user_id.is_(None))
        result = await self._db.execute(query)
        return list(result.scalars().all())

    async def upsert(self, *, scope: str, key: str, value: dict, user_id: uuid.UUID | None) -> Setting:
        existing = await self.get(scope=scope, key=key, user_id=user_id)
        if existing:
            existing.value = value
            await self._db.flush()
            await self._db.refresh(existing)
            return existing

        setting = Setting(scope=scope, key=key, value=value, user_id=user_id)
        self._db.add(setting)
        await self._db.flush()
        await self._db.refresh(setting)
        return setting
