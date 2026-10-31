"""
Settings business logic.
"""

import uuid

from app.models.setting import Setting
from app.repositories.setting_repository import SettingRepository


class SettingService:
    def __init__(self, setting_repository: SettingRepository):
        self._settings = setting_repository

    async def list_settings(self, *, scope: str, user_id: uuid.UUID | None) -> list[Setting]:
        return await self._settings.list_for_scope(scope=scope, user_id=user_id)

    async def upsert_setting(
        self, *, scope: str, key: str, value: dict, user_id: uuid.UUID | None
    ) -> Setting:
        return await self._settings.upsert(scope=scope, key=key, value=value, user_id=user_id)
