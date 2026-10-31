"""
AuditLog repository.
"""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


class AuditLogRepository:
    def __init__(self, db: AsyncSession):
        self._db = db

    async def create(self, **fields) -> AuditLog:
        entry = AuditLog(**fields)
        self._db.add(entry)
        await self._db.flush()
        await self._db.refresh(entry)
        return entry

    async def list_paginated(self, *, page: int = 1, page_size: int = 25) -> tuple[list[AuditLog], int]:
        total = (await self._db.execute(select(func.count()).select_from(AuditLog))).scalar_one()
        result = await self._db.execute(
            select(AuditLog).order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        )
        return list(result.scalars().all()), total
