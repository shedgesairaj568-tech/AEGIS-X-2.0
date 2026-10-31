"""
ResponseAction repository.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.response_action import ResponseAction


class ResponseActionRepository:
    def __init__(self, db: AsyncSession):
        self._db = db

    async def get_by_id(self, action_id: uuid.UUID) -> ResponseAction | None:
        result = await self._db.execute(select(ResponseAction).where(ResponseAction.id == action_id))
        return result.scalar_one_or_none()

    async def create(self, **fields) -> ResponseAction:
        action = ResponseAction(**fields)
        self._db.add(action)
        await self._db.flush()
        await self._db.refresh(action)
        return action

    async def list_for_alert(self, alert_id: uuid.UUID) -> list[ResponseAction]:
        result = await self._db.execute(
            select(ResponseAction)
            .where(ResponseAction.alert_id == alert_id)
            .order_by(ResponseAction.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_pending(self, limit: int = 50) -> list[ResponseAction]:
        result = await self._db.execute(
            select(ResponseAction)
            .where(ResponseAction.status == "pending_approval")
            .order_by(ResponseAction.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def update_status(
        self,
        action: ResponseAction,
        status: str,
        approved_by_id: uuid.UUID | None = None,
        execution_log: dict | None = None,
    ) -> ResponseAction:
        action.status = status
        now = datetime.now(timezone.utc)
        if status == "approved":
            action.approved_by_id = approved_by_id
            action.approved_at = now
        elif status == "executed":
            action.executed_at = now
            if execution_log:
                action.execution_log = execution_log
        elif status == "rejected":
            action.approved_by_id = approved_by_id
            action.approved_at = now
            if execution_log:
                action.execution_log = execution_log

        await self._db.flush()
        await self._db.refresh(action)
        return action

