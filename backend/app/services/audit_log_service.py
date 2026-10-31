"""
AuditLog business logic.

`record()` is designed to be called from other services (e.g. AuthService
on login/register) as a fire-and-forget audit write — it deliberately
takes loosely-typed args so any part of the app can log an action without
importing the AuditLog model directly.
"""

import uuid

from app.repositories.audit_log_repository import AuditLogRepository


class AuditLogService:
    def __init__(self, audit_log_repository: AuditLogRepository):
        self._logs = audit_log_repository

    async def record(
        self,
        *,
        action: str,
        user_id: uuid.UUID | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        ip_address: str | None = None,
        log_metadata: dict | None = None,
    ) -> None:
        await self._logs.create(
            action=action,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            log_metadata=log_metadata,
        )

    async def list_logs(self, *, page: int, page_size: int):
        return await self._logs.list_paginated(page=page, page_size=page_size)
