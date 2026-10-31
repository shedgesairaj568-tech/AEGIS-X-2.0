"""
ThreatHistory business logic — thin, since most history writes happen as
a side effect inside AlertService. This service handles the explicit
"analyst adds a note" case.
"""

import uuid

from app.models.threat_history import ThreatHistory
from app.repositories.threat_history_repository import ThreatHistoryRepository
from app.schemas.threat_history import ThreatHistoryCreate


class ThreatHistoryService:
    def __init__(self, history_repository: ThreatHistoryRepository):
        self._history = history_repository

    async def add_entry(
        self, alert_id: uuid.UUID, payload: ThreatHistoryCreate, *, actor_id: uuid.UUID, actor_label: str
    ) -> ThreatHistory:
        return await self._history.create(
            alert_id=alert_id,
            actor_id=actor_id,
            actor_label=actor_label,
            **payload.model_dump(),
        )

    async def list_for_alert(self, alert_id: uuid.UUID) -> list[ThreatHistory]:
        return await self._history.list_for_alert(alert_id)
