"""
Alert business logic.

Every create/update also writes a ThreatHistory entry, so the timeline is
always consistent with the alert's actual state — callers never need to
remember to log history separately.
"""

import uuid

from app.core.exceptions import NotFoundError
from app.models.alert import Alert
from app.repositories.alert_repository import AlertRepository
from app.repositories.threat_history_repository import ThreatHistoryRepository
from app.schemas.alert import AlertCreate, AlertUpdate


class AlertService:
    def __init__(self, alert_repository: AlertRepository, history_repository: ThreatHistoryRepository):
        self._alerts = alert_repository
        self._history = history_repository

    async def create_alert(self, payload: AlertCreate, *, actor_label: str = "ai_pipeline") -> Alert:
        alert = await self._alerts.create(**payload.model_dump())
        await self._history.create(
            alert_id=alert.id,
            event_type="detected",
            description=f"Alert created: {alert.title}",
            actor_label=actor_label,
        )
        return alert

    async def get_alert(self, alert_id: uuid.UUID) -> Alert:
        alert = await self._alerts.get_by_id(alert_id)
        if alert is None:
            raise NotFoundError(f"Alert '{alert_id}' not found.")
        return alert

    async def list_alerts(
        self,
        *,
        status: str | None,
        severity: str | None,
        attack_type: str | None,
        source: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[Alert], int]:
        return await self._alerts.list_filtered(
            status=status,
            severity=severity,
            attack_type=attack_type,
            source=source,
            page=page,
            page_size=page_size,
        )

    async def update_alert(
        self, alert_id: uuid.UUID, payload: AlertUpdate, *, actor_id: uuid.UUID, actor_label: str
    ) -> Alert:
        alert = await self.get_alert(alert_id)
        changes = payload.model_dump(exclude_unset=True, exclude_none=True)

        previous_status = alert.status
        updated = await self._alerts.update(alert, **changes)

        if "status" in changes and changes["status"] != previous_status:
            await self._history.create(
                alert_id=alert.id,
                event_type="status_change",
                description=f"Status changed from '{previous_status}' to '{changes['status']}'",
                actor_id=actor_id,
                actor_label=actor_label,
            )
        if "assigned_to_id" in changes:
            await self._history.create(
                alert_id=alert.id,
                event_type="assignment",
                description="Alert reassigned",
                actor_id=actor_id,
                actor_label=actor_label,
                event_metadata={"assigned_to_id": str(changes["assigned_to_id"])},
            )

        return updated
