"""
Report business logic.
"""

import uuid

from app.core.exceptions import NotFoundError
from app.models.report import Report
from app.repositories.alert_repository import AlertRepository
from app.repositories.report_repository import ReportRepository
from app.repositories.threat_history_repository import ThreatHistoryRepository
from app.schemas.report import ReportCreate


class ReportService:
    def __init__(
        self,
        report_repository: ReportRepository,
        alert_repository: AlertRepository,
        history_repository: ThreatHistoryRepository,
    ):
        self._reports = report_repository
        self._alerts = alert_repository
        self._history = history_repository

    async def create_report(
        self, alert_id: uuid.UUID, payload: ReportCreate, *, created_by_id: uuid.UUID | None
    ) -> Report:
        alert = await self._alerts.get_by_id(alert_id)
        if alert is None:
            raise NotFoundError(f"Alert '{alert_id}' not found.")

        report = await self._reports.create(
            alert_id=alert_id, created_by_id=created_by_id, **payload.model_dump()
        )
        await self._history.create(
            alert_id=alert_id,
            event_type="report_generated",
            description=f"Report generated: {report.title}",
            actor_id=created_by_id,
            actor_label=payload.generated_by,
        )
        return report

    async def list_for_alert(self, alert_id: uuid.UUID) -> list[Report]:
        return await self._reports.list_for_alert(alert_id)
