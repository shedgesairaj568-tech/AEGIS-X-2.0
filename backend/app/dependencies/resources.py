"""
Dependency wiring for Alert, ThreatHistory, Report, and Setting resources.
Mirrors the pattern in app/dependencies/auth.py: DB session -> repository -> service.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.dependencies.auth import get_audit_log_service
from app.repositories.alert_repository import AlertRepository
from app.repositories.report_repository import ReportRepository
from app.repositories.response_action_repository import ResponseActionRepository
from app.repositories.setting_repository import SettingRepository
from app.repositories.threat_history_repository import ThreatHistoryRepository
from app.services.alert_service import AlertService
from app.services.audit_log_service import AuditLogService
from app.services.report_service import ReportService
from app.services.response_action_service import ResponseActionService
from app.services.setting_service import SettingService
from app.services.threat_history_service import ThreatHistoryService


def get_alert_repository(db: AsyncSession = Depends(get_db_session)) -> AlertRepository:
    return AlertRepository(db)


def get_threat_history_repository(db: AsyncSession = Depends(get_db_session)) -> ThreatHistoryRepository:
    return ThreatHistoryRepository(db)


def get_report_repository(db: AsyncSession = Depends(get_db_session)) -> ReportRepository:
    return ReportRepository(db)


def get_setting_repository(db: AsyncSession = Depends(get_db_session)) -> SettingRepository:
    return SettingRepository(db)


def get_alert_service(
    alert_repo: AlertRepository = Depends(get_alert_repository),
    history_repo: ThreatHistoryRepository = Depends(get_threat_history_repository),
) -> AlertService:
    return AlertService(alert_repo, history_repo)


def get_threat_history_service(
    history_repo: ThreatHistoryRepository = Depends(get_threat_history_repository),
) -> ThreatHistoryService:
    return ThreatHistoryService(history_repo)


def get_report_service(
    report_repo: ReportRepository = Depends(get_report_repository),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    history_repo: ThreatHistoryRepository = Depends(get_threat_history_repository),
) -> ReportService:
    return ReportService(report_repo, alert_repo, history_repo)


def get_setting_service(setting_repo: SettingRepository = Depends(get_setting_repository)) -> SettingService:
    return SettingService(setting_repo)


def get_response_action_repository(db: AsyncSession = Depends(get_db_session)) -> ResponseActionRepository:
    return ResponseActionRepository(db)


def get_response_action_service(
    repo: ResponseActionRepository = Depends(get_response_action_repository),
    audit_logs: AuditLogService = Depends(get_audit_log_service),
) -> ResponseActionService:
    return ResponseActionService(repo, audit_logs)
