import uuid
from fastapi import APIRouter, Depends, Query, status

from app.core.enums import AlertSeverity, AlertSource, AlertStatus, AttackType
from app.dependencies.auth import get_current_user
from app.dependencies.resources import get_alert_service, get_report_service, get_threat_history_service
from app.models.user import User
from app.schemas.alert import AlertCreate, AlertListResponse, AlertResponse, AlertUpdate
from app.schemas.common import ErrorResponse
from app.schemas.report import ReportCreate, ReportResponse
from app.schemas.threat_history import ThreatHistoryCreate, ThreatHistoryResponse
from app.services.alert_service import AlertService
from app.services.report_service import ReportService
from app.services.threat_history_service import ThreatHistoryService

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED, responses={422: {"model": ErrorResponse}})
async def create_alert(payload: AlertCreate, current_user: User = Depends(get_current_user),
                        alert_service: AlertService = Depends(get_alert_service)):
    return await alert_service.create_alert(payload)


@router.get("", response_model=AlertListResponse)
async def list_alerts(status_filter: AlertStatus | None = Query(default=None, alias="status"),
                       severity: AlertSeverity | None = Query(default=None),
                       attack_type: AttackType | None = Query(default=None),
                       source: AlertSource | None = Query(default=None),
                       page: int = Query(default=1, ge=1), page_size: int = Query(default=25, ge=1, le=100),
                       current_user: User = Depends(get_current_user),
                       alert_service: AlertService = Depends(get_alert_service)) -> AlertListResponse:
    items, total = await alert_service.list_alerts(status=status_filter, severity=severity, attack_type=attack_type,
                                                     source=source, page=page, page_size=page_size)
    return AlertListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get("/related", response_model=list[AlertResponse])
async def list_related_alerts(
    attack_type: AttackType | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    exclude_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    alert_service: AlertService = Depends(get_alert_service),
):
    """
    Used by the AI pipeline's Investigation Agent (Module 8/9) to fetch
    prior alerts sharing the same attack_type or source_ip, for
    correlation. Placed before /{alert_id} in the route order so "related"
    isn't swallowed by the {alert_id} path parameter.
    """
    return await alert_service.list_related_events(
        attack_type=attack_type, source_ip=source_ip, exclude_id=exclude_id, limit=limit
    )


@router.get("/{alert_id}", response_model=AlertResponse, responses={404: {"model": ErrorResponse}})
async def get_alert(alert_id: uuid.UUID, current_user: User = Depends(get_current_user),
                     alert_service: AlertService = Depends(get_alert_service)):
    return await alert_service.get_alert(alert_id)


@router.patch("/{alert_id}", response_model=AlertResponse, responses={404: {"model": ErrorResponse}})
async def update_alert(alert_id: uuid.UUID, payload: AlertUpdate, current_user: User = Depends(get_current_user),
                        alert_service: AlertService = Depends(get_alert_service)):
    return await alert_service.update_alert(alert_id, payload, actor_id=current_user.id, actor_label=current_user.email)


@router.get("/{alert_id}/history", response_model=list[ThreatHistoryResponse], responses={404: {"model": ErrorResponse}})
async def get_alert_history(alert_id: uuid.UUID, current_user: User = Depends(get_current_user),
                             alert_service: AlertService = Depends(get_alert_service),
                             history_service: ThreatHistoryService = Depends(get_threat_history_service)):
    await alert_service.get_alert(alert_id)
    return await history_service.list_for_alert(alert_id)


@router.post("/{alert_id}/history", response_model=ThreatHistoryResponse, status_code=status.HTTP_201_CREATED, responses={404: {"model": ErrorResponse}})
async def add_alert_history(alert_id: uuid.UUID, payload: ThreatHistoryCreate, current_user: User = Depends(get_current_user),
                             alert_service: AlertService = Depends(get_alert_service),
                             history_service: ThreatHistoryService = Depends(get_threat_history_service)):
    await alert_service.get_alert(alert_id)
    return await history_service.add_entry(alert_id, payload, actor_id=current_user.id, actor_label=current_user.email)


@router.get("/{alert_id}/reports", response_model=list[ReportResponse], responses={404: {"model": ErrorResponse}})
async def list_alert_reports(alert_id: uuid.UUID, current_user: User = Depends(get_current_user),
                              alert_service: AlertService = Depends(get_alert_service),
                              report_service: ReportService = Depends(get_report_service)):
    await alert_service.get_alert(alert_id)
    return await report_service.list_for_alert(alert_id)


@router.post("/{alert_id}/reports", response_model=ReportResponse, status_code=status.HTTP_201_CREATED, responses={404: {"model": ErrorResponse}})
async def create_alert_report(alert_id: uuid.UUID, payload: ReportCreate, current_user: User = Depends(get_current_user),
                               report_service: ReportService = Depends(get_report_service)):
    return await report_service.create_report(alert_id, payload, created_by_id=current_user.id)
