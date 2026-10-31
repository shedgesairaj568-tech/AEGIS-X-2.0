"""
Audit log endpoints — read-only, admin-gated. Entries are written
internally by other services (e.g. AuthService), never via a public POST.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.dependencies.auth import require_role
from app.repositories.audit_log_repository import AuditLogRepository
from app.schemas.audit_log import AuditLogListResponse
from app.services.audit_log_service import AuditLogService

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


def get_audit_log_service_dep(db: AsyncSession = Depends(get_db_session)) -> AuditLogService:
    return AuditLogService(AuditLogRepository(db))


@router.get(
    "",
    response_model=AuditLogListResponse,
    dependencies=[Depends(require_role("admin"))],
    summary="List audit log entries (admin only)",
)
async def list_audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    audit_service: AuditLogService = Depends(get_audit_log_service_dep),
) -> AuditLogListResponse:
    items, total = await audit_service.list_logs(page=page, page_size=page_size)
    return AuditLogListResponse(items=items, total=total, page=page, page_size=page_size)
