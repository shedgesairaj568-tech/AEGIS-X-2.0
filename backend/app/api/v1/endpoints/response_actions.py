"""
API endpoints for Human-in-the-Loop Incident Response Actions.
"""

import uuid
from fastapi import APIRouter, Depends, Query, status

from app.dependencies.auth import get_current_user
from app.dependencies.resources import get_response_action_service
from app.models.user import User
from app.schemas.common import ErrorResponse
from app.schemas.response_action import (
    ResponseActionCreate,
    ResponseActionDecision,
    ResponseActionListResponse,
    ResponseActionResponse,
)
from app.services.response_action_service import ResponseActionService

router = APIRouter(prefix="/actions", tags=["Incident Response Actions"])


@router.get("/pending", response_model=ResponseActionListResponse)
async def list_pending_actions(
    limit: int = Query(default=50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    service: ResponseActionService = Depends(get_response_action_service),
) -> ResponseActionListResponse:
    """Retrieves all containment actions currently pending analyst approval."""
    items = await service.list_pending(limit=limit)
    return ResponseActionListResponse(items=items, total=len(items))


@router.get("/alert/{alert_id}", response_model=list[ResponseActionResponse])
async def list_actions_for_alert(
    alert_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    service: ResponseActionService = Depends(get_response_action_service),
) -> list[ResponseActionResponse]:
    """Retrieves all proposed, approved, and executed actions associated with an alert."""
    return await service.list_for_alert(alert_id)


@router.post(
    "",
    response_model=ResponseActionResponse,
    status_code=status.HTTP_201_CREATED,
    responses={422: {"model": ErrorResponse}},
)
async def create_action(
    payload: ResponseActionCreate,
    current_user: User = Depends(get_current_user),
    service: ResponseActionService = Depends(get_response_action_service),
) -> ResponseActionResponse:
    """Proposes a containment action (always initialized in 'pending_approval' status)."""
    return await service.create_action(payload, created_by=current_user.email)


@router.post(
    "/{action_id}/decision",
    response_model=ResponseActionResponse,
    responses={400: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def decide_action(
    action_id: uuid.UUID,
    payload: ResponseActionDecision,
    current_user: User = Depends(get_current_user),
    service: ResponseActionService = Depends(get_response_action_service),
) -> ResponseActionResponse:
    """
    Approves or rejects a pending containment action.
    RBAC: Actions marked with HIGH blast radius require administrative privileges.
    Executes containment and appends an immutable audit log entry.
    """
    return await service.decide_action(
        action_id=action_id,
        decision=payload.decision,
        current_user=current_user,
        notes=payload.notes,
    )

