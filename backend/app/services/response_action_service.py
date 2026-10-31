"""
ResponseAction business logic with Role-Based Access Control and Audit Logging.

Enforces:
- No autonomous execution: actions must pass through human decision.
- Role checks: High blast radius actions require 'admin' role.
- Complete audit trails via AuditLogService.
"""

import uuid
from fastapi import HTTPException, status

from app.models.response_action import ResponseAction
from app.models.user import User
from app.repositories.response_action_repository import ResponseActionRepository
from app.schemas.response_action import ResponseActionCreate
from app.services.audit_log_service import AuditLogService


class ResponseActionService:
    def __init__(
        self,
        repository: ResponseActionRepository,
        audit_logs: AuditLogService,
    ):
        self._repo = repository
        self._audit = audit_logs

    async def list_for_alert(self, alert_id: uuid.UUID) -> list[ResponseAction]:
        return await self._repo.list_for_alert(alert_id)

    async def list_pending(self, limit: int = 50) -> list[ResponseAction]:
        return await self._repo.list_pending(limit)

    async def create_action(self, payload: ResponseActionCreate, created_by: str = "ai_response_agent") -> ResponseAction:
        return await self._repo.create(
            alert_id=payload.alert_id,
            action_type=payload.action_type,
            target=payload.target,
            status="pending_approval",
            required_role=payload.required_role,
            blast_radius=payload.blast_radius,
            description=payload.description,
            rationale=payload.rationale,
            rollback_plan=payload.rollback_plan,
            created_by=created_by,
        )

    async def decide_action(
        self,
        action_id: uuid.UUID,
        decision: str,
        current_user: User,
        notes: str | None = None,
    ) -> ResponseAction:
        action = await self._repo.get_by_id(action_id)
        if not action:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Action '{action_id}' not found.")

        if action.status not in ("pending_approval", "approved"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Action cannot be decided: current status is '{action.status}'.",
            )

        # Enforce Role-Based Access Control (RBAC)
        if (action.required_role == "admin" or action.blast_radius == "HIGH") and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions: HIGH blast radius or administrative actions require 'admin' role.",
            )

        if decision == "approved":
            # 1. Mark as approved by analyst
            await self._repo.update_status(action, status="approved", approved_by_id=current_user.id)

            # 2. Execute containment action (or verified containment hook)
            exec_log = {
                "executor": "aegis_containment_daemon",
                "notes": notes,
                "command_simulated": f"apply_containment_{action.action_type} --target {action.target}",
                "result": "success",
            }
            executed_action = await self._repo.update_status(
                action, status="executed", approved_by_id=current_user.id, execution_log=exec_log
            )

            # 3. Append immutable audit log
            await self._audit.record(
                action="response_action.executed",
                user_id=current_user.id,
                resource_type="response_action",
                resource_id=str(action.id),
                log_metadata={
                    "action_type": action.action_type,
                    "target": action.target,
                    "blast_radius": action.blast_radius,
                    "notes": notes,
                },
            )
            return executed_action

        elif decision == "rejected":
            rejected_action = await self._repo.update_status(
                action,
                status="rejected",
                approved_by_id=current_user.id,
                execution_log={"rejected_by": current_user.email, "notes": notes},
            )

            await self._audit.record(
                action="response_action.rejected",
                user_id=current_user.id,
                resource_type="response_action",
                resource_id=str(action.id),
                log_metadata={
                    "action_type": action.action_type,
                    "target": action.target,
                    "rejection_notes": notes,
                },
            )
            return rejected_action
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid decision '{decision}'. Must be 'approved' or 'rejected'.",
            )

