"""
Unit tests for ResponseActionService — testing RBAC, state transitions, and audit log generation.
"""

import os
import uuid
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.models.response_action import ResponseAction
from app.models.user import User
from app.schemas.response_action import ResponseActionCreate
from app.services.response_action_service import ResponseActionService


def async_return(val):
    async def _f():
        return val
    return _f()


def drive_coro(coro):
    """
    Drive a coroutine chain of mock returns to completion without needing
    Windows IOCP ProactorEventLoop sockets in the sandbox environment.
    """
    stack = [coro]
    val = None
    exc = None
    while stack:
        current = stack[-1]
        try:
            if exc:
                curr_exc = exc
                exc = None
                nxt = current.throw(curr_exc)
            else:
                nxt = current.send(val)
                val = None
            if hasattr(nxt, "send") and hasattr(nxt, "throw"):
                stack.append(nxt)
            else:
                val = nxt
        except StopIteration as e:
            stack.pop()
            val = e.value
            exc = None
        except Exception as e:
            stack.pop()
            exc = e
            val = None
    if exc:
        raise exc
    return val


@pytest.fixture
def mock_repo():
    return MagicMock()


@pytest.fixture
def mock_audit():
    audit = MagicMock()
    audit.record = MagicMock(side_effect=lambda *a, **k: async_return(None))
    return audit


@pytest.fixture
def service(mock_repo, mock_audit):
    return ResponseActionService(repository=mock_repo, audit_logs=mock_audit)


@pytest.fixture
def analyst_user():
    return User(
        id=uuid.uuid4(),
        email="analyst@aegis-x.io",
        full_name="SOC Analyst",
        role="analyst",
        is_active=True,
    )


@pytest.fixture
def admin_user():
    return User(
        id=uuid.uuid4(),
        email="admin@aegis-x.io",
        full_name="SOC Admin",
        role="admin",
        is_active=True,
    )


def test_create_action(service, mock_repo):
    payload = ResponseActionCreate(
        alert_id=uuid.uuid4(),
        action_type="isolate_host",
        target="192.168.1.100",
        required_role="admin",
        blast_radius="HIGH",
        description="Isolate endpoint from local network",
        rationale="Active lateral movement detected",
        rollback_plan="Re-enable network adapter via EDR",
    )
    
    mock_action = ResponseAction(
        id=uuid.uuid4(),
        alert_id=payload.alert_id,
        action_type=payload.action_type,
        target=payload.target,
        status="pending_approval",
        required_role=payload.required_role,
        blast_radius=payload.blast_radius,
        description=payload.description,
        rationale=payload.rationale,
        rollback_plan=payload.rollback_plan,
        created_by="ai_response_agent",
    )
    mock_repo.create = MagicMock(side_effect=lambda **k: async_return(mock_action))

    result = drive_coro(service.create_action(payload))
    assert result.status == "pending_approval"
    assert result.action_type == "isolate_host"
    mock_repo.create.assert_called_once()


def test_analyst_cannot_approve_high_blast_radius_action(service, mock_repo, analyst_user):
    action_id = uuid.uuid4()
    mock_action = ResponseAction(
        id=action_id,
        alert_id=uuid.uuid4(),
        action_type="isolate_host",
        target="192.168.1.100",
        status="pending_approval",
        required_role="admin",
        blast_radius="HIGH",
    )
    mock_repo.get_by_id = MagicMock(side_effect=lambda *a: async_return(mock_action))

    with pytest.raises(HTTPException) as exc_info:
        drive_coro(service.decide_action(action_id, decision="approved", current_user=analyst_user))
    
    assert exc_info.value.status_code == 403
    assert "Insufficient permissions" in exc_info.value.detail


def test_admin_can_approve_high_blast_radius_action(service, mock_repo, mock_audit, admin_user):
    action_id = uuid.uuid4()
    mock_action = ResponseAction(
        id=action_id,
        alert_id=uuid.uuid4(),
        action_type="isolate_host",
        target="192.168.1.100",
        status="pending_approval",
        required_role="admin",
        blast_radius="HIGH",
    )
    mock_repo.get_by_id = MagicMock(side_effect=lambda *a: async_return(mock_action))
    mock_repo.update_status = MagicMock(side_effect=lambda *a, **k: async_return(mock_action))

    drive_coro(service.decide_action(action_id, decision="approved", current_user=admin_user, notes="Confirmed threat"))
    
    assert mock_repo.update_status.call_count == 2
    mock_audit.record.assert_called_once()
    assert mock_audit.record.call_args[1]["action"] == "response_action.executed"


def test_analyst_can_approve_low_blast_radius_action(service, mock_repo, mock_audit, analyst_user):
    action_id = uuid.uuid4()
    mock_action = ResponseAction(
        id=action_id,
        alert_id=uuid.uuid4(),
        action_type="block_ip",
        target="203.0.113.5",
        status="pending_approval",
        required_role="analyst",
        blast_radius="LOW",
    )
    mock_repo.get_by_id = MagicMock(side_effect=lambda *a: async_return(mock_action))
    mock_repo.update_status = MagicMock(side_effect=lambda *a, **k: async_return(mock_action))

    drive_coro(service.decide_action(action_id, decision="approved", current_user=analyst_user))
    assert mock_repo.update_status.call_count == 2
    mock_audit.record.assert_called_once()


def test_reject_action(service, mock_repo, mock_audit, analyst_user):
    action_id = uuid.uuid4()
    mock_action = ResponseAction(
        id=action_id,
        alert_id=uuid.uuid4(),
        action_type="block_ip",
        target="203.0.113.5",
        status="pending_approval",
        required_role="analyst",
        blast_radius="LOW",
    )
    mock_repo.get_by_id = MagicMock(side_effect=lambda *a: async_return(mock_action))
    mock_repo.update_status = MagicMock(side_effect=lambda *a, **k: async_return(mock_action))

    drive_coro(service.decide_action(action_id, decision="rejected", current_user=analyst_user, notes="False positive IP"))
    
    assert mock_repo.update_status.call_count == 1
    mock_audit.record.assert_called_once()
    assert mock_audit.record.call_args[1]["action"] == "response_action.rejected"


def test_decide_nonexistent_action_raises_404(service, mock_repo, admin_user):
    mock_repo.get_by_id = MagicMock(side_effect=lambda *a: async_return(None))
    with pytest.raises(HTTPException) as exc_info:
        drive_coro(service.decide_action(uuid.uuid4(), decision="approved", current_user=admin_user))
    assert exc_info.value.status_code == 404


def test_decide_already_executed_action_raises_400(service, mock_repo, admin_user):
    action_id = uuid.uuid4()
    mock_action = ResponseAction(
        id=action_id,
        alert_id=uuid.uuid4(),
        action_type="isolate_host",
        target="192.168.1.100",
        status="executed",
        required_role="admin",
        blast_radius="HIGH",
    )
    mock_repo.get_by_id = MagicMock(side_effect=lambda *a: async_return(mock_action))
    with pytest.raises(HTTPException) as exc_info:
        drive_coro(service.decide_action(action_id, decision="approved", current_user=admin_user))
    assert exc_info.value.status_code == 400
