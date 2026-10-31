"""
Tests for ai_engine.integration.backend_client.

Uses mocked `requests` calls — no real server needed for these; the true
end-to-end proof (real server, real HTTP) is in
test_full_stack_integration.py.
"""

from unittest.mock import MagicMock, patch

import pytest

from ai_engine.integration.backend_client import BackendAuthError, BackendClient


def _mock_response(status_code=200, json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    return resp


@patch("ai_engine.integration.backend_client.requests.post")
def test_login_success_stores_token(mock_post):
    mock_post.return_value = _mock_response(200, {"access_token": "abc123", "refresh_token": "xyz"})

    client = BackendClient("http://localhost:8000", "user@test.io", "pw")
    client._login()

    assert client._access_token == "abc123"


@patch("ai_engine.integration.backend_client.requests.post")
def test_login_failure_raises_backend_auth_error(mock_post):
    mock_post.return_value = _mock_response(401, {})

    client = BackendClient("http://localhost:8000", "user@test.io", "wrongpw")
    with pytest.raises(BackendAuthError):
        client._login()


@patch("ai_engine.integration.backend_client.requests.request")
@patch("ai_engine.integration.backend_client.requests.post")
def test_create_alert_logs_in_automatically_on_first_call(mock_post, mock_request):
    mock_post.return_value = _mock_response(200, {"access_token": "abc123"})
    mock_request.return_value = _mock_response(201, {"id": "alert-1", "title": "Test"})

    client = BackendClient("http://localhost:8000", "user@test.io", "pw")
    result = client.create_alert({"title": "Test", "source": "network_flow"})

    assert result["id"] == "alert-1"
    mock_post.assert_called_once()  # login happened exactly once


@patch("ai_engine.integration.backend_client.requests.request")
@patch("ai_engine.integration.backend_client.requests.post")
def test_401_triggers_reauth_and_retry(mock_post, mock_request):
    mock_post.return_value = _mock_response(200, {"access_token": "abc123"})
    # First call: 401 (expired token). Second call (after re-login): success.
    mock_request.side_effect = [_mock_response(401, {}), _mock_response(201, {"id": "alert-1"})]

    client = BackendClient("http://localhost:8000", "user@test.io", "pw")
    client._access_token = "expired-token"  # pretend we already had a token

    result = client.create_alert({"title": "Test"})

    assert result["id"] == "alert-1"
    assert mock_request.call_count == 2


@patch("ai_engine.integration.backend_client.requests.request")
@patch("ai_engine.integration.backend_client.requests.post")
def test_get_related_alerts_sends_correct_params(mock_post, mock_request):
    mock_post.return_value = _mock_response(200, {"access_token": "abc123"})
    mock_request.return_value = _mock_response(200, [])

    client = BackendClient("http://localhost:8000", "user@test.io", "pw")
    client.get_related_alerts(attack_type="ddos", source_ip="10.0.0.1", limit=5)

    call_kwargs = mock_request.call_args.kwargs
    assert call_kwargs["params"]["attack_type"] == "ddos"
    assert call_kwargs["params"]["source_ip"] == "10.0.0.1"
    assert call_kwargs["params"]["limit"] == 5


@patch("ai_engine.integration.backend_client.requests.request")
@patch("ai_engine.integration.backend_client.requests.post")
def test_add_history_entry_posts_to_correct_path(mock_post, mock_request):
    mock_post.return_value = _mock_response(200, {"access_token": "abc123"})
    mock_request.return_value = _mock_response(201, {"id": "hist-1"})

    client = BackendClient("http://localhost:8000", "user@test.io", "pw")
    client.add_history_entry("alert-123", event_type="correlation", description="test")

    call_args = mock_request.call_args
    assert "/api/v1/alerts/alert-123/history" in call_args.args[1]


@patch("ai_engine.integration.backend_client.requests.request")
@patch("ai_engine.integration.backend_client.requests.post")
def test_create_report_posts_to_correct_path(mock_post, mock_request):
    mock_post.return_value = _mock_response(200, {"access_token": "abc123"})
    mock_request.return_value = _mock_response(201, {"id": "report-1"})

    client = BackendClient("http://localhost:8000", "user@test.io", "pw")
    client.create_report("alert-123", {"title": "t", "summary": "s"})

    call_args = mock_request.call_args
    assert "/api/v1/alerts/alert-123/reports" in call_args.args[1]
