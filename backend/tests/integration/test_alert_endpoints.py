"""
Integration tests for /api/v1/alerts/* — create, list/filter, get, update,
and the nested history/reports endpoints.
"""

import pytest

pytestmark = pytest.mark.asyncio

USER = {
    "email": "analyst@aegis-x.io",
    "full_name": "Jordan Analyst",
    "password": "supersecret123",
}

ALERT_PAYLOAD = {
    "title": "Suspicious brute force attempt",
    "description": "Multiple failed logins from a single source IP",
    "source": "auth_log",
    "attack_type": "brute_force",
    "severity": "high",
    "anomaly_score": 0.92,
    "risk_score": 78.5,
    "confidence": 0.88,
    "source_ip": "203.0.113.42",
    "destination_ip": "10.0.0.5",
    "source_port": 51321,
    "destination_port": 22,
    "protocol": "TCP",
    "mitre_technique_id": "T1110",
    "mitre_technique_name": "Brute Force",
}


async def _auth_headers(client) -> dict:
    await client.post("/api/v1/auth/register", json=USER)
    resp = await client.post(
        "/api/v1/auth/login", json={"email": USER["email"], "password": USER["password"]}
    )
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


async def test_create_alert(client):
    headers = await _auth_headers(client)
    resp = await client.post("/api/v1/alerts", json=ALERT_PAYLOAD, headers=headers)
    assert resp.status_code == 201
    body = resp.json()
    assert body["title"] == ALERT_PAYLOAD["title"]
    assert body["status"] == "open"
    assert body["attack_type"] == "brute_force"


async def test_create_alert_requires_auth(client):
    resp = await client.post("/api/v1/alerts", json=ALERT_PAYLOAD)
    assert resp.status_code == 401


async def test_creating_alert_writes_history_entry(client):
    headers = await _auth_headers(client)
    create_resp = await client.post("/api/v1/alerts", json=ALERT_PAYLOAD, headers=headers)
    alert_id = create_resp.json()["id"]

    history_resp = await client.get(f"/api/v1/alerts/{alert_id}/history", headers=headers)
    assert history_resp.status_code == 200
    history = history_resp.json()
    assert len(history) == 1
    assert history[0]["event_type"] == "detected"


async def test_list_alerts_filters_by_severity(client):
    headers = await _auth_headers(client)
    await client.post("/api/v1/alerts", json=ALERT_PAYLOAD, headers=headers)
    await client.post(
        "/api/v1/alerts", json={**ALERT_PAYLOAD, "title": "Low sev noise", "severity": "low"}, headers=headers
    )

    resp = await client.get("/api/v1/alerts?severity=high", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "high"


async def test_get_alert_by_id(client):
    headers = await _auth_headers(client)
    create_resp = await client.post("/api/v1/alerts", json=ALERT_PAYLOAD, headers=headers)
    alert_id = create_resp.json()["id"]

    resp = await client.get(f"/api/v1/alerts/{alert_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == alert_id


async def test_get_nonexistent_alert_returns_404(client):
    headers = await _auth_headers(client)
    resp = await client.get("/api/v1/alerts/00000000-0000-0000-0000-000000000000", headers=headers)
    assert resp.status_code == 404
    assert resp.json()["error_code"] == "not_found"


async def test_update_alert_status_writes_history(client):
    headers = await _auth_headers(client)
    create_resp = await client.post("/api/v1/alerts", json=ALERT_PAYLOAD, headers=headers)
    alert_id = create_resp.json()["id"]

    update_resp = await client.patch(
        f"/api/v1/alerts/{alert_id}", json={"status": "investigating"}, headers=headers
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "investigating"

    history_resp = await client.get(f"/api/v1/alerts/{alert_id}/history", headers=headers)
    event_types = [h["event_type"] for h in history_resp.json()]
    assert "status_change" in event_types


async def test_add_analyst_note_to_alert(client):
    headers = await _auth_headers(client)
    create_resp = await client.post("/api/v1/alerts", json=ALERT_PAYLOAD, headers=headers)
    alert_id = create_resp.json()["id"]

    note_resp = await client.post(
        f"/api/v1/alerts/{alert_id}/history",
        json={"event_type": "note", "description": "Confirmed with the on-call engineer."},
        headers=headers,
    )
    assert note_resp.status_code == 201
    assert note_resp.json()["event_type"] == "note"


async def test_create_and_list_report_for_alert(client):
    headers = await _auth_headers(client)
    create_resp = await client.post("/api/v1/alerts", json=ALERT_PAYLOAD, headers=headers)
    alert_id = create_resp.json()["id"]

    report_resp = await client.post(
        f"/api/v1/alerts/{alert_id}/reports",
        json={
            "title": "Incident Report: Brute Force Attempt",
            "summary": "Repeated SSH login failures detected and blocked.",
            "root_cause": "Exposed SSH port with weak password policy.",
            "mitigation": "Enable key-based auth, add rate limiting.",
        },
        headers=headers,
    )
    assert report_resp.status_code == 201
    assert report_resp.json()["alert_id"] == alert_id

    list_resp = await client.get(f"/api/v1/alerts/{alert_id}/reports", headers=headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1
