"""
Integration tests for /api/v1/settings/* and /api/v1/audit-logs.
"""

import pytest

pytestmark = pytest.mark.asyncio

USER = {
    "email": "analyst@aegis-x.io",
    "full_name": "Jordan Analyst",
    "password": "supersecret123",
}


async def _auth_headers(client) -> dict:
    await client.post("/api/v1/auth/register", json=USER)
    resp = await client.post(
        "/api/v1/auth/login", json={"email": USER["email"], "password": USER["password"]}
    )
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


async def test_upsert_and_read_own_setting(client):
    headers = await _auth_headers(client)
    resp = await client.put(
        "/api/v1/settings/me/dark_mode", json={"value": {"enabled": True}}, headers=headers
    )
    assert resp.status_code == 200
    assert resp.json()["value"] == {"enabled": True}

    list_resp = await client.get("/api/v1/settings/me", headers=headers)
    assert list_resp.status_code == 200
    keys = [s["key"] for s in list_resp.json()]
    assert "dark_mode" in keys


async def test_upsert_setting_overwrites_existing_value(client):
    headers = await _auth_headers(client)
    await client.put("/api/v1/settings/me/dark_mode", json={"value": {"enabled": True}}, headers=headers)
    resp = await client.put(
        "/api/v1/settings/me/dark_mode", json={"value": {"enabled": False}}, headers=headers
    )
    assert resp.status_code == 200
    assert resp.json()["value"] == {"enabled": False}

    list_resp = await client.get("/api/v1/settings/me", headers=headers)
    dark_mode_entries = [s for s in list_resp.json() if s["key"] == "dark_mode"]
    assert len(dark_mode_entries) == 1  # upsert, not duplicate


async def test_analyst_cannot_read_system_settings(client):
    headers = await _auth_headers(client)
    resp = await client.get("/api/v1/settings/system", headers=headers)
    assert resp.status_code == 403


async def test_analyst_cannot_read_audit_logs(client):
    headers = await _auth_headers(client)
    resp = await client.get("/api/v1/audit-logs", headers=headers)
    assert resp.status_code == 403


async def test_login_and_register_are_audit_logged(client, db_session):
    """
    Indirect check: we can't read /audit-logs as a non-admin, so this test
    verifies the audit rows exist directly via the DB session, proving the
    AuthService -> AuditLogService wiring actually writes rows.
    """
    from sqlalchemy import select

    from app.models.audit_log import AuditLog

    await _auth_headers(client)  # registers + logs in

    result = await db_session.execute(select(AuditLog))
    actions = [row.action for row in result.scalars().all()]
    assert "user.register" in actions
    assert "user.login" in actions
