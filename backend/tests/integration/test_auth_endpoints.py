"""
Integration tests for /api/v1/auth/* — exercise the full stack (route ->
service -> repository -> in-memory SQLite DB) through the ASGI app.
"""

import pytest

pytestmark = pytest.mark.asyncio

VALID_USER = {
    "email": "analyst@aegis-x.io",
    "full_name": "Jordan Analyst",
    "password": "supersecret123",
}


async def test_health_check(client):
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"


async def test_register_creates_user(client):
    resp = await client.post("/api/v1/auth/register", json=VALID_USER)
    assert resp.status_code == 201
    body = resp.json()
    assert body["email"] == VALID_USER["email"]
    assert body["role"] == "analyst"
    assert "hashed_password" not in body  # response schema must never leak this


async def test_register_duplicate_email_returns_409(client):
    await client.post("/api/v1/auth/register", json=VALID_USER)
    resp = await client.post("/api/v1/auth/register", json=VALID_USER)
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "user_already_exists"


async def test_register_weak_password_returns_422(client):
    payload = {**VALID_USER, "password": "short"}
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 422


async def test_login_with_correct_credentials_returns_tokens(client):
    await client.post("/api/v1/auth/register", json=VALID_USER)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert "access_token" in body
    assert "refresh_token" in body


async def test_login_with_wrong_password_returns_401(client):
    await client.post("/api/v1/auth/register", json=VALID_USER)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": VALID_USER["email"], "password": "wrong-password"},
    )
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "invalid_credentials"


async def test_me_without_token_returns_401(client):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


async def test_me_with_valid_token_returns_profile(client):
    await client.post("/api/v1/auth/register", json=VALID_USER)
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    access_token = login_resp.json()["access_token"]

    resp = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["email"] == VALID_USER["email"]


async def test_refresh_returns_new_access_token(client):
    await client.post("/api/v1/auth/register", json=VALID_USER)
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    refresh_token = login_resp.json()["refresh_token"]

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


async def test_refresh_with_access_token_is_rejected(client):
    """An access token must not work as a refresh token (type confusion check)."""
    await client.post("/api/v1/auth/register", json=VALID_USER)
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    access_token = login_resp.json()["access_token"]

    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": access_token})
    assert resp.status_code == 401
