"""
Unit tests for app.core.security — no DB, no HTTP, pure functions.
"""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-use-only")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import pytest

from app.core.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert hashed != "correct-horse-battery-staple"

    def test_verify_correct_password_succeeds(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("correct-horse-battery-staple", hashed) is True

    def test_verify_wrong_password_fails(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("wrong-password", hashed) is False


class TestJWT:
    def test_access_token_decodes_with_correct_subject(self):
        token = create_access_token(subject="user-123")
        payload = decode_token(token, expected_type="access")
        assert payload["sub"] == "user-123"
        assert payload["type"] == "access"

    def test_access_token_carries_extra_claims(self):
        token = create_access_token(subject="user-123", extra_claims={"role": "admin"})
        payload = decode_token(token)
        assert payload["role"] == "admin"

    def test_refresh_token_has_refresh_type(self):
        token = create_refresh_token(subject="user-123")
        payload = decode_token(token, expected_type="refresh")
        assert payload["type"] == "refresh"

    def test_wrong_expected_type_raises(self):
        token = create_access_token(subject="user-123")
        with pytest.raises(TokenError):
            decode_token(token, expected_type="refresh")

    def test_garbage_token_raises(self):
        with pytest.raises(TokenError):
            decode_token("not-a-real-token")
