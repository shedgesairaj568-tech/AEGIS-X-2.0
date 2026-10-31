"""
Auth business logic.

Deliberately has no FastAPI imports (no Request, no HTTPException) — it
raises the framework-agnostic exceptions from app.core.exceptions, which
the middleware translates into HTTP responses. This keeps the logic
reusable (e.g. from a CLI, a background job, or a test) and easy to unit
test without spinning up the ASGI app.
"""

import uuid

from app.core.exceptions import InvalidCredentialsError, UserAlreadyExistsError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.core.security import TokenError
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.user import TokenResponse, UserCreate, UserLogin
from app.services.audit_log_service import AuditLogService


class AuthService:
    def __init__(self, user_repository: UserRepository, audit_log_service: AuditLogService | None = None):
        self._users = user_repository
        self._audit = audit_log_service

    async def register(self, payload: UserCreate, *, ip_address: str | None = None) -> User:
        existing = await self._users.get_by_email(payload.email)
        if existing is not None:
            raise UserAlreadyExistsError(f"A user with email '{payload.email}' already exists.")

        user = await self._users.create(
            email=payload.email,
            full_name=payload.full_name,
            hashed_password=hash_password(payload.password),
        )
        if self._audit:
            await self._audit.record(
                action="user.register",
                user_id=user.id,
                resource_type="user",
                resource_id=str(user.id),
                ip_address=ip_address,
            )
        return user

    async def authenticate(self, payload: UserLogin, *, ip_address: str | None = None) -> User:
        user = await self._users.get_by_email(payload.email)
        if user is None or not verify_password(payload.password, user.hashed_password):
            if self._audit:
                await self._audit.record(
                    action="user.login_failed",
                    resource_type="user",
                    log_metadata={"email": payload.email},
                    ip_address=ip_address,
                )
            raise InvalidCredentialsError()
        if not user.is_active:
            raise InvalidCredentialsError("This account has been deactivated.")

        if self._audit:
            await self._audit.record(
                action="user.login",
                user_id=user.id,
                resource_type="user",
                resource_id=str(user.id),
                ip_address=ip_address,
            )
        return user

    def issue_tokens(self, user: User) -> TokenResponse:
        subject = str(user.id)
        return TokenResponse(
            access_token=create_access_token(subject, extra_claims={"role": user.role}),
            refresh_token=create_refresh_token(subject),
        )

    async def refresh_access_token(self, refresh_token: str) -> TokenResponse:
        try:
            payload = decode_token(refresh_token, expected_type="refresh")
        except TokenError as exc:
            raise InvalidCredentialsError("Invalid or expired refresh token.") from exc

        try:
            user_id = uuid.UUID(payload["sub"])
        except (KeyError, ValueError) as exc:
            raise InvalidCredentialsError("Malformed token subject.") from exc

        user = await self._users.get_by_id(user_id)
        if user is None or not user.is_active:
            raise InvalidCredentialsError("User no longer exists or is inactive.")

        return self.issue_tokens(user)
