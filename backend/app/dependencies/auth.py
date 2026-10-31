"""
FastAPI dependency wiring for auth: DB session -> repository -> service,
and the `get_current_user` dependency used to protect endpoints.
"""

import uuid

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.exceptions import UnauthorizedError
from app.core.security import TokenError, decode_token
from app.models.user import User
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.user_repository import UserRepository
from app.services.audit_log_service import AuditLogService
from app.services.auth_service import AuthService

# HTTPBearer (rather than OAuth2PasswordBearer) gives Swagger UI a single
# "paste your token" field in the Authorize dialog, matching our actual
# JSON-based login endpoint. OAuth2PasswordBearer renders a username/
# password/client_id form that expects an OAuth2 form-encoded token
# endpoint, which doesn't match /api/v1/auth/login's JSON body.
bearer_scheme = HTTPBearer(auto_error=False)


def get_user_repository(db: AsyncSession = Depends(get_db_session)) -> UserRepository:
    return UserRepository(db)


def get_audit_log_repository(db: AsyncSession = Depends(get_db_session)) -> AuditLogRepository:
    return AuditLogRepository(db)


def get_audit_log_service(
    audit_log_repo: AuditLogRepository = Depends(get_audit_log_repository),
) -> AuditLogService:
    return AuditLogService(audit_log_repo)


def get_auth_service(
    user_repo: UserRepository = Depends(get_user_repository),
    audit_log_service: AuditLogService = Depends(get_audit_log_service),
) -> AuthService:
    return AuthService(user_repo, audit_log_service)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    user_repo: UserRepository = Depends(get_user_repository),
) -> User:
    if credentials is None:
        raise UnauthorizedError("Missing bearer token.")

    token = credentials.credentials

    try:
        payload = decode_token(token, expected_type="access")
    except TokenError as exc:
        raise UnauthorizedError(str(exc)) from exc

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError) as exc:
        raise UnauthorizedError("Malformed token subject.") from exc

    user = await user_repo.get_by_id(user_id)
    if user is None or not user.is_active:
        raise UnauthorizedError("User no longer exists or is inactive.")

    return user


def require_role(*allowed_roles: str):
    """
    Dependency factory for role-gated endpoints, e.g.:
        @router.get("/admin-only", dependencies=[Depends(require_role("admin"))])
    """
    from app.core.exceptions import ForbiddenError

    async def _check(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise ForbiddenError(f"Requires one of roles: {', '.join(allowed_roles)}")
        return user

    return _check