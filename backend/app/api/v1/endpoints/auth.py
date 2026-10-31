"""
Auth endpoints.

These are the first endpoints the Lovable frontend will integrate against:
register, login, refresh, and "who am I". The response_model on each route
is what drives the OpenAPI schema Lovable (or a human) reads to generate
matching TypeScript types.
"""

from fastapi import APIRouter, Depends, Request, status

from app.dependencies.auth import get_auth_service, get_current_user
from app.models.user import User
from app.schemas.common import ErrorResponse
from app.schemas.user import RefreshRequest, TokenResponse, UserCreate, UserLogin, UserResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Auth"])

COMMON_ERROR_RESPONSES = {
    401: {"model": ErrorResponse},
    409: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
}


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    responses=COMMON_ERROR_RESPONSES,
    summary="Register a new SOC analyst account",
)
async def register(
    payload: UserCreate, request: Request, auth_service: AuthService = Depends(get_auth_service)
) -> User:
    return await auth_service.register(payload, ip_address=request.client.host if request.client else None)


@router.post(
    "/login",
    response_model=TokenResponse,
    responses=COMMON_ERROR_RESPONSES,
    summary="Authenticate and receive access + refresh tokens",
)
async def login(
    payload: UserLogin, request: Request, auth_service: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    user = await auth_service.authenticate(payload, ip_address=request.client.host if request.client else None)
    return auth_service.issue_tokens(user)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    responses=COMMON_ERROR_RESPONSES,
    summary="Exchange a refresh token for a new access token",
)
async def refresh(payload: RefreshRequest, auth_service: AuthService = Depends(get_auth_service)) -> TokenResponse:
    return await auth_service.refresh_access_token(payload.refresh_token)


@router.get(
    "/me",
    response_model=UserResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Get the currently authenticated user",
)
async def read_current_user(current_user: User = Depends(get_current_user)) -> User:
    return current_user
