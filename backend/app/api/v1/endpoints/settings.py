"""
Settings endpoints.

User-scoped settings (e.g. dark mode) are readable/writable by the owner.
System-scoped settings (e.g. global risk threshold) require the "admin" role.
"""

from fastapi import APIRouter, Depends

from app.dependencies.auth import get_current_user, require_role
from app.dependencies.resources import get_setting_service
from app.models.user import User
from app.schemas.setting import SettingResponse, SettingUpsert
from app.services.setting_service import SettingService

router = APIRouter(prefix="/settings", tags=["Settings"])


@router.get("/me", response_model=list[SettingResponse], summary="List the current user's settings")
async def list_my_settings(
    current_user: User = Depends(get_current_user),
    setting_service: SettingService = Depends(get_setting_service),
) -> list:
    return await setting_service.list_settings(scope="user", user_id=current_user.id)


@router.put("/me/{key}", response_model=SettingResponse, summary="Set a value for the current user")
async def upsert_my_setting(
    key: str,
    payload: SettingUpsert,
    current_user: User = Depends(get_current_user),
    setting_service: SettingService = Depends(get_setting_service),
) -> object:
    return await setting_service.upsert_setting(
        scope="user", key=key, value=payload.value, user_id=current_user.id
    )


@router.get(
    "/system",
    response_model=list[SettingResponse],
    dependencies=[Depends(require_role("admin"))],
    summary="List system-wide settings (admin only)",
)
async def list_system_settings(
    setting_service: SettingService = Depends(get_setting_service),
) -> list:
    return await setting_service.list_settings(scope="system", user_id=None)


@router.put(
    "/system/{key}",
    response_model=SettingResponse,
    dependencies=[Depends(require_role("admin"))],
    summary="Set a system-wide setting (admin only)",
)
async def upsert_system_setting(
    key: str,
    payload: SettingUpsert,
    setting_service: SettingService = Depends(get_setting_service),
) -> object:
    return await setting_service.upsert_setting(scope="system", key=key, value=payload.value, user_id=None)
