"""
Centralized application configuration.

All environment-dependent values live here and ONLY here. Nothing else in the
codebase should call os.environ / os.getenv directly — import `settings`
instead. This keeps configuration testable (override `settings` in tests)
and makes it obvious, in one file, what the app depends on from its
environment.
"""

from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- App ---
    APP_NAME: str = "AEGIS-X"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # --- Security / JWT ---
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # --- Database ---
    DATABASE_URL: str
    DATABASE_URL_SYNC: str | None = None

    # --- CORS ---
    CORS_ORIGINS: str = "http://localhost:5173"

    # --- Logging ---
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @field_validator("CORS_ORIGINS")
    @classmethod
    def validate_cors_origins(cls, v: str) -> str:
        # Stored as a raw comma-separated string in env; exposed as a list
        # via the `cors_origins_list` property below. Keeping the raw string
        # here avoids pydantic-settings' JSON-parsing quirks with List[str].
        return v

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    """
    Cached settings accessor. Using a function (rather than a bare module-level
    instance) makes it straightforward to override settings in tests via
    dependency_overrides or monkeypatching `get_settings`.
    """
    return Settings()


settings = get_settings()
