"""
Shared response schemas used across the API.
"""

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    """
    Uniform error shape returned by every endpoint on failure, so the
    frontend can write one error-handling code path instead of one per
    endpoint.
    """
    error_code: str
    message: str


class HealthResponse(BaseModel):
    status: str
    app_name: str
    environment: str
