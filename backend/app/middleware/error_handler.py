"""
Centralized exception handling.

Translates app.core.exceptions.AegisError subclasses (raised by
services/repositories) into the uniform ErrorResponse JSON shape, and
catches anything unexpected so the API never leaks a raw stack trace to
the frontend. Registered once in app/main.py via `register_exception_handlers`.
"""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.exceptions import AegisError
from app.core.logging import get_logger

logger = get_logger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AegisError)
    async def handle_aegis_error(request: Request, exc: AegisError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error_code": exc.error_code, "message": exc.message},
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Flatten pydantic's verbose error list into one readable message
        # while keeping the uniform ErrorResponse shape for the frontend.
        first_error = exc.errors()[0] if exc.errors() else {}
        field = ".".join(str(p) for p in first_error.get("loc", []) if p != "body")
        message = f"{field}: {first_error.get('msg', 'invalid request')}" if field else "Invalid request payload."
        return JSONResponse(
            status_code=422,
            content={"error_code": "validation_error", "message": message},
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"error_code": "internal_error", "message": "An unexpected error occurred."},
        )
