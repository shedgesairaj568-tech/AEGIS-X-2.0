"""
Lightweight request/response logging middleware.

Logs method, path, status code, and duration for every request. Kept
separate from error_handler.py because this is cross-cutting logging
concern, not error translation — Clean Architecture principle of
separating distinct responsibilities into distinct modules.
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.logging import get_logger

logger = get_logger("aegis.request")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000

        logger.info(
            "%s %s -> %s (%.1fms)",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        return response
