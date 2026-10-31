"""
AEGIS-X Backend — application entrypoint.

Run locally with:
    uvicorn app.main:app --reload

Swagger UI:  http://localhost:8000/docs
ReDoc:       http://localhost:8000/redoc
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.middleware.error_handler import register_exception_handlers
from app.middleware.request_logging import RequestLoggingMiddleware
from app.db.seed import init_db_and_seed

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "%s starting up | env=%s | debug=%s | cors_origins=%s",
        settings.APP_NAME,
        settings.APP_ENV,
        settings.DEBUG,
        settings.cors_origins_list,
    )
    # Ensure tables exist and seed baseline accounts on startup
    await init_db_and_seed()
    yield
    logger.info("%s shutting down", settings.APP_NAME)


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description=(
            "Autonomous Enterprise Guardian Intelligence System — "
            "AI-driven cybersecurity intelligence for SOC analysts."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # --- CORS: allows the frontend (and local dev servers)
    # to call this API from the browser. Supports explicit env origins
    # plus dynamic regex matching for Vercel and Render deployments. ---
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_origin_regex=r"https://.*\.vercel\.app|https://.*\.onrender\.com|http://localhost:.*|http://127\.0\.0\.1:.*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(RequestLoggingMiddleware)

    register_exception_handlers(app)

    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    return app


app = create_app()
