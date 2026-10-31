"""
Application-wide logging configuration.

Uses stdlib logging with a structured, single-line format so logs are easy
to grep locally and easy to parse if shipped to a log aggregator (ELK,
CloudWatch, etc.) later. Call `configure_logging()` once, at app startup.
"""

import logging
import sys

from app.core.config import settings

LOG_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)


def configure_logging() -> None:
    root_logger = logging.getLogger()
    root_logger.setLevel(settings.LOG_LEVEL.upper())

    # Avoid duplicate handlers if configure_logging() is called more than
    # once (e.g. in tests that re-import the app).
    if root_logger.handlers:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root_logger.addHandler(handler)

    # Quiet down noisy third-party loggers unless we're debugging.
    if not settings.DEBUG:
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
