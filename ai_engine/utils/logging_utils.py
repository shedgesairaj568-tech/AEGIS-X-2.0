"""
Lightweight logging helper for the ai_engine package.

Deliberately independent from backend/app/core/logging.py — the AI engine
is a separate deployable unit (see the architecture rationale in the
root README) and shouldn't import from the backend package just to log a
message.
"""

import logging
import sys

_CONFIGURED = False


def _configure_once() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    _configure_once()
    return logging.getLogger(name)
