"""
Aggregates all v1 endpoint routers into a single router mounted in main.py.

Adding a new endpoint module (e.g. `alerts.py` in Module 9's integration
work) means: create the router in endpoints/, import it here, include it.
Nothing else changes.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import alerts, audit_logs, auth, health, response_actions, settings

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(alerts.router)
api_router.include_router(response_actions.router)
api_router.include_router(settings.router)
api_router.include_router(audit_logs.router)
