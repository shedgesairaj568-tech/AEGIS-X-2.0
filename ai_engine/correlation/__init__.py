"""
AEGIS-X 2.0 Event Correlation Package.
"""

from ai_engine.correlation.correlation_engine import (
    AttackStage,
    CorrelatedIncident,
    CorrelationEngine,
    TimelineEntry,
)

__all__ = [
    "AttackStage",
    "TimelineEntry",
    "CorrelatedIncident",
    "CorrelationEngine",
]

