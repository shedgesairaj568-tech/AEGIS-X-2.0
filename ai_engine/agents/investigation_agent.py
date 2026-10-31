"""
Agent 1 — Investigation Agent for AEGIS-X 2.0.

Responsibilities:
- Ingest high-priority threat detections.
- Query and evaluate candidate historical and cross-source events via CorrelationEngine.
- Construct evidence-grounded incident timelines with temporal causality.
- Extract affected entities (source IPs, targeted accounts, host assets).
- Formulate scientific, auditable root cause hypotheses.
"""

from typing import Any

from ai_engine.correlation.correlation_engine import CorrelatedIncident, CorrelationEngine
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


class InvestigationAgent:
    def __init__(self, correlation_engine: CorrelationEngine | None = None):
        self.correlation_engine = correlation_engine or CorrelationEngine()

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        detection = state.get("detection", {})
        related_events = state.get("related_events", [])

        # Run correlation engine
        incident: CorrelatedIncident = self.correlation_engine.correlate(
            focal_alert=detection,
            candidate_events=related_events,
        )

        formatted_timeline = [
            f"{entry.timestamp}: [{entry.stage.value.upper()}] {entry.description} "
            f"(source={entry.source}, entity={entry.entity_key}, severity={entry.severity})"
            for entry in incident.timeline
        ]

        structured_timeline = [
            {
                "timestamp": entry.timestamp,
                "event_id": entry.event_id,
                "source": entry.source,
                "event_type": entry.event_type,
                "stage": entry.stage.value,
                "entity_key": entry.entity_key,
                "description": entry.description,
                "severity": entry.severity,
                "is_focal_event": entry.is_focal_event,
            }
            for entry in incident.timeline
        ]

        logger.info(
            "InvestigationAgent: Correlated %d events | Multi-stage: %s | Confidence: %.2f",
            incident.correlated_event_count,
            incident.is_multi_stage_attack,
            incident.confidence_score,
        )

        return {
            "investigation": {
                "correlated_event_count": incident.correlated_event_count,
                "timeline": formatted_timeline,
                "structured_timeline": structured_timeline,
                "root_cause_hypothesis": incident.evidence_summary,
                "confidence_score": incident.confidence_score,
                "is_multi_stage_attack": incident.is_multi_stage_attack,
                "stages_detected": [s.value for s in incident.stages_detected],
                "primary_attacker_ip": incident.primary_attacker_ip,
                "targeted_users": incident.targeted_users,
                "targeted_assets": incident.targeted_assets,
                "correlation_reasons": incident.correlation_reasons,
            }
        }
