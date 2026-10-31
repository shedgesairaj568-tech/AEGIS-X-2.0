"""
Pipeline connector — the actual integration point.

Takes a raw network flow, runs it through Module 8's InvestigationPipeline,
and writes the result into the real backend as an actual Alert row (plus
its investigation timeline and incident report, when the full pipeline
ran). This is the piece that makes Modules 6-8 stop being "code that
prints to a console" and start being "a system that populates a real
database a real dashboard can read from."

Correlation note: the Investigation Agent needs `related_events` as part
of the graph's INITIAL state (see ai_engine/agents/state.py) — it can't
be fetched mid-graph, because LangGraph's state is supplied upfront, not
queried lazily node-by-node. So this connector fetches related alerts
from the backend BEFORE running detection, using only `source_ip` (the
one correlation key available before we know the attack_type) — the
Investigation Agent then further narrows those down using attack_type
once detection has run (see InvestigationAgent._correlate).
"""

from dataclasses import dataclass

from ai_engine.agents.graph import InvestigationPipeline
from ai_engine.integration.backend_client import BackendClient
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class ProcessResult:
    alert_id: str | None
    attack_type: str
    severity: str
    risk_score: float
    was_investigated: bool  # False if the router skipped straight to END (confidently normal)
    report_id: str | None = None


class PipelineConnector:
    def __init__(self, backend_client: BackendClient, investigation_pipeline: InvestigationPipeline):
        self._backend = backend_client
        self._pipeline = investigation_pipeline

    def process_flow(
        self, raw_features: dict, source: str = "network_flow", source_ip: str | None = None
    ) -> ProcessResult:
        related_events = []
        if source_ip:
            try:
                related_events = self._backend.get_related_alerts(source_ip=source_ip, limit=20)
            except Exception as exc:
                # Correlation is an enrichment, not a hard dependency — a
                # failed lookup shouldn't stop a real detection from being
                # recorded. Proceed with no related events instead.
                logger.warning("Could not fetch related alerts for correlation (%s); proceeding without them.", exc)

        state = self._pipeline.investigate(raw_features, related_events=related_events)
        detection = state["detection"]

        alert_payload = {
            "title": detection["title"],
            "source": source,
            "attack_type": detection["attack_type"],
            "severity": detection["severity"],
            "anomaly_score": detection["anomaly_score"],
            "risk_score": detection["risk_score"],
            "confidence": detection["confidence"],
            "mitre_technique_id": detection.get("mitre_technique_id"),
            "mitre_technique_name": detection.get("mitre_technique_name"),
            "source_ip": source_ip,
            "raw_event": raw_features,
            "description": detection.get("explanation"),
        }
        created_alert = self._backend.create_alert(alert_payload)
        alert_id = created_alert["id"]
        logger.info(
            "Created alert %s: %s (%s, risk=%.1f)",
            alert_id,
            detection["title"],
            detection["severity"],
            detection["risk_score"],
        )

        was_investigated = "response" in state
        report_id = None

        if was_investigated:
            investigation = state["investigation"]
            response = state["response"]

            # Record the Investigation Agent's correlation findings on the
            # timeline, distinct from the "detected" entry the backend
            # auto-creates on alert creation.
            self._backend.add_history_entry(
                alert_id,
                event_type="correlation",
                description=investigation["root_cause_hypothesis"],
                event_metadata={"correlated_event_count": investigation["correlated_event_count"]},
            )

            self._backend.create_report(
                alert_id,
                {
                    "title": response["incident_title"],
                    "summary": response["summary"],
                    "root_cause": response["root_cause"],
                    "mitigation": response["mitigation"],
                    "generated_by": response["generated_by"],
                },
            )
            report_id = "created"  # backend doesn't echo an id we need beyond confirming success here
            logger.info("Report created for alert %s (generated_by=%s)", alert_id, response["generated_by"])

        return ProcessResult(
            alert_id=alert_id,
            attack_type=detection["attack_type"],
            severity=detection["severity"],
            risk_score=detection["risk_score"],
            was_investigated=was_investigated,
            report_id=report_id,
        )
