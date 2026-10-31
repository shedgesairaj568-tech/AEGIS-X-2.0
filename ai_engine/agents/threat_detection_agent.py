"""
Threat Detection Agent — Ingestion & Detection Entry Node for AEGIS-X 2.0.

Wraps DetectionService to execute hybrid ML detection, statistical score calibration,
adaptive threat fusion, and dual-mode explainability. Populates detection state for
downstream investigation agents in LangGraph.
"""

from typing import Any

from ai_engine.inference.detection_service import DetectionService
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


class ThreatDetectionAgent:
    def __init__(self, detection_service: DetectionService):
        self._service = detection_service

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        raw_features = state.get("raw_features", {})
        source = state.get("source", "network_flow")

        result = self._service.detect(raw_features, source=source)

        logger.info(
            "ThreatDetectionAgent: attack_type=%s severity=%s calibrated_risk=%.2f is_anomaly=%s",
            result.attack_type,
            result.severity,
            result.risk_score,
            result.is_anomaly,
        )

        return {
            "detection": {
                "title": result.title,
                "source": result.source,
                "attack_type": result.attack_type,
                "severity": result.severity,
                "anomaly_score": result.anomaly_score,
                "risk_score": result.risk_score,
                "confidence": result.confidence,
                "mitre_technique_id": result.mitre_technique_id,
                "mitre_technique_name": result.mitre_technique_name,
                "explanation": result.explanation,
                "is_anomaly": result.is_anomaly,
                "reconstruction_error": result.reconstruction_error,
                "is_ae_anomaly": result.is_ae_anomaly,
                "calibrated_probability": result.calibrated_probability,
                "model_contributions": result.model_contributions,
                "autoencoder_attributions": result.autoencoder_attributions,
                "source_ip": raw_features.get("source_ip"),
                "destination_ip": raw_features.get("destination_ip"),
                "raw_event": raw_features,
            }
        }
