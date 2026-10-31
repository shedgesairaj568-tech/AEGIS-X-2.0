"""
Tests for ai_engine.agents.threat_detection_agent.
"""

from unittest.mock import MagicMock

from ai_engine.agents.threat_detection_agent import ThreatDetectionAgent
from ai_engine.inference.detection_service import DetectionOutput


def _fake_detection_output(**overrides) -> DetectionOutput:
    defaults = dict(
        title="Test Alert",
        source="network_flow",
        attack_type="ddos",
        severity="critical",
        anomaly_score=0.9,
        risk_score=90.0,
        confidence=0.95,
        mitre_technique_id="T1498",
        mitre_technique_name="Network Denial of Service",
        explanation="Flagged due to high packet rate.",
        raw_event={},
        is_anomaly=True,
    )
    defaults.update(overrides)
    return DetectionOutput(**defaults)


def test_run_populates_detection_state_from_service_output():
    mock_service = MagicMock()
    mock_service.detect.return_value = _fake_detection_output()

    agent = ThreatDetectionAgent(mock_service)
    result = agent.run({"raw_features": {"a": 1.0}})

    assert result["detection"]["attack_type"] == "ddos"
    assert result["detection"]["severity"] == "critical"
    assert result["detection"]["mitre_technique_id"] == "T1498"


def test_run_passes_raw_features_to_service():
    mock_service = MagicMock()
    mock_service.detect.return_value = _fake_detection_output()

    agent = ThreatDetectionAgent(mock_service)
    features = {"Flow Duration": 123.0}
    agent.run({"raw_features": features})

    mock_service.detect.assert_called_once()
    call_args = mock_service.detect.call_args
    assert call_args[0][0] == features


def test_is_anomaly_passes_through_true_from_detection_output():
    mock_service = MagicMock()
    mock_service.detect.return_value = _fake_detection_output(is_anomaly=True)

    agent = ThreatDetectionAgent(mock_service)
    result = agent.run({"raw_features": {}})

    assert result["detection"]["is_anomaly"] is True


def test_is_anomaly_passes_through_false_from_detection_output():
    mock_service = MagicMock()
    mock_service.detect.return_value = _fake_detection_output(is_anomaly=False, attack_type="normal")

    agent = ThreatDetectionAgent(mock_service)
    result = agent.run({"raw_features": {}})

    assert result["detection"]["is_anomaly"] is False


def test_is_anomaly_reflects_isolation_forest_decision_not_a_score_threshold():
    """
    Regression test for a real bug: the agent used to recompute
    is_anomaly as `anomaly_score >= 0.5` independently of what
    DetectionService/IsolationForest actually decided — producing
    contradictions like a "confidently normal" routing decision on a flow
    whose title said "Anomalous traffic". The agent must now trust
    DetectionOutput.is_anomaly directly, even when it disagrees with a
    naive score-threshold guess.
    """
    mock_service = MagicMock()
    # A case where the real IsolationForest flagged this anomalous (True)
    # despite a normalized anomaly_score that a naive >=0.5 threshold
    # would have called "not anomalous".
    mock_service.detect.return_value = _fake_detection_output(
        is_anomaly=True, anomaly_score=0.4384, attack_type="normal"
    )

    agent = ThreatDetectionAgent(mock_service)
    result = agent.run({"raw_features": {}})

    assert result["detection"]["is_anomaly"] is True
