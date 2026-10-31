"""
Tests for ai_engine.integration.pipeline_connector.
"""

from unittest.mock import MagicMock

from ai_engine.integration.pipeline_connector import PipelineConnector


def _normal_state():
    return {
        "detection": {
            "title": "Normal traffic",
            "attack_type": "normal",
            "severity": "low",
            "anomaly_score": 0.1,
            "risk_score": 5.0,
            "confidence": 1.0,
            "mitre_technique_id": None,
            "mitre_technique_name": None,
            "explanation": "Nothing unusual.",
        }
    }


def _attack_state():
    return {
        "detection": {
            "title": "Ddos detected",
            "attack_type": "ddos",
            "severity": "critical",
            "anomaly_score": 0.95,
            "risk_score": 94.0,
            "confidence": 0.98,
            "mitre_technique_id": "T1498",
            "mitre_technique_name": "Network Denial of Service",
            "explanation": "High packet rate.",
        },
        "investigation": {"correlated_event_count": 2, "root_cause_hypothesis": "Sustained campaign."},
        "knowledge": {"mitre_attck": [], "cve": [], "security_policies": []},
        "response": {
            "incident_title": "Ddos detected",
            "summary": "DDoS attack detected.",
            "root_cause": "High packet volume.",
            "mitigation": "Enable rate limiting.",
            "generated_by": "template_fallback",
        },
    }


def test_normal_traffic_only_creates_alert_no_report():
    mock_backend = MagicMock()
    mock_backend.create_alert.return_value = {"id": "alert-1"}
    mock_pipeline = MagicMock()
    mock_pipeline.investigate.return_value = _normal_state()

    connector = PipelineConnector(mock_backend, mock_pipeline)
    result = connector.process_flow({"feature_a": 1.0})

    mock_backend.create_alert.assert_called_once()
    mock_backend.create_report.assert_not_called()
    mock_backend.add_history_entry.assert_not_called()
    assert result.was_investigated is False
    assert result.alert_id == "alert-1"


def test_attack_traffic_creates_alert_history_and_report():
    mock_backend = MagicMock()
    mock_backend.create_alert.return_value = {"id": "alert-2"}
    mock_pipeline = MagicMock()
    mock_pipeline.investigate.return_value = _attack_state()

    connector = PipelineConnector(mock_backend, mock_pipeline)
    result = connector.process_flow({"feature_a": 5.0})

    mock_backend.create_alert.assert_called_once()
    mock_backend.add_history_entry.assert_called_once()
    mock_backend.create_report.assert_called_once()
    assert result.was_investigated is True
    assert result.severity == "critical"


def test_alert_payload_includes_detection_fields():
    mock_backend = MagicMock()
    mock_backend.create_alert.return_value = {"id": "alert-3"}
    mock_pipeline = MagicMock()
    mock_pipeline.investigate.return_value = _attack_state()

    connector = PipelineConnector(mock_backend, mock_pipeline)
    connector.process_flow({"feature_a": 5.0}, source_ip="10.0.0.5")

    call_args = mock_backend.create_alert.call_args[0][0]
    assert call_args["attack_type"] == "ddos"
    assert call_args["severity"] == "critical"
    assert call_args["mitre_technique_id"] == "T1498"
    assert call_args["source_ip"] == "10.0.0.5"


def test_report_payload_uses_response_agent_output():
    mock_backend = MagicMock()
    mock_backend.create_alert.return_value = {"id": "alert-4"}
    mock_pipeline = MagicMock()
    mock_pipeline.investigate.return_value = _attack_state()

    connector = PipelineConnector(mock_backend, mock_pipeline)
    connector.process_flow({"feature_a": 5.0})

    report_call_args = mock_backend.create_report.call_args[0]
    assert report_call_args[0] == "alert-4"
    assert report_call_args[1]["summary"] == "DDoS attack detected."
    assert report_call_args[1]["mitigation"] == "Enable rate limiting."


def test_fetches_related_alerts_when_source_ip_given():
    mock_backend = MagicMock()
    mock_backend.get_related_alerts.return_value = [{"attack_type": "ddos", "source_ip": "10.0.0.5"}]
    mock_backend.create_alert.return_value = {"id": "alert-5"}
    mock_pipeline = MagicMock()
    mock_pipeline.investigate.return_value = _attack_state()

    connector = PipelineConnector(mock_backend, mock_pipeline)
    connector.process_flow({"feature_a": 5.0}, source_ip="10.0.0.5")

    mock_backend.get_related_alerts.assert_called_once_with(source_ip="10.0.0.5", limit=20)
    passed_related_events = mock_pipeline.investigate.call_args.kwargs["related_events"]
    assert passed_related_events == [{"attack_type": "ddos", "source_ip": "10.0.0.5"}]


def test_no_related_alert_fetch_without_source_ip():
    mock_backend = MagicMock()
    mock_backend.create_alert.return_value = {"id": "alert-6"}
    mock_pipeline = MagicMock()
    mock_pipeline.investigate.return_value = _normal_state()

    connector = PipelineConnector(mock_backend, mock_pipeline)
    connector.process_flow({"feature_a": 1.0})

    mock_backend.get_related_alerts.assert_not_called()


def test_correlation_lookup_failure_does_not_block_detection():
    """
    Correlation is an enrichment, not a hard dependency — if the related
    alerts lookup fails, the flow should still be detected and recorded.
    """
    mock_backend = MagicMock()
    mock_backend.get_related_alerts.side_effect = Exception("network error")
    mock_backend.create_alert.return_value = {"id": "alert-7"}
    mock_pipeline = MagicMock()
    mock_pipeline.investigate.return_value = _normal_state()

    connector = PipelineConnector(mock_backend, mock_pipeline)
    result = connector.process_flow({"feature_a": 1.0}, source_ip="10.0.0.9")

    assert result.alert_id == "alert-7"
    mock_backend.create_alert.assert_called_once()
