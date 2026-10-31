"""
Tests for ai_engine.agents.response_agent.
"""

from unittest.mock import MagicMock

from ai_engine.agents.response_agent import ResponseAgent


def _base_state(severity="high"):
    return {
        "detection": {
            "title": "DDoS detected",
            "attack_type": "ddos",
            "severity": severity,
            "risk_score": 94.0,
            "anomaly_score": 0.99,
            "confidence": 0.98,
            "explanation": "Flagged due to high packet rate.",
            "mitre_technique_id": "T1498",
            "mitre_technique_name": "Network Denial of Service",
        },
        "investigation": {
            "correlated_event_count": 2,
            "root_cause_hypothesis": "Part of a sustained campaign.",
        },
        "knowledge": {
            "mitre_attck": [{"mitigation": "Deploy rate limiting.", "text": "..."}],
            "cve": [],
            "security_policies": [{"title": "DDoS Response Procedure", "content": "Enable scrubbing."}],
        },
    }


def test_uses_template_fallback_when_llm_not_configured():
    mock_llm = MagicMock()
    mock_llm.is_configured = False

    agent = ResponseAgent(llm_client=mock_llm)
    result = agent.run(_base_state())

    assert result["response"]["generated_by"] == "template_fallback"
    mock_llm.generate.assert_not_called()


def test_template_fallback_includes_mitigation_from_knowledge():
    mock_llm = MagicMock()
    mock_llm.is_configured = False

    agent = ResponseAgent(llm_client=mock_llm)
    result = agent.run(_base_state())

    assert "Deploy rate limiting" in result["response"]["mitigation"]
    assert "DDoS Response Procedure" in result["response"]["mitigation"]


def test_low_severity_uses_template_even_when_llm_configured():
    """Low/medium severity alerts deliberately skip the LLM call by design."""
    mock_llm = MagicMock()
    mock_llm.is_configured = True

    agent = ResponseAgent(llm_client=mock_llm)
    result = agent.run(_base_state(severity="low"))

    assert result["response"]["generated_by"] == "template_fallback"
    mock_llm.generate.assert_not_called()


def test_high_severity_tries_llm_when_configured():
    mock_llm = MagicMock()
    mock_llm.is_configured = True
    mock_llm.generate.return_value = (
        "SUMMARY: A DDoS attack was detected.\n"
        "ROOT_CAUSE: High packet volume from many sources.\n"
        "MITIGATION: Enable rate limiting immediately."
    )

    agent = ResponseAgent(llm_client=mock_llm)
    result = agent.run(_base_state(severity="high"))

    assert result["response"]["generated_by"] == "llm"
    assert result["response"]["summary"] == "A DDoS attack was detected."
    assert result["response"]["mitigation"] == "Enable rate limiting immediately."


def test_falls_back_to_template_when_llm_returns_malformed_response():
    mock_llm = MagicMock()
    mock_llm.is_configured = True
    mock_llm.generate.return_value = "This response does not follow the expected format at all."

    agent = ResponseAgent(llm_client=mock_llm)
    result = agent.run(_base_state(severity="high"))

    assert result["response"]["generated_by"] == "template_fallback"


def test_falls_back_to_template_when_llm_returns_none():
    mock_llm = MagicMock()
    mock_llm.is_configured = True
    mock_llm.generate.return_value = None

    agent = ResponseAgent(llm_client=mock_llm)
    result = agent.run(_base_state(severity="critical"))

    assert result["response"]["generated_by"] == "template_fallback"


def test_response_includes_mitre_reference_in_root_cause():
    mock_llm = MagicMock()
    mock_llm.is_configured = False

    agent = ResponseAgent(llm_client=mock_llm)
    result = agent.run(_base_state())

    assert "T1498" in result["response"]["root_cause"]


def test_missing_knowledge_falls_back_to_escalation_message():
    mock_llm = MagicMock()
    mock_llm.is_configured = False

    state = _base_state()
    state["knowledge"] = {"mitre_attck": [], "cve": [], "security_policies": []}

    agent = ResponseAgent(llm_client=mock_llm)
    result = agent.run(state)

    assert "escalate" in result["response"]["mitigation"].lower()
