"""
Tests for ai_engine.agents.knowledge_agent.
"""

from unittest.mock import MagicMock

from ai_engine.agents.knowledge_agent import KnowledgeAgent
from rag.retrieval.retrieval_service import RetrievedDocument


def _fake_doc(doc_id, score=0.5, **payload):
    return RetrievedDocument(doc_id=doc_id, score=score, source="mitre_attck", payload=payload)


def test_run_calls_enrich_alert_with_attack_type():
    mock_service = MagicMock()
    mock_service.enrich_alert.return_value = {"mitre_attck": [], "cve": [], "security_policies": []}

    agent = KnowledgeAgent(mock_service)
    agent.run(
        {
            "detection": {
                "attack_type": "ddos",
                "explanation": "some shap text",
                "mitre_technique_name": "Network Denial of Service",
            }
        }
    )

    call_args = mock_service.enrich_alert.call_args
    assert call_args[0][0] == "ddos"


def test_run_uses_mitre_technique_name_not_raw_shap_explanation():
    """
    Regression test: the query passed to enrich_alert must use the clean
    MITRE technique name for extra context, NOT the raw SHAP explanation
    text (full of noisy ML feature names like "Total Fwd Packets") — this
    was a real bug that caused wrong policy/CVE matches in the fallback
    embedder (see ai_engine/agents/knowledge_agent.py for the fix).
    """
    mock_service = MagicMock()
    mock_service.enrich_alert.return_value = {"mitre_attck": [], "cve": [], "security_policies": []}

    agent = KnowledgeAgent(mock_service)
    agent.run(
        {
            "detection": {
                "attack_type": "ddos",
                "explanation": "Flagged mainly due to: Total Fwd Packets (3.07), Average Packet Size (1.91).",
                "mitre_technique_name": "Network Denial of Service",
            }
        }
    )

    call_args = mock_service.enrich_alert.call_args
    query_context = call_args[0][1]
    assert "Total Fwd Packets" not in query_context
    assert query_context == "Network Denial of Service"


def test_run_converts_retrieved_documents_to_dicts():
    mock_service = MagicMock()
    mock_service.enrich_alert.return_value = {
        "mitre_attck": [_fake_doc("T1498", name="Network Denial of Service")],
        "cve": [],
        "security_policies": [],
    }

    agent = KnowledgeAgent(mock_service)
    result = agent.run({"detection": {"attack_type": "ddos"}})

    assert result["knowledge"]["mitre_attck"][0]["doc_id"] == "T1498"
    assert result["knowledge"]["mitre_attck"][0]["name"] == "Network Denial of Service"


def test_run_handles_missing_mitre_technique_name():
    mock_service = MagicMock()
    mock_service.enrich_alert.return_value = {"mitre_attck": [], "cve": [], "security_policies": []}

    agent = KnowledgeAgent(mock_service)
    # Should not raise even without mitre_technique_name in detection state
    agent.run({"detection": {"attack_type": "normal"}})

    call_args = mock_service.enrich_alert.call_args
    assert call_args[0][1] == ""
