"""
Unit tests for ThreatIntelAgent (Agent 2 in AEGIS-X 2.0).
"""

import pytest
from ai_engine.agents.threat_intel_agent import ThreatIntelAgent


def test_threat_intel_maps_known_attack_type():
    """Maps brute_force attack to MITRE ATT&CK Tactic and Technique."""
    agent = ThreatIntelAgent()
    state = {
        "detection": {
            "attack_type": "brute_force",
            "confidence": 0.95,
            "risk_score": 85.0,
            "is_anomaly": True,
        },
        "investigation": {"timeline": ["t1", "t2"], "is_multi_stage_attack": False},
    }

    result = agent.run(state)
    intel = result["threat_intel"]

    assert intel["mitre_tactic_id"] == "TA0006"
    assert intel["mitre_tactic_name"] == "Credential Access"
    assert intel["mitre_technique_id"] == "T1110"
    assert intel["mitre_technique_name"] == "Brute Force"
    assert intel["confidence"] > 0.80
    assert "telemetry_indicators" in intel
    assert len(intel["telemetry_indicators"]) > 0


def test_threat_intel_attribution_guard():
    """Confirms attribution guard strictly prevents unsupported adversary group attribution."""
    agent = ThreatIntelAgent()
    state = {
        "detection": {
            "attack_type": "web_attack",
            "confidence": 0.90,
            "risk_score": 78.0,
            "is_anomaly": False,
        },
        "investigation": {},
    }

    result = agent.run(state)
    intel = result["threat_intel"]

    stmt = intel["attribution_statement"].lower()
    assert "not supported" in stmt
    assert "un-attributed" in stmt or "unattributed" in stmt


def test_threat_intel_unclassified_anomaly():
    """Unclassified anomaly maps to defense evasion / anomalous telemetry without fabrication."""
    agent = ThreatIntelAgent()
    state = {
        "detection": {
            "attack_type": "normal",
            "confidence": 0.40,
            "risk_score": 65.0,
            "is_anomaly": True,  # Anomaly flagged by IF / AE
        },
        "investigation": {},
    }

    result = agent.run(state)
    intel = result["threat_intel"]

    assert intel["mitre_technique_id"] == "T1027"
    assert "anomalous" in intel["attack_pattern"].lower()


def test_threat_intel_benign_traffic():
    """Benign normal traffic returns clean baseline telemetry."""
    agent = ThreatIntelAgent()
    state = {
        "detection": {
            "attack_type": "normal",
            "confidence": 0.99,
            "risk_score": 10.0,
            "is_anomaly": False,
        },
        "investigation": {},
    }

    result = agent.run(state)
    intel = result["threat_intel"]

    assert intel["mitre_technique_id"] is None
    assert intel["confidence"] == 0.0
    assert "normal" in intel["threat_intel_summary"].lower()

