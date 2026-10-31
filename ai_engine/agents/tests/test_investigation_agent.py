"""
Tests for ai_engine.agents.investigation_agent.
"""

from ai_engine.agents.investigation_agent import InvestigationAgent


def test_no_related_events_gives_isolated_hypothesis():
    agent = InvestigationAgent()
    state = {"detection": {"attack_type": "ddos", "title": "DDoS Alert"}, "related_events": []}

    result = agent.run(state)

    assert result["investigation"]["correlated_event_count"] == 0
    assert "Isolated" in result["investigation"]["root_cause_hypothesis"]


def test_correlates_events_with_same_attack_type():
    agent = InvestigationAgent()
    state = {
        "detection": {"attack_type": "port_scan", "title": "Port Scan Alert"},
        "related_events": [
            {"attack_type": "port_scan", "detected_at": "2026-01-01T10:00:00", "severity": "low"},
            {"attack_type": "ddos", "detected_at": "2026-01-01T10:01:00", "severity": "high"},  # different type
        ],
    }

    result = agent.run(state)

    assert result["investigation"]["correlated_event_count"] == 1


def test_correlates_events_with_same_source_ip():
    agent = InvestigationAgent()
    state = {
        "detection": {"attack_type": "brute_force", "source_ip": "10.0.0.5", "title": "Brute Force Alert"},
        "related_events": [
            {"attack_type": "port_scan", "source_ip": "10.0.0.5", "detected_at": "t1", "severity": "low"},
        ],
    }

    result = agent.run(state)

    assert result["investigation"]["correlated_event_count"] == 1


def test_many_correlated_events_gives_campaign_hypothesis():
    agent = InvestigationAgent()
    related = [{"attack_type": "ddos", "detected_at": f"t{i}", "severity": "high"} for i in range(4)]
    state = {"detection": {"attack_type": "ddos", "title": "DDoS Alert"}, "related_events": related}

    result = agent.run(state)

    assert result["investigation"]["correlated_event_count"] == 4
    assert "sustained" in result["investigation"]["root_cause_hypothesis"].lower()


def test_normal_traffic_gives_no_attack_pattern_hypothesis():
    agent = InvestigationAgent()
    state = {"detection": {"attack_type": "normal", "title": "Normal"}, "related_events": []}

    result = agent.run(state)

    assert "no attack pattern" in result["investigation"]["root_cause_hypothesis"].lower()


def test_timeline_includes_current_detection():
    agent = InvestigationAgent()
    state = {"detection": {"attack_type": "ddos", "title": "DDoS Alert"}, "related_events": []}

    result = agent.run(state)

    assert any("this detection" in entry for entry in result["investigation"]["timeline"])
