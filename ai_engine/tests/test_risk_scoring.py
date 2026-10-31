"""
Tests for ai_engine.inference.risk_scoring.
"""

from ai_engine.inference.risk_scoring import compute_risk_score, score_to_severity


def test_confident_normal_traffic_gets_low_risk_score():
    """
    Regression test for the bug where high confidence on "normal" traffic
    contributed a flat ~25 points toward risk, pushing confidently-benign
    traffic into "medium" severity. Confidence should NOT count as a
    risk-increasing signal for the normal class.
    """
    score = compute_risk_score(anomaly_score=0.1, confidence=1.0, attack_type="normal")
    assert score < 25  # should land in "low"
    assert score_to_severity(score) == "low"


def test_high_confidence_ddos_gets_critical_severity():
    score = compute_risk_score(anomaly_score=0.9, confidence=0.95, attack_type="ddos")
    assert score >= 80
    assert score_to_severity(score) == "critical"


def test_low_severity_attack_type_scores_lower_than_high_severity_at_same_confidence():
    port_scan_score = compute_risk_score(anomaly_score=0.5, confidence=0.9, attack_type="port_scan")
    ddos_score = compute_risk_score(anomaly_score=0.5, confidence=0.9, attack_type="ddos")
    assert ddos_score > port_scan_score


def test_normal_traffic_risk_still_reflects_high_anomaly_score():
    """
    Even when classified 'normal', a high Isolation Forest anomaly score
    should still push risk up somewhat — this is the "possible novel
    attack XGBoost wasn't trained to recognize" signal, and it must not
    get zeroed out entirely.
    """
    low_anomaly = compute_risk_score(anomaly_score=0.05, confidence=1.0, attack_type="normal")
    high_anomaly = compute_risk_score(anomaly_score=0.95, confidence=1.0, attack_type="normal")
    assert high_anomaly > low_anomaly


def test_score_is_always_within_0_to_100():
    for anomaly in (0.0, 0.5, 1.0):
        for confidence in (0.0, 0.5, 1.0):
            for attack_type in ("normal", "ddos", "port_scan", "unknown_type"):
                score = compute_risk_score(anomaly, confidence, attack_type)
                assert 0 <= score <= 100


def test_score_to_severity_boundaries():
    assert score_to_severity(0) == "low"
    assert score_to_severity(24.9) == "low"
    assert score_to_severity(25) == "medium"
    assert score_to_severity(54.9) == "medium"
    assert score_to_severity(55) == "high"
    assert score_to_severity(79.9) == "high"
    assert score_to_severity(80) == "critical"
    assert score_to_severity(100) == "critical"


def test_unknown_attack_type_falls_back_to_other_severity_weight():
    known_other_score = compute_risk_score(0.5, 0.8, "other")
    unknown_score = compute_risk_score(0.5, 0.8, "some_new_type_not_in_table")
    assert known_other_score == unknown_score
