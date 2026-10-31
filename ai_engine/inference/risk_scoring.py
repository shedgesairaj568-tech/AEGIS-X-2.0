"""
Risk scoring.

Combines three signals into the single 0-100 `risk_score` that the
backend's Alert model stores (see backend/app/models/alert.py) and the
dashboard's "Risk Meter" displays:

  1. anomaly_score (0-1, from Isolation Forest) — HOW unusual is this?
  2. classification confidence (0-1, from XGBoost) — how SURE is the
     model about what kind of attack this is? Low confidence means the
     classification itself is shaky, which should temper the risk score
     even if the anomaly score is high.
  3. attack_type severity weight — a DDoS is inherently more dangerous
     than a port scan, independent of how confident/anomalous the
     detection was.

This is a deliberately simple, transparent weighted formula rather than
another trained model — risk scoring needs to be explainable and
auditable (a SOC analyst should be able to understand why a score is
what it is), not a second black box on top of the first two.
"""

# How dangerous each attack type is, independent of detection confidence.
# 0 = benign, 1 = most severe. Used as one of three weighted inputs below.
ATTACK_SEVERITY_WEIGHT: dict[str, float] = {
    "normal": 0.0,
    "port_scan": 0.35,  # often reconnaissance, not yet a breach
    "brute_force": 0.55,
    "web_attack": 0.60,
    "botnet": 0.75,
    "sql_injection": 0.80,
    "other": 0.50,  # unclassified/rare — treat as moderately severe by default
    "ddos": 0.85,
}

# Weights for the three inputs into the final 0-100 score. Sum to 1.0.
ANOMALY_WEIGHT = 0.35
CONFIDENCE_WEIGHT = 0.25
SEVERITY_WEIGHT = 0.40


def compute_risk_score(anomaly_score: float, confidence: float, attack_type: str) -> float:
    """
    Returns a risk score in [0, 100]. Higher = more urgent for a SOC
    analyst to look at.

    For attack_type == "normal", classification confidence is
    deliberately EXCLUDED from the formula: high confidence there means
    "sure this is benign", which should pull risk toward zero, not add
    to it. Confidence only counts as a risk-increasing signal when the
    model actually classified the traffic as some kind of attack. Normal
    traffic's risk score comes from anomaly_score alone — this is what
    lets a genuinely novel/zero-day pattern (flagged unusual by Isolation
    Forest despite XGBoost calling it "normal", since XGBoost can only
    recognize attack types it was trained on) still surface as elevated
    risk instead of being silently zeroed out.
    """
    severity = ATTACK_SEVERITY_WEIGHT.get(attack_type, ATTACK_SEVERITY_WEIGHT["other"])
    effective_confidence = 0.0 if attack_type == "normal" else confidence

    combined = (
        ANOMALY_WEIGHT * anomaly_score
        + CONFIDENCE_WEIGHT * effective_confidence
        + SEVERITY_WEIGHT * severity
    )
    return round(min(max(combined, 0.0), 1.0) * 100, 2)


def score_to_severity(risk_score: float) -> str:
    """
    Maps a numeric risk_score to the backend's AlertSeverity enum
    ("low" | "medium" | "high" | "critical") — see
    backend/app/core/enums.py, which this must stay in sync with.
    """
    if risk_score >= 80:
        return "critical"
    if risk_score >= 55:
        return "high"
    if risk_score >= 25:
        return "medium"
    return "low"
