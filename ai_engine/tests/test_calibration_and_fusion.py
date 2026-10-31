"""
Unit and statistical tests for Calibration and AdaptiveThreatFusionEngine (Phase 2).
"""

import numpy as np
import pytest

from ai_engine.inference.adaptive_fusion import AdaptiveThreatFusionEngine
from ai_engine.inference.calibration import IsotonicCalibrator, PlattCalibrator, compute_ece


def test_platt_and_isotonic_calibrator():
    """Verifies that Platt and Isotonic calibrators produce valid, bounded probabilities in [0, 1]."""
    np.random.seed(42)
    raw_scores = np.linspace(-5.0, 5.0, 100)
    # Synthetic ground truth correlated with raw score
    probs = 1.0 / (1.0 + np.exp(-raw_scores))
    y_true = (np.random.rand(100) < probs).astype(int)

    # Platt calibrator
    platt = PlattCalibrator()
    platt.fit(raw_scores, y_true)
    cal_platt = platt.predict_proba(raw_scores)
    assert np.all(cal_platt >= 0.0) and np.all(cal_platt <= 1.0)
    # Platt should be monotonically increasing
    assert np.all(np.diff(cal_platt) >= -1e-7)

    # Isotonic calibrator
    iso = IsotonicCalibrator()
    iso.fit(raw_scores, y_true)
    cal_iso = iso.predict_proba(raw_scores)
    assert np.all(cal_iso >= 0.0) and np.all(cal_iso <= 1.0)
    assert np.all(np.diff(cal_iso) >= -1e-7)


def test_expected_calibration_error():
    """Verifies that ECE calculation correctly measures miscalibration."""
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    # Perfectly calibrated
    y_prob_good = np.array([0.05, 0.10, 0.15, 0.10, 0.85, 0.90, 0.95, 0.90])
    # Severely overconfident / miscalibrated
    y_prob_bad = np.array([0.9, 0.9, 0.9, 0.9, 0.1, 0.1, 0.1, 0.1])

    ece_good, _ = compute_ece(y_true, y_prob_good, n_bins=4)
    ece_bad, _ = compute_ece(y_true, y_prob_bad, n_bins=4)

    assert 0.0 <= ece_good <= 1.0
    assert 0.0 <= ece_bad <= 1.0
    assert ece_good < ece_bad, f"Well-calibrated ECE ({ece_good}) should be lower than bad ECE ({ece_bad})"


def test_adaptive_threat_fusion_engine_fit_and_assess():
    """Verifies simplex weight learning, severity classification, and model contribution breakdown."""
    np.random.seed(42)
    n = 200

    # Simulate validation signals
    y_val = np.random.choice([0, 1], size=n, p=[0.7, 0.3])
    if_scores = np.where(y_val == 1, np.random.uniform(0.6, 1.0, n), np.random.uniform(0.1, 0.5, n))
    ae_errors = np.where(y_val == 1, np.random.uniform(0.5, 2.0, n), np.random.uniform(0.01, 0.3, n))
    xgb_confs = np.where(y_val == 1, np.random.uniform(0.8, 1.0, n), np.random.uniform(0.0, 0.4, n))

    engine = AdaptiveThreatFusionEngine(source_aware=True)
    engine.fit_calibrators(if_scores, ae_errors, xgb_confs, y_val)

    assert engine.is_calibrated
    assert "xgboost" in engine.weights
    assert "autoencoder" in engine.weights
    assert "isolation_forest" in engine.weights

    total_weight = sum(engine.weights.values())
    assert pytest.approx(total_weight, 1e-2) == 1.0, "Weights must sum to 1.0 (simplex constraint)"

    # Test threat assessment for a clear attack
    res_attack = engine.assess_threat(
        if_anomaly_score=0.95,
        ae_recon_error=1.8,
        xgb_confidence=0.98,
        attack_type="ddos",
        source="network_flow",
    )

    assert 0 <= res_attack.risk_score <= 100
    assert res_attack.severity in ("critical", "high")
    assert 0.0 <= res_attack.calibrated_probability <= 1.0
    assert "xgboost" in res_attack.model_contributions

    # Model contributions should sum to ~100%
    contrib_sum = sum(res_attack.model_contributions.values())
    assert pytest.approx(contrib_sum, 1.0) == 100.0

    # Test threat assessment for a clean normal event
    res_normal = engine.assess_threat(
        if_anomaly_score=0.10,
        ae_recon_error=0.05,
        xgb_confidence=0.99,
        attack_type="normal",
        source="network_flow",
    )
    assert res_normal.risk_score <= 20.0
    assert res_normal.severity in ("info", "low")


def test_adaptive_fusion_severity_thresholds():
    """Verifies that configurable severity bands are respected."""
    engine = AdaptiveThreatFusionEngine()

    assert engine._score_to_severity(10.0) == "info"
    assert engine._score_to_severity(25.0) == "low"
    assert engine._score_to_severity(55.0) == "medium"
    assert engine._score_to_severity(75.0) == "high"
    assert engine._score_to_severity(92.0) == "critical"


def test_adaptive_fusion_save_and_load(tmp_path):
    """Verifies serialization and deserialization of the fusion engine."""
    engine = AdaptiveThreatFusionEngine(source_aware=True)
    engine.weights = {"xgboost": 0.70, "autoencoder": 0.15, "isolation_forest": 0.15}
    engine.is_calibrated = True

    save_path = tmp_path / "fusion_engine.joblib"
    engine.save(save_path)
    assert save_path.exists()

    loaded = AdaptiveThreatFusionEngine.load(save_path)
    assert loaded.is_calibrated
    assert loaded.weights == engine.weights
    assert loaded.source_aware == engine.source_aware
