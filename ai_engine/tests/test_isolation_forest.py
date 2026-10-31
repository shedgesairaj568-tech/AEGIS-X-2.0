"""
Tests for ai_engine.models.isolation_forest.model.
"""

import numpy as np
import pandas as pd
import pytest

from ai_engine.models.isolation_forest.model import IsolationForestDetector


def _normal_like_data(n=200, seed=1):
    rng = np.random.default_rng(seed)
    return pd.DataFrame(
        {
            "a": rng.normal(0, 1, n),
            "b": rng.normal(0, 1, n),
            "c": rng.normal(0, 1, n),
        }
    )


def test_fit_then_predict_returns_expected_shapes():
    X = _normal_like_data()
    detector = IsolationForestDetector(contamination=0.1)
    detector.fit(X)
    result = detector.predict(X)

    assert len(result.anomaly_scores) == len(X)
    assert len(result.is_anomaly) == len(X)


def test_anomaly_scores_are_normalized_between_0_and_1():
    X = _normal_like_data()
    detector = IsolationForestDetector(contamination=0.1)
    detector.fit(X)
    result = detector.predict(X)

    assert (result.anomaly_scores >= 0).all()
    assert (result.anomaly_scores <= 1).all()


def test_predict_before_fit_raises():
    detector = IsolationForestDetector()
    with pytest.raises(RuntimeError):
        detector.predict(_normal_like_data())


def test_clear_outlier_gets_higher_anomaly_score_than_typical_point():
    X = _normal_like_data(seed=2)
    detector = IsolationForestDetector(contamination=0.1)
    detector.fit(X)

    typical_point = pd.DataFrame({"a": [0.0], "b": [0.0], "c": [0.0]})
    extreme_outlier = pd.DataFrame({"a": [50.0], "b": [-50.0], "c": [50.0]})

    typical_score = detector.predict(typical_point).anomaly_scores[0]
    outlier_score = detector.predict(extreme_outlier).anomaly_scores[0]

    assert outlier_score > typical_score


def test_predict_one_returns_scalar_tuple():
    X = _normal_like_data()
    detector = IsolationForestDetector(contamination=0.1)
    detector.fit(X)

    score, is_anomaly = detector.predict_one(X.iloc[0])
    assert isinstance(score, float)
    assert isinstance(is_anomaly, bool)


def test_save_and_load_round_trip(tmp_path):
    X = _normal_like_data()
    detector = IsolationForestDetector(contamination=0.1)
    detector.fit(X)

    path = tmp_path / "isolation_forest.joblib"
    detector.save(path)
    reloaded = IsolationForestDetector.load(path)

    original_scores = detector.predict(X).anomaly_scores
    reloaded_scores = reloaded.predict(X).anomaly_scores
    assert np.allclose(original_scores, reloaded_scores)
