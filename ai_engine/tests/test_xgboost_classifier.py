"""
Tests for ai_engine.models.xgboost_classifier.model.
"""

import numpy as np
import pandas as pd
import pytest

from ai_engine.models.xgboost_classifier.model import XGBoostAttackClassifier


def _separable_classification_data(n_per_class=50, seed=1):
    """Three well-separated clusters -> easy, fast-to-fit classification task."""
    rng = np.random.default_rng(seed)
    frames = []
    labels = []
    for class_id, center in enumerate([-10, 0, 10]):
        frames.append(pd.DataFrame({"a": rng.normal(center, 1, n_per_class), "b": rng.normal(center, 1, n_per_class)}))
        labels += [class_id] * n_per_class
    X = pd.concat(frames, ignore_index=True)
    y = pd.Series(labels)
    return X, y


def test_fit_then_predict_returns_expected_shapes():
    X, y = _separable_classification_data()
    clf = XGBoostAttackClassifier(n_estimators=20)
    clf.fit(X, y)
    result = clf.predict(X)

    assert len(result.predicted_class_ids) == len(X)
    assert len(result.confidences) == len(X)
    assert result.probabilities.shape == (len(X), 3)


def test_well_separated_classes_are_classified_correctly():
    X, y = _separable_classification_data()
    clf = XGBoostAttackClassifier(n_estimators=20)
    clf.fit(X, y)
    result = clf.predict(X)

    accuracy = (result.predicted_class_ids == y.to_numpy()).mean()
    assert accuracy > 0.95  # trivially separable data should be nearly perfect


def test_confidences_are_between_0_and_1():
    X, y = _separable_classification_data()
    clf = XGBoostAttackClassifier(n_estimators=20)
    clf.fit(X, y)
    result = clf.predict(X)

    assert (result.confidences >= 0).all()
    assert (result.confidences <= 1).all()


def test_predict_before_fit_raises():
    clf = XGBoostAttackClassifier()
    X, _ = _separable_classification_data()
    with pytest.raises(RuntimeError):
        clf.predict(X)


def test_predict_one_returns_expected_types():
    X, y = _separable_classification_data()
    clf = XGBoostAttackClassifier(n_estimators=20)
    clf.fit(X, y)

    class_id, confidence, probabilities = clf.predict_one(X.iloc[0])
    assert isinstance(class_id, int)
    assert isinstance(confidence, float)
    assert len(probabilities) == 3


def test_save_and_load_round_trip(tmp_path):
    X, y = _separable_classification_data()
    clf = XGBoostAttackClassifier(n_estimators=20)
    clf.fit(X, y)

    path = tmp_path / "xgb.joblib"
    clf.save(path)
    reloaded = XGBoostAttackClassifier.load(path)

    original = clf.predict(X).predicted_class_ids
    reloaded_pred = reloaded.predict(X).predicted_class_ids
    assert np.array_equal(original, reloaded_pred)
