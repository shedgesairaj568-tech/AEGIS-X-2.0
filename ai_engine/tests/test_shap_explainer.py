"""
Tests for ai_engine.explainability.shap_explainer.
"""

import numpy as np
import pandas as pd

from ai_engine.explainability.shap_explainer import FeatureContribution, ShapExplainer
from ai_engine.models.xgboost_classifier.model import XGBoostAttackClassifier


def _trained_classifier_and_data():
    rng = np.random.default_rng(1)
    frames, labels = [], []
    for class_id, center in enumerate([-10, 10]):
        frames.append(pd.DataFrame({"a": rng.normal(center, 1, 50), "b": rng.normal(0, 1, 50)}))
        labels += [class_id] * 50
    X = pd.concat(frames, ignore_index=True)
    y = pd.Series(labels)

    clf = XGBoostAttackClassifier(n_estimators=20)
    clf.fit(X, y)
    return clf, X, y


def test_explain_one_returns_feature_contributions():
    clf, X, y = _trained_classifier_and_data()
    explainer = ShapExplainer(clf.model, class_names=["class_0", "class_1"])

    predicted_class, _, _ = clf.predict_one(X.iloc[0])
    contributions = explainer.explain_one(X.iloc[0], predicted_class_id=predicted_class)

    assert len(contributions) > 0
    assert all(isinstance(c, FeatureContribution) for c in contributions)


def test_explain_one_respects_top_n():
    clf, X, y = _trained_classifier_and_data()
    explainer = ShapExplainer(clf.model, class_names=["class_0", "class_1"])

    predicted_class, _, _ = clf.predict_one(X.iloc[0])
    contributions = explainer.explain_one(X.iloc[0], predicted_class_id=predicted_class, top_n=1)

    assert len(contributions) == 1


def test_contributions_sorted_by_absolute_magnitude_descending():
    clf, X, y = _trained_classifier_and_data()
    explainer = ShapExplainer(clf.model, class_names=["class_0", "class_1"])

    predicted_class, _, _ = clf.predict_one(X.iloc[0])
    contributions = explainer.explain_one(X.iloc[0], predicted_class_id=predicted_class, top_n=2)

    magnitudes = [abs(c.shap_value) for c in contributions]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_to_human_readable_handles_empty_list():
    result = ShapExplainer.to_human_readable([])
    assert "No dominant" in result


def test_to_human_readable_produces_sentence_with_feature_names():
    contributions = [
        FeatureContribution(feature="Flow Bytes/s", value=1.5, shap_value=0.8),
        FeatureContribution(feature="SYN Flag Count", value=1.0, shap_value=0.3),
    ]
    result = ShapExplainer.to_human_readable(contributions)
    assert "Flow Bytes/s" in result
    assert "SYN Flag Count" in result
