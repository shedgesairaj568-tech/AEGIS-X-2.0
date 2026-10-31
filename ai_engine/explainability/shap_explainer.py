"""
SHAP explainability for the XGBoost attack classifier.

SHAP (SHapley Additive exPlanations) answers "why did the model predict
this?" for one specific prediction, in terms a human can read — e.g.
"Flow Bytes/s was unusually high, which pushed this toward 'ddos'." It's
based on Shapley values from cooperative game theory: treat each feature
as a "player" contributing to the prediction, and fairly distribute
credit for the final prediction across all the features based on how
much each one moved the outcome, averaged over every possible order the
features could be considered in.

We use shap.TreeExplainer specifically (rather than the slower,
model-agnostic KernelExplainer) because it's exact and fast for
tree-based models like XGBoost — it walks the actual trees rather than
approximating with random sampling, which matters for real-time
inference speed on live alerts.

This is what populates the "reason for prediction" the project spec
calls for under Explainable AI, and feeds the Response Agent (Module 8)
the raw material for writing a human-readable root-cause explanation.
"""

from dataclasses import dataclass

import pandas as pd
import shap

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class FeatureContribution:
    feature: str
    value: float
    shap_value: float  # positive = pushed toward the predicted class, negative = pushed away


class ShapExplainer:
    """Wraps shap.TreeExplainer for the XGBoost attack classifier."""

    def __init__(self, xgboost_model, class_names: list[str]):
        """
        xgboost_model: the underlying trained xgboost.XGBClassifier
        (i.e. `XGBoostAttackClassifier.model`, not the wrapper itself —
        SHAP needs direct access to the tree structure).
        """
        self._explainer = shap.TreeExplainer(xgboost_model)
        self._class_names = class_names

    def explain_one(
        self, x: pd.Series | pd.DataFrame, predicted_class_id: int, top_n: int = 5
    ) -> list[FeatureContribution]:
        """
        Returns the top_n features that most influenced the model toward
        (or away from) the predicted class, for one single row, sorted by
        magnitude of influence (largest absolute impact first).
        """
        X = x.to_frame().T if isinstance(x, pd.Series) else x

        shap_values = self._explainer.shap_values(X)

        # shap_values shape for multi-class XGBoost is either a list of
        # per-class arrays, or a single (n_samples, n_features, n_classes)
        # array depending on the SHAP/XGBoost version — handle both.
        if isinstance(shap_values, list):
            row_values = shap_values[predicted_class_id][0]
        elif shap_values.ndim == 3:
            row_values = shap_values[0, :, predicted_class_id]
        else:
            row_values = shap_values[0]

        feature_names = list(X.columns)
        contributions = [
            FeatureContribution(
                feature=feature_names[i], value=float(X.iloc[0, i]), shap_value=float(row_values[i])
            )
            for i in range(len(feature_names))
        ]
        contributions.sort(key=lambda c: abs(c.shap_value), reverse=True)
        return contributions[:top_n]

    @staticmethod
    def to_human_readable(contributions: list[FeatureContribution]) -> str:
        """
        Turns a list of FeatureContributions into one plain-English
        sentence, e.g.:
        "Flagged mainly due to high Flow Bytes/s and elevated SYN Flag Count."
        """
        if not contributions:
            return "No dominant contributing features identified."

        pushing_toward = [c for c in contributions if c.shap_value > 0]
        if not pushing_toward:
            return "No features strongly pushed toward this classification."

        described = [f"{c.feature} ({c.value:.2f})" for c in pushing_toward[:3]]
        return "Flagged mainly due to: " + ", ".join(described) + "."
