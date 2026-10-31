"""
XGBoost — attack type classification.

Where Isolation Forest (isolation_forest/model.py) answers "does this
look unusual at all?" without needing labels, XGBoost answers the next
question: "given labeled examples of each attack type, which specific
type does this flow most resemble?"

XGBoost (eXtreme Gradient Boosting) works by building an ensemble of
decision trees SEQUENTIALLY, where each new tree is trained specifically
to correct the mistakes of the trees built before it (this is "boosting",
as opposed to Isolation Forest and Random Forest, which build trees
independently in parallel). Each tree makes a small, simple decision;
combined, hundreds of small trees vote together into one strong
prediction. It's a standard, well-proven choice for structured/tabular
data like network flow statistics, and is what the project spec calls
for.

Trained WITH labels (supervised), on the full attack_type-encoded
training set from Module 5 — including the "normal" class, so it also
implicitly learns to recognize non-attack traffic as one of its classes.
"""

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class ClassificationResult:
    predicted_class_ids: np.ndarray  # integer class ids (matches the LabelEncoder from Module 5)
    confidences: np.ndarray  # probability of the predicted class, per row
    probabilities: np.ndarray  # full probability distribution over all classes, per row


class XGBoostAttackClassifier:
    """Thin, save/load-able wrapper around xgboost.XGBClassifier."""

    def __init__(
        self,
        n_estimators: int = 200,
        max_depth: int = 6,
        learning_rate: float = 0.1,
        random_state: int = 42,
    ):
        self.model = XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            random_state=random_state,
            n_jobs=-1,
        )
        self._is_fitted = False
        self._feature_columns: list[str] | None = None

    def fit(self, X: pd.DataFrame, y: pd.Series, sample_weight: np.ndarray | None = None) -> "XGBoostAttackClassifier":
        logger.info(
            "Training XGBoost classifier on %d samples, %d features, %d classes.",
            X.shape[0],
            X.shape[1],
            y.nunique(),
        )
        self._feature_columns = list(X.columns)
        self.model.fit(X, y, sample_weight=sample_weight)
        self._is_fitted = True
        logger.info("XGBoost classifier trained.")
        return self

    def predict(self, X: pd.DataFrame) -> ClassificationResult:
        if not self._is_fitted:
            raise RuntimeError("XGBoostAttackClassifier.fit() must be called before predict().")

        probabilities = self.model.predict_proba(X)
        predicted_class_ids = np.argmax(probabilities, axis=1)
        confidences = probabilities[np.arange(len(probabilities)), predicted_class_ids]

        return ClassificationResult(
            predicted_class_ids=predicted_class_ids,
            confidences=confidences,
            probabilities=probabilities,
        )

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Returns predicted class probabilities."""
        if not self._is_fitted:
            raise RuntimeError("XGBoostAttackClassifier.fit() must be called before predict_proba().")
        return self.model.predict_proba(X)

    def predict_one(self, x: pd.Series | pd.DataFrame) -> tuple[int, float, np.ndarray]:
        """Convenience method for scoring a single flow. Returns (class_id, confidence, full_probabilities)."""
        X = x.to_frame().T if isinstance(x, pd.Series) else x
        result = self.predict(X)
        return int(result.predicted_class_ids[0]), float(result.confidences[0]), result.probabilities[0]

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "feature_columns": self._feature_columns,
                "is_fitted": self._is_fitted,
            },
            path,
        )
        logger.info("Saved XGBoost classifier to %s", path)

    @classmethod
    def load(cls, path: str | Path) -> "XGBoostAttackClassifier":
        state = joblib.load(path)
        instance = cls()
        instance.model = state["model"]
        instance._feature_columns = state["feature_columns"]
        instance._is_fitted = state["is_fitted"]
        return instance
