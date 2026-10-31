"""
Isolation Forest — anomaly detection.

What Isolation Forest actually does: it randomly picks a feature and a
random split value, repeatedly, building many random decision trees. The
key insight is that anomalies are "few and different" — they get isolated
(separated into their own leaf) in far fewer random splits than normal
points, because normal points are surrounded by many similar points and
take longer to separate out. A point's anomaly score is based on the
average number of splits it took to isolate it across all the trees:
fewer splits = shorter average path length = more anomalous.

We train this UNSUPERVISED, on (mostly) normal traffic only, deliberately
without attack labels. That's the point of this model in the pipeline: it
answers "does this look like normal behavior at all?" without needing to
have seen every possible attack type in advance — which matters because
new/unknown attack types won't be in any labeled training set, but they
will still look "different" from normal traffic.

The XGBoost classifier (xgboost_classifier/model.py) is the second stage
that answers "given this IS unusual, what specific kind of attack does it
look like?" — trained WITH labels. Isolation Forest and XGBoost are
deliberately complementary, not redundant.
"""

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class AnomalyResult:
    anomaly_scores: np.ndarray  # normalized 0 (normal) .. 1 (highly anomalous)
    is_anomaly: np.ndarray  # boolean array


class IsolationForestDetector:
    """
    Thin, save/load-able wrapper around sklearn's IsolationForest with a
    normalized [0, 1] anomaly score instead of sklearn's raw
    (unintuitive, sign-flipped, unbounded) decision_function output —
    this normalized score is what gets written directly into the Alert
    model's `anomaly_score` column (see backend/app/models/alert.py),
    so the API contract expects 0..1, not sklearn's raw units.
    """

    def __init__(self, contamination: float = 0.1, n_estimators: int = 150, random_state: int = 42):
        """
        contamination: the expected proportion of anomalies in the
        training data. We train mostly on normal traffic, so this is
        deliberately kept low — it primarily controls where the
        is_anomaly threshold gets drawn, not the model's actual behavior.
        """
        self._contamination = contamination
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self._is_fitted = False
        # Min/max of raw decision_function scores seen during training,
        # used to normalize new scores into a stable [0, 1] range.
        self._raw_score_min: float | None = None
        self._raw_score_max: float | None = None

    def fit(self, X: pd.DataFrame) -> "IsolationForestDetector":
        logger.info("Training Isolation Forest on %d samples, %d features.", *X.shape)
        self.model.fit(X)

        raw_scores = self.model.decision_function(X)
        self._raw_score_min = float(raw_scores.min())
        self._raw_score_max = float(raw_scores.max())
        self._is_fitted = True

        logger.info(
            "Isolation Forest trained. Raw decision_function range: [%.4f, %.4f]",
            self._raw_score_min,
            self._raw_score_max,
        )
        return self

    def _normalize(self, raw_scores: np.ndarray) -> np.ndarray:
        """
        sklearn's decision_function is HIGHER for normal points and LOWER
        (more negative) for anomalies — the opposite of what an
        "anomaly_score" should intuitively mean. We flip and rescale it
        so 0 = normal, 1 = highly anomalous, clipped to that range for
        any new score that falls outside the training distribution's
        observed min/max.
        """
        span = self._raw_score_max - self._raw_score_min
        if span == 0:
            return np.zeros_like(raw_scores)
        normalized = (self._raw_score_max - raw_scores) / span
        return np.clip(normalized, 0.0, 1.0)

    def predict(self, X: pd.DataFrame) -> AnomalyResult:
        if not self._is_fitted:
            raise RuntimeError("IsolationForestDetector.fit() must be called before predict().")

        raw_scores = self.model.decision_function(X)
        anomaly_scores = self._normalize(raw_scores)
        # sklearn's .predict() returns -1 for anomaly, 1 for normal.
        is_anomaly = self.model.predict(X) == -1

        return AnomalyResult(anomaly_scores=anomaly_scores, is_anomaly=is_anomaly)

    def predict_one(self, x: pd.Series | pd.DataFrame) -> tuple[float, bool]:
        """Convenience method for scoring a single flow (e.g. live inference)."""
        X = x.to_frame().T if isinstance(x, pd.Series) else x
        result = self.predict(X)
        return float(result.anomaly_scores[0]), bool(result.is_anomaly[0])

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "contamination": self._contamination,
                "raw_score_min": self._raw_score_min,
                "raw_score_max": self._raw_score_max,
                "is_fitted": self._is_fitted,
            },
            path,
        )
        logger.info("Saved Isolation Forest to %s", path)

    @classmethod
    def load(cls, path: str | Path) -> "IsolationForestDetector":
        state = joblib.load(path)
        instance = cls(contamination=state["contamination"])
        instance.model = state["model"]
        instance._raw_score_min = state["raw_score_min"]
        instance._raw_score_max = state["raw_score_max"]
        instance._is_fitted = state["is_fitted"]
        return instance
