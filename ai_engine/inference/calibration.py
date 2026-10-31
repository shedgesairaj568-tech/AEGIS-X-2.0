"""
Statistical Score Calibration for AEGIS-X 2.0.

Provides Platt Scaling (logistic sigmoid) and Isotonic Regression calibration to transform
uncalibrated anomaly scores (Isolation Forest), reconstruction errors (Deep Autoencoder),
and tree probability outputs (XGBoost) into statistically grounded threat likelihoods:
    P(Malicious | Score)

Includes Expected Calibration Error (ECE) and Brier Score evaluation.
"""

from dataclasses import dataclass
from typing import Any
import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class CalibrationMetrics:
    """Statistical calibration validation metrics."""

    brier_score: float
    expected_calibration_error: float
    max_calibration_error: float
    is_calibrated: bool


class PlattCalibrator:
    """
    Parametric logistic calibration (Platt Scaling):
        P(Y = 1 | s) = 1 / (1 + exp(A * s + B))
    Fitted via maximum likelihood on a held-out validation split.
    """

    def __init__(self):
        self.model = LogisticRegression(C=1.0, solver="lbfgs")
        self.is_fitted = False

    def fit(self, scores: np.ndarray, y_binary: np.ndarray) -> "PlattCalibrator":
        scores_2d = np.asarray(scores, dtype=np.float64).reshape(-1, 1)
        y_arr = np.asarray(y_binary, dtype=int)
        self.model.fit(scores_2d, y_arr)
        self.is_fitted = True
        return self

    def predict_proba(self, scores: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            # Fallback min-max normalization if unfitted
            s = np.asarray(scores, dtype=np.float64)
            return np.clip((s - s.min()) / (s.max() - s.min() + 1e-8), 0.0, 1.0)
        scores_2d = np.asarray(scores, dtype=np.float64).reshape(-1, 1)
        return self.model.predict_proba(scores_2d)[:, 1]

    def calibrate_one(self, score: float) -> float:
        if not self.is_fitted:
            return float(np.clip(score, 0.0, 1.0))
        return float(self.predict_proba(np.array([score]))[0])


class IsotonicCalibrator:
    """
    Non-parametric monotonic isotonic regression calibration.
    Transforms raw continuous scores into calibrated probabilities without
    assuming a rigid parametric shape.
    """

    def __init__(self):
        self.model = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip")
        self.is_fitted = False

    def fit(self, scores: np.ndarray, y_binary: np.ndarray) -> "IsotonicCalibrator":
        scores_arr = np.asarray(scores, dtype=np.float64).flatten()
        y_arr = np.asarray(y_binary, dtype=float).flatten()
        self.model.fit(scores_arr, y_arr)
        self.is_fitted = True
        return self

    def predict_proba(self, scores: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            s = np.asarray(scores, dtype=np.float64)
            return np.clip((s - s.min()) / (s.max() - s.min() + 1e-8), 0.0, 1.0)
        scores_arr = np.asarray(scores, dtype=np.float64).flatten()
        return self.model.predict(scores_arr)

    def calibrate_one(self, score: float) -> float:
        if not self.is_fitted:
            return float(np.clip(score, 0.0, 1.0))
        return float(self.predict_proba(np.array([score]))[0])


def compute_brier_score(y_true: np.ndarray, y_prob: np.ndarray) -> float:
    """
    Computes Brier Score:
        BS = (1/N) * sum((y_prob_i - y_true_i)^2)
    Optimal: 0.0. Lower is better.
    """
    y_t = np.asarray(y_true, dtype=np.float64)
    y_p = np.asarray(y_prob, dtype=np.float64)
    return float(np.mean((y_p - y_t) ** 2))


def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> tuple[float, float]:
    """
    Computes Expected Calibration Error (ECE) and Maximum Calibration Error (MCE):
        ECE = sum_m (|B_m| / N) * | acc(B_m) - conf(B_m) |
    """
    y_t = np.asarray(y_true, dtype=int)
    y_p = np.asarray(y_prob, dtype=np.float64)
    n_samples = len(y_t)

    if n_samples == 0:
        return 0.0, 0.0

    bins = np.linspace(0.0, 1.0, n_bins + 1)
    bin_indices = np.digitize(y_p, bins) - 1
    bin_indices = np.clip(bin_indices, 0, n_bins - 1)

    ece = 0.0
    mce = 0.0

    for m in range(n_bins):
        mask = bin_indices == m
        bin_count = np.sum(mask)
        if bin_count > 0:
            bin_acc = float(np.mean(y_t[mask]))
            bin_conf = float(np.mean(y_p[mask]))
            diff = abs(bin_acc - bin_conf)
            ece += (bin_count / n_samples) * diff
            mce = max(mce, diff)

    return float(ece), float(mce)


def evaluate_calibration(y_true: np.ndarray, y_prob: np.ndarray, ece_threshold: float = 0.10) -> CalibrationMetrics:
    """Evaluates whether predictions meet empirical calibration standards."""
    bs = compute_brier_score(y_true, y_prob)
    ece, mce = compute_ece(y_true, y_prob)
    return CalibrationMetrics(
        brier_score=round(bs, 4),
        expected_calibration_error=round(ece, 4),
        max_calibration_error=round(mce, 4),
        is_calibrated=bool(ece <= ece_threshold),
    )

