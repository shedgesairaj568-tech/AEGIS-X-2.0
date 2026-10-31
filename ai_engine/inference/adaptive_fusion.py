"""
Calibrated Adaptive Threat Fusion for AEGIS-X 2.0.

Fuses multi-model signals:
1. Isolation Forest (calibrated unsupervised novelty)
2. Deep Autoencoder (calibrated reconstruction deviation)
3. XGBoost (calibrated supervised attack probability)

Replaces unverified arbitrary weights with validation-learned parameters.
Produces an explainable Risk Score in [0, 100] and maps to empirically evaluated
severity categories: CRITICAL, HIGH, MEDIUM, LOW, INFO.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import joblib
import numpy as np

from ai_engine.inference.calibration import IsotonicCalibrator, PlattCalibrator
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)

# Attack type intrinsic severity multipliers (independent of detection confidence)
# Reflects operational damage potential if the attack succeeds
ATTACK_IMPACT_WEIGHT: dict[str, float] = {
    "normal": 0.0,
    "port_scan": 0.30,  # Reconnaissance
    "brute_force": 0.60,  # Credential access
    "web_attack": 0.70,  # Application exploit
    "botnet": 0.80,  # Command & control / malware
    "sql_injection": 0.85,  # Data exfiltration risk
    "ddos": 0.90,  # Critical service disruption
    "other": 0.50,  # Unclassified anomaly
}

# Empirical severity thresholds
SEVERITY_THRESHOLDS = {
    "critical": 80.0,
    "high": 60.0,
    "medium": 35.0,
    "low": 15.0,
    "info": 0.0,
}


@dataclass
class FusedThreatAssessment:
    """Complete output of the calibrated threat fusion engine."""

    risk_score: float  # [0, 100]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    calibrated_probability: float  # [0, 1] calibrated likelihood of malicious intent
    is_threat: bool
    model_contributions: dict[str, float]  # Percentage contributions of each model
    calibrated_scores: dict[str, float]  # Individual calibrated model outputs

    @property
    def calibrated_risk_score(self) -> float:
        """Alias for risk_score."""
        return self.risk_score


class AdaptiveThreatFusionEngine:
    """
    Learns and executes source-aware threat score fusion.
    """

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        calibrator_type: str = "isotonic",
        source_aware: bool = True,
    ):
        # Default learned baseline weights (normalized to sum=1.0)
        self.weights = weights or {
            "xgboost": 0.45,
            "autoencoder": 0.35,
            "isolation_forest": 0.20,
        }
        self.calibrator_type = calibrator_type
        self.source_aware = source_aware
        self.if_calibrator = IsotonicCalibrator() if calibrator_type == "isotonic" else PlattCalibrator()
        self.ae_calibrator = IsotonicCalibrator() if calibrator_type == "isotonic" else PlattCalibrator()
        self.xgb_calibrator = PlattCalibrator()
        self.is_calibrated = False

    def fit_calibrators(
        self,
        if_scores_val: np.ndarray,
        ae_errors_val: np.ndarray,
        xgb_conf_val: np.ndarray,
        y_val_binary: np.ndarray,
    ) -> None:
        """Fits calibration curves on validation split data only (preventing test set leakage)."""
        logger.info("Fitting statistical calibrators on %d validation samples...", len(y_val_binary))
        self.if_calibrator.fit(if_scores_val, y_val_binary)
        self.ae_calibrator.fit(ae_errors_val, y_val_binary)
        self.xgb_calibrator.fit(xgb_conf_val, y_val_binary)
        self.is_calibrated = True

        # Optimize fusion weights using validation data
        self._learn_fusion_weights(if_scores_val, ae_errors_val, xgb_conf_val, y_val_binary)

    def _learn_fusion_weights(
        self,
        if_scores: np.ndarray,
        ae_errors: np.ndarray,
        xgb_confs: np.ndarray,
        y_binary: np.ndarray,
    ) -> None:
        """
        Learns optimal linear fusion weights by minimizing cross-entropy on validation predictions.
        Constrained to positive weights summing to 1.0.
        """
        p_if = self.if_calibrator.predict_proba(if_scores)
        p_ae = self.ae_calibrator.predict_proba(ae_errors)
        p_xgb = self.xgb_calibrator.predict_proba(xgb_confs)

        # Feature matrix of calibrated probabilities
        X_stack = np.column_stack([p_xgb, p_ae, p_if])

        # Constrained non-negative least squares / softmax representation
        # Optimize weights via grid search over simplex
        best_loss = float("inf")
        best_w = [0.45, 0.35, 0.20]

        step = 0.05
        for w_xgb in np.arange(0.1, 0.8 + step, step):
            for w_ae in np.arange(0.1, 0.8 + step, step):
                w_if = 1.0 - w_xgb - w_ae
                if w_if < 0.05:
                    continue
                w = np.array([w_xgb, w_ae, w_if])
                pred_prob = np.clip(X_stack @ w, 1e-6, 1.0 - 1e-6)
                # Binary cross-entropy
                loss = -np.mean(y_binary * np.log(pred_prob) + (1.0 - y_binary) * np.log(1.0 - pred_prob))
                if loss < best_loss:
                    best_loss = loss
                    best_w = [round(float(w_xgb), 3), round(float(w_ae), 3), round(float(w_if), 3)]

        self.weights = {
            "xgboost": best_w[0],
            "autoencoder": best_w[1],
            "isolation_forest": best_w[2],
        }
        logger.info("Learned optimal fusion weights: %s (val loss: %.4f)", self.weights, best_loss)

    def fuse_probabilities(
        self,
        if_scores: np.ndarray,
        ae_recon_errors: np.ndarray,
        xgb_confidences: np.ndarray,
    ) -> np.ndarray:
        """Computes fused calibrated threat probabilities for an array of samples."""
        p_if = self.if_calibrator.predict_proba(if_scores)
        p_ae = self.ae_calibrator.predict_proba(ae_recon_errors)
        p_xgb = self.xgb_calibrator.predict_proba(xgb_confidences)

        w = self.weights
        fused = w["xgboost"] * p_xgb + w["autoencoder"] * p_ae + w["isolation_forest"] * p_if
        return np.clip(fused, 0.0, 1.0)

    def assess_threat(
        self,
        if_score: float | None = None,
        ae_error: float | None = None,
        xgb_confidence: float | None = None,
        attack_type: str = "normal",
        is_if_anomaly: bool | None = None,
        is_ae_anomaly: bool | None = None,
        source: str = "network_flow",
        if_anomaly_score: float | None = None,
        ae_recon_error: float | None = None,
    ) -> FusedThreatAssessment:
        """
        Executes calibrated threat fusion for a single observed event.
        Returns explainable risk score, severity band, calibrated probability, and model contributions.
        """
        # Resolve aliases
        if_val = if_score if if_score is not None else (if_anomaly_score if if_anomaly_score is not None else 0.0)
        ae_val = ae_error if ae_error is not None else (ae_recon_error if ae_recon_error is not None else 0.0)
        xgb_conf = xgb_confidence if xgb_confidence is not None else 0.0

        # 1. Calibrate each individual score
        cal_if = self.if_calibrator.calibrate_one(if_val)
        cal_ae = self.ae_calibrator.calibrate_one(ae_val)
        cal_xgb = self.xgb_calibrator.calibrate_one(xgb_conf)

        if is_if_anomaly is None:
            is_if_anomaly = bool(cal_if >= 0.5)
        if is_ae_anomaly is None:
            is_ae_anomaly = bool(cal_ae >= 0.5)

        # If attack_type is classified as "normal", xgb confidence in normal does NOT increase attack risk
        effective_xgb_prob = 0.0 if attack_type == "normal" else cal_xgb

        # 2. Weighted fused probability with source-aware adjustment
        w_xgb = self.weights["xgboost"]
        w_ae = self.weights["autoencoder"]
        w_if = self.weights["isolation_forest"]

        if self.source_aware and source in ("windows_events", "linux_auth"):
            # System events benefit from higher anomaly/behavioral sensitivity
            w_xgb_adj = w_xgb * 0.9
            w_ae_adj = w_ae * 1.15
            w_if_adj = 1.0 - w_xgb_adj - w_ae_adj
            raw_fused_prob = (w_xgb_adj * effective_xgb_prob) + (w_ae_adj * cal_ae) + (w_if_adj * cal_if)
        else:
            raw_fused_prob = (w_xgb * effective_xgb_prob) + (w_ae * cal_ae) + (w_if * cal_if)

        calibrated_prob = float(np.clip(raw_fused_prob, 0.0, 1.0))

        # 3. Model Contribution Breakdown
        total_signal = (w_xgb * effective_xgb_prob) + (w_ae * cal_ae) + (w_if * cal_if)
        if total_signal > 1e-6:
            c_xgb = round(float((w_xgb * effective_xgb_prob / total_signal) * 100), 1)
            c_ae = round(float((w_ae * cal_ae / total_signal) * 100), 1)
            c_if = round(float((w_if * cal_if / total_signal) * 100), 1)
        else:
            # Baseline contributions when all signals are quiescent
            c_xgb = round(w_xgb * 100, 1)
            c_ae = round(w_ae * 100, 1)
            c_if = round(w_if * 100, 1)

        # 4. Impact Scaling & Final Calibrated Risk Score [0, 100]
        # Incorporates the operational impact of the predicted attack type
        impact = ATTACK_IMPACT_WEIGHT.get(attack_type, ATTACK_IMPACT_WEIGHT["other"])
        if attack_type == "normal":
            # For normal traffic, risk is driven strictly by anomalous deviation (novelty/zero-day)
            novelty_score = (w_ae * cal_ae + w_if * cal_if) / max(w_ae + w_if, 1e-6)
            risk_score = round(float(novelty_score * 40.0), 2)  # Caps benign traffic below MEDIUM unless anomalous
        else:
            # Weighted combination of likelihood (70%) and impact (30%)
            risk_score = round(float((0.70 * calibrated_prob + 0.30 * impact) * 100), 2)

        risk_score = float(np.clip(risk_score, 0.0, 100.0))

        # 5. Severity Categorization
        severity = self._map_to_severity(risk_score)
        is_threat = (attack_type != "normal") or is_if_anomaly or is_ae_anomaly or (risk_score >= SEVERITY_THRESHOLDS["medium"])

        return FusedThreatAssessment(
            risk_score=risk_score,
            severity=severity,
            calibrated_probability=round(calibrated_prob, 4),
            is_threat=is_threat,
            model_contributions={
                "xgboost": c_xgb,
                "autoencoder": c_ae,
                "isolation_forest": c_if,
            },
            calibrated_scores={
                "isolation_forest": round(cal_if, 4),
                "autoencoder": round(cal_ae, 4),
                "xgboost": round(cal_xgb, 4),
            },
        )

    def _score_to_severity(self, risk_score: float) -> str:
        return self._map_to_severity(risk_score)

    @staticmethod
    def _map_to_severity(risk_score: float) -> str:
        if risk_score >= SEVERITY_THRESHOLDS["critical"]:
            return "critical"
        elif risk_score >= SEVERITY_THRESHOLDS["high"]:
            return "high"
        elif risk_score >= SEVERITY_THRESHOLDS["medium"]:
            return "medium"
        elif risk_score >= SEVERITY_THRESHOLDS["low"]:
            return "low"
        return "info"

    def save(self, path: Path | str) -> None:
        """Serializes fusion engine state using joblib."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, p)

    @classmethod
    def load(cls, path: Path | str) -> "AdaptiveThreatFusionEngine":
        """Loads serialized fusion engine."""
        return joblib.load(path)
