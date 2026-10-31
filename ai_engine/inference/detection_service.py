"""
Detection service — the real-time inference entry point for AEGIS-X 2.0.

Loads all trained models once at construction:
- Isolation Forest (unsupervised tree anomaly detection)
- Deep Autoencoder (unsupervised neural reconstruction error)
- XGBoost Attack Classifier (supervised multi-class classification)
- Adaptive Threat Fusion Engine (statistically calibrated risk score [0-100] & severity)
- TreeSHAP Explainer & Autoencoder Per-Feature Attribution

Returns a structured DetectionOutput shaped to match backend/app/schemas/alert.py
(AlertCreate) with zero translation layer required, while exposing full
calibrated threat intelligence and dual-mode explainability.
"""

from dataclasses import dataclass, field
from pathlib import Path

import joblib
import pandas as pd

from ai_engine.explainability.shap_explainer import ShapExplainer
from ai_engine.inference.adaptive_fusion import AdaptiveThreatFusionEngine
from ai_engine.inference.mitre_mapping import get_mitre_mapping
from ai_engine.inference.risk_scoring import compute_risk_score, score_to_severity
from ai_engine.models.autoencoder.model import DeepAutoencoderDetector
from ai_engine.models.isolation_forest.model import IsolationForestDetector
from ai_engine.models.xgboost_classifier.model import XGBoostAttackClassifier
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class DetectionOutput:
    """Shaped to match backend/app/schemas/alert.py::AlertCreate exactly."""

    title: str
    source: str
    attack_type: str
    severity: str
    anomaly_score: float
    risk_score: float
    confidence: float
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    explanation: str  # human-readable SHAP + AE summary; maps onto AlertCreate.description
    raw_event: dict
    is_anomaly: bool  # Composite anomaly decision (IF or AE)

    # AEGIS-X 2.0 multi-model & calibration fields
    reconstruction_error: float = 0.0
    is_ae_anomaly: bool = False
    calibrated_probability: float = 0.0
    model_contributions: dict = field(default_factory=dict)
    autoencoder_attributions: dict = field(default_factory=dict)


class DetectionService:
    def __init__(
        self,
        artifacts_dir: str | Path = "models/artifacts",
        processed_dir: str | Path = "datasets/processed",
    ):
        artifacts_dir = Path(artifacts_dir)
        processed_dir = Path(processed_dir)

        logger.info("Loading detection models from %s", artifacts_dir)
        self.isolation_forest = IsolationForestDetector.load(artifacts_dir / "isolation_forest.joblib")
        self.xgb_classifier = XGBoostAttackClassifier.load(artifacts_dir / "xgboost_classifier.joblib")
        self.scaler = joblib.load(processed_dir / "scaler.joblib")
        self.label_encoder = joblib.load(processed_dir / "label_encoder.joblib")

        # Load Deep Autoencoder if available
        ae_path = artifacts_dir / "autoencoder.pt"
        if ae_path.exists():
            self.autoencoder = DeepAutoencoderDetector.load(ae_path)
            logger.info("Deep Autoencoder loaded (threshold=%.4f).", self.autoencoder.threshold or 0.0)
        else:
            self.autoencoder = None
            logger.info("No autoencoder artifact found at %s; operating in dual-model mode.", ae_path)

        # Load Calibrated Adaptive Threat Fusion Engine if available
        fusion_path = artifacts_dir / "adaptive_fusion_engine.joblib"
        if fusion_path.exists():
            self.fusion_engine = AdaptiveThreatFusionEngine.load(fusion_path)
            logger.info("Adaptive Threat Fusion Engine loaded with weights: %s", self.fusion_engine.weights)
        else:
            self.fusion_engine = None
            logger.info("No fusion engine artifact found; using heuristic risk scoring.")

        # Class names from encoder
        self.class_names = list(self.label_encoder.classes_)
        self.shap_explainer = ShapExplainer(self.xgb_classifier.model, self.class_names)
        logger.info("AEGIS-X 2.0 Detection Service initialized successfully.")

    def detect(self, raw_features: dict, source: str = "network_flow") -> DetectionOutput:
        """
        Runs real-time multi-model detection, calibration, fusion, and dual-mode explainability.
        """
        feature_columns = list(raw_features.keys())
        X_raw = pd.DataFrame([raw_features], columns=feature_columns)
        X_scaled = pd.DataFrame(
            self.scaler.transform(X_raw), columns=feature_columns, index=X_raw.index
        )
        row_scaled = X_scaled.iloc[0]

        # 1. Isolation Forest (Tree Anomaly Detection)
        anomaly_score, is_if_anomaly = self.isolation_forest.predict_one(row_scaled)

        # 2. Deep Autoencoder (Neural Reconstruction Anomaly Detection)
        if self.autoencoder is not None:
            ae_error, is_ae_anomaly, ae_attributions = self.autoencoder.predict_one(row_scaled)
        else:
            ae_error, is_ae_anomaly, ae_attributions = 0.0, False, {}

        # 3. XGBoost Classifier (Supervised Attack Classification)
        class_id, confidence, _ = self.xgb_classifier.predict_one(row_scaled)
        attack_type = self.label_encoder.inverse_transform([class_id])[0]

        # 4. Calibrated Threat Scoring and Adaptive Fusion
        if self.fusion_engine is not None:
            assessment = self.fusion_engine.assess_threat(
                if_anomaly_score=anomaly_score,
                ae_recon_error=ae_error,
                xgb_confidence=confidence,
                attack_type=attack_type,
                source=source,
            )
            risk_score = assessment.risk_score
            severity = assessment.severity
            calibrated_prob = assessment.calibrated_probability
            model_contributions = assessment.model_contributions
        else:
            risk_score = compute_risk_score(anomaly_score, confidence, attack_type)
            severity = score_to_severity(risk_score)
            calibrated_prob = confidence
            model_contributions = {"xgboost": 0.5, "isolation_forest": 0.5}

        # 5. MITRE ATT&CK Mapping
        mitre = get_mitre_mapping(attack_type)

        # 6. Dual-Mode Explainability: Supervised SHAP + Unsupervised AE Attribution
        contributions = self.shap_explainer.explain_one(row_scaled, predicted_class_id=class_id)
        shap_explanation = self.shap_explainer.to_human_readable(contributions)

        if ae_attributions:
            top_ae_feats = sorted(ae_attributions.items(), key=lambda kv: kv[1], reverse=True)[:3]
            ae_summary = "Reconstruction anomaly drivers: " + ", ".join(
                f"{k} (err: {v:.3f})" for k, v in top_ae_feats
            )
            explanation = f"{shap_explanation}. {ae_summary}."
        else:
            explanation = shap_explanation

        # 7. Alert Title & Composite Anomaly Determination
        is_composite_anomaly = bool(is_if_anomaly or is_ae_anomaly)
        if attack_type != "normal":
            title = f"{attack_type.replace('_', ' ').title()} detected"
        elif is_composite_anomaly:
            title = "Anomalous traffic (unclassified)"
        else:
            title = "Normal traffic"

        return DetectionOutput(
            title=title,
            source=source,
            attack_type=attack_type,
            severity=severity,
            anomaly_score=round(anomaly_score, 4),
            risk_score=round(risk_score, 2),
            confidence=round(confidence, 4),
            mitre_technique_id=mitre.technique_id if mitre else None,
            mitre_technique_name=mitre.technique_name if mitre else None,
            explanation=explanation,
            raw_event=raw_features,
            is_anomaly=is_composite_anomaly,
            reconstruction_error=round(ae_error, 4),
            is_ae_anomaly=is_ae_anomaly,
            calibrated_probability=round(calibrated_prob, 4),
            model_contributions=model_contributions,
            autoencoder_attributions=ae_attributions,
        )
