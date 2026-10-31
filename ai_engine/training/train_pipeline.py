"""
End-to-end model training pipeline for AEGIS-X 2.0.

Loads the train/test split and label encoder produced by
ai_engine.pipelines.preprocessing_pipeline, partitions training data into
train and validation splits (preventing test set leakage), trains all three
hybrid models:
1. Isolation Forest (unsupervised normal-traffic baseline)
2. XGBoost Attack Classifier (supervised multi-class threat classifier)
3. Deep Autoencoder (unsupervised reconstruction-error neural detector)

Calibrates the models and learns optimal simplex fusion weights using
AdaptiveThreatFusionEngine on the validation split, evaluates on the held-out
test set, and saves all artifacts and evaluation metadata.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from ai_engine.inference.adaptive_fusion import AdaptiveThreatFusionEngine
from ai_engine.inference.calibration import compute_ece
from ai_engine.models.autoencoder.model import DeepAutoencoderDetector
from ai_engine.models.isolation_forest.model import IsolationForestDetector
from ai_engine.models.xgboost_classifier.model import XGBoostAttackClassifier
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)

LABEL_COLUMN = "attack_type_encoded"


@dataclass
class TrainingResult:
    isolation_forest_path: Path
    xgboost_path: Path
    metadata_path: Path
    metrics: dict
    confusion_matrix_path: Path
    autoencoder_path: Path | None = None
    fusion_engine_path: Path | None = None


def _load_processed_data(processed_dir: Path) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame, pd.Series, list[str]]:
    train_df = pd.read_csv(processed_dir / "train.csv")
    test_df = pd.read_csv(processed_dir / "test.csv")

    feature_columns = [c for c in train_df.columns if c != LABEL_COLUMN]

    X_train = train_df[feature_columns]
    y_train = train_df[LABEL_COLUMN]
    X_test = test_df[feature_columns]
    y_test = test_df[LABEL_COLUMN]

    return X_train, y_train, X_test, y_test, feature_columns


def _plot_confusion_matrix(y_true, y_pred, class_names: list[str], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cm = confusion_matrix(y_true, y_pred, labels=range(len(class_names)))

    fig, ax = plt.subplots(figsize=(9, 7))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=class_names, yticklabels=class_names, ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("XGBoost Attack Classification — Confusion Matrix")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)

    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def train_models(
    processed_dir: str | Path = "datasets/processed",
    artifacts_dir: str | Path = "models/artifacts",
    metadata_dir: str | Path = "models/metadata",
    isolation_forest_contamination: float = 0.1,
    autoencoder_epochs: int = 15,
    random_seed: int = 42,
) -> TrainingResult:
    processed_dir = Path(processed_dir)
    artifacts_dir = Path(artifacts_dir)
    metadata_dir = Path(metadata_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    metadata_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=== Loading preprocessed data ===")
    X_train_full, y_train_full, X_test, y_test, feature_columns = _load_processed_data(processed_dir)

    label_encoder = joblib.load(processed_dir / "label_encoder.joblib")
    class_names = list(label_encoder.classes_)
    normal_class_id = int(label_encoder.transform(["normal"])[0])

    # Partition full training data into 90% train sub-split and 10% validation split
    # (used for calibration, AE threshold tuning, and fusion weight learning)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full,
        y_train_full,
        test_size=0.10,
        random_state=random_seed,
        stratify=y_train_full,
    )

    # 1. Isolation Forest (unsupervised, normal traffic only)
    normal_mask_train = y_train == normal_class_id
    X_train_normal = X_train[normal_mask_train]
    logger.info(
        "=== Training Isolation Forest on %d normal samples (of %d training rows) ===",
        len(X_train_normal),
        len(X_train),
    )
    isolation_forest = IsolationForestDetector(contamination=isolation_forest_contamination)
    isolation_forest.fit(X_train_normal)

    # 2. XGBoost Classifier (supervised, all classes)
    logger.info("=== Training XGBoost Attack Classifier on %d samples ===", len(X_train))
    xgb_classifier = XGBoostAttackClassifier()
    xgb_classifier.fit(X_train, y_train)

    # 3. Deep Autoencoder (unsupervised, normal traffic only)
    logger.info("=== Training Deep Autoencoder on %d normal samples ===", len(X_train_normal))
    scaler_path = processed_dir / "scaler.joblib"
    scaler = joblib.load(scaler_path) if scaler_path.exists() else None

    # Autoencoder operates on scaled features for stable neural reconstruction
    if scaler is not None:
        X_train_norm_sc = scaler.transform(X_train_normal)
        X_val_sc = pd.DataFrame(scaler.transform(X_val), columns=feature_columns, index=X_val.index)
        X_test_sc = pd.DataFrame(scaler.transform(X_test), columns=feature_columns, index=X_test.index)
    else:
        X_train_norm_sc = X_train_normal.values
        X_val_sc = X_val
        X_test_sc = X_test

    autoencoder = DeepAutoencoderDetector(
        input_dim=len(feature_columns),
        latent_dim=16,
        feature_names=feature_columns,
    )
    autoencoder.fit(X_train_norm_sc, epochs=autoencoder_epochs, random_seed=random_seed)

    # Tune Autoencoder decision threshold using validation set
    y_val_binary = (y_val != normal_class_id).astype(int).values
    normal_val_mask = y_val == normal_class_id
    if normal_val_mask.sum() > 0:
        val_normal_errors = autoencoder.reconstruction_error(X_val_sc[normal_val_mask])
        autoencoder.threshold = float(np.percentile(val_normal_errors, 95))
    else:
        val_errors = autoencoder.reconstruction_error(X_val_sc)
        autoencoder.threshold = float(np.mean(val_errors) + 2 * np.std(val_errors))
    logger.info("Autoencoder threshold calibrated on validation set: %.4f", autoencoder.threshold)

    # 4. Adaptive Threat Fusion Engine (calibrated on validation split)
    logger.info("=== Fitting Adaptive Threat Fusion Engine on validation split ===")
    fusion_engine = AdaptiveThreatFusionEngine(source_aware=True)

    if_val_scores = isolation_forest.predict(X_val).anomaly_scores
    ae_val_errors = autoencoder.reconstruction_error(X_val_sc)
    xgb_val_confs = np.max(xgb_classifier.predict_proba(X_val), axis=1)

    fusion_engine.fit_calibrators(
        if_scores_val=if_val_scores,
        ae_errors_val=ae_val_errors,
        xgb_conf_val=xgb_val_confs,
        y_val_binary=y_val_binary,
    )

    # 5. Evaluate XGBoost on held-out test set
    logger.info("=== Evaluating XGBoost on held-out test set ===")
    result = xgb_classifier.predict(X_test)
    y_pred = result.predicted_class_ids

    present_labels = sorted(set(y_test.unique()) | set(y_pred))
    present_names = [class_names[i] for i in present_labels]

    report = classification_report(
        y_test, y_pred, labels=present_labels, target_names=present_names, output_dict=True, zero_division=0
    )
    logger.info(
        "Test accuracy: %.4f | macro F1: %.4f",
        report["accuracy"],
        report["macro avg"]["f1-score"],
    )

    # 6. Evaluate Adaptive Fusion on held-out test set
    logger.info("=== Evaluating Calibrated Adaptive Threat Fusion on test set ===")
    if_test_scores = isolation_forest.predict(X_test).anomaly_scores
    ae_test_errors = autoencoder.reconstruction_error(X_test_sc)
    xgb_test_confs = np.max(xgb_classifier.predict_proba(X_test), axis=1)

    y_test_binary = (y_test != normal_class_id).astype(int).values
    fused_probs = fusion_engine.fuse_probabilities(
        if_scores=if_test_scores,
        ae_recon_errors=ae_test_errors,
        xgb_confidences=xgb_test_confs,
    )
    brier_score = float(np.mean((fused_probs - y_test_binary) ** 2))
    ece, _ = compute_ece(y_test_binary, fused_probs)
    logger.info("Test Brier Score: %.4f | Expected Calibration Error (ECE): %.4f", brier_score, ece)

    cm_path = _plot_confusion_matrix(y_test, y_pred, present_names, metadata_dir / "confusion_matrix.png")

    logger.info("=== Saving model artifacts ===")
    isolation_forest_path = artifacts_dir / "isolation_forest.joblib"
    xgboost_path = artifacts_dir / "xgboost_classifier.joblib"
    autoencoder_path = artifacts_dir / "autoencoder.pt"
    fusion_engine_path = artifacts_dir / "adaptive_fusion_engine.joblib"

    isolation_forest.save(isolation_forest_path)
    xgb_classifier.save(xgboost_path)
    autoencoder.save(autoencoder_path)
    fusion_engine.save(fusion_engine_path)

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "feature_columns": feature_columns,
        "class_names": class_names,
        "n_train_rows": len(X_train),
        "n_val_rows": len(X_val),
        "n_test_rows": len(X_test),
        "n_normal_rows_used_for_unsupervised": int(normal_mask_train.sum()),
        "isolation_forest_contamination": isolation_forest_contamination,
        "autoencoder_threshold": autoencoder.threshold,
        "learned_fusion_weights": fusion_engine.weights,
        "test_accuracy": report["accuracy"],
        "test_macro_f1": report["macro avg"]["f1-score"],
        "test_brier_score": round(brier_score, 4),
        "test_ece": round(ece, 4),
        "per_class_metrics": {
            name: {
                "precision": report[name]["precision"],
                "recall": report[name]["recall"],
                "f1_score": report[name]["f1-score"],
                "support": report[name]["support"],
            }
            for name in present_names
        },
    }
    metadata_path = metadata_dir / "training_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2))
    logger.info("Saved training metadata to %s", metadata_path)

    return TrainingResult(
        isolation_forest_path=isolation_forest_path,
        xgboost_path=xgboost_path,
        metadata_path=metadata_path,
        metrics=metadata,
        confusion_matrix_path=cm_path,
        autoencoder_path=autoencoder_path,
        fusion_engine_path=fusion_engine_path,
    )


if __name__ == "__main__":
    result = train_models()
    print(f"Test accuracy: {result.metrics['test_accuracy']:.4f}")
    print(f"Test macro F1: {result.metrics['test_macro_f1']:.4f}")
    print(f"Test Brier: {result.metrics['test_brier_score']:.4f} | ECE: {result.metrics['test_ece']:.4f}")
    print(f"Artifacts saved to: {result.isolation_forest_path.parent}")
