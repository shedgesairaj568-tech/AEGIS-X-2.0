"""
Integration test: runs Module 5's preprocessing, then Module 6's full
training pipeline, then the DetectionService end-to-end — the same
sequence a real deployment follows, just against a small synthetic
sample so it stays fast.
"""

import pytest

from ai_engine.inference.detection_service import DetectionService
from ai_engine.pipelines.preprocessing_pipeline import run_preprocessing_pipeline
from ai_engine.training.train_pipeline import train_models
from ai_engine.utils.synthetic_data_generator import write_sample_csv


@pytest.fixture(scope="module")
def trained_pipeline_dirs(tmp_path_factory):
    """
    Runs preprocessing + training ONCE for this whole test file (module
    scope) since both are relatively expensive — individual tests below
    just load the already-trained artifacts.
    """
    base = tmp_path_factory.mktemp("module6_integration")
    raw_csv = write_sample_csv(base / "raw" / "sample.csv", n_rows=3000, seed=7)

    processed_dir = base / "processed"
    run_preprocessing_pipeline(raw_csv, output_dir=processed_dir, generate_eda=False)

    artifacts_dir = base / "artifacts"
    metadata_dir = base / "metadata"
    train_models(
        processed_dir=processed_dir,
        artifacts_dir=artifacts_dir,
        metadata_dir=metadata_dir,
    )

    return {"processed_dir": processed_dir, "artifacts_dir": artifacts_dir, "metadata_dir": metadata_dir}


def test_training_produces_all_expected_artifacts(trained_pipeline_dirs):
    artifacts_dir = trained_pipeline_dirs["artifacts_dir"]
    metadata_dir = trained_pipeline_dirs["metadata_dir"]

    assert (artifacts_dir / "isolation_forest.joblib").exists()
    assert (artifacts_dir / "xgboost_classifier.joblib").exists()
    assert (metadata_dir / "training_metadata.json").exists()
    assert (metadata_dir / "confusion_matrix.png").exists()


def test_training_metadata_has_sane_accuracy(trained_pipeline_dirs):
    import json

    metadata = json.loads((trained_pipeline_dirs["metadata_dir"] / "training_metadata.json").read_text())
    assert 0.0 <= metadata["test_accuracy"] <= 1.0
    assert metadata["n_train_rows"] > 0
    assert metadata["n_test_rows"] > 0


def test_detection_service_loads_and_runs(trained_pipeline_dirs):
    import pandas as pd

    service = DetectionService(
        artifacts_dir=trained_pipeline_dirs["artifacts_dir"],
        processed_dir=trained_pipeline_dirs["processed_dir"],
    )

    # Feature columns must match what Module 5 selected/engineered.
    feature_columns = [
        c
        for c in pd.read_csv(trained_pipeline_dirs["processed_dir"] / "train.csv").columns
        if c != "attack_type_encoded"
    ]
    sample_features = {col: 0.0 for col in feature_columns}

    result = service.detect(sample_features)

    assert result.attack_type in (
        "normal",
        "brute_force",
        "ddos",
        "botnet",
        "port_scan",
        "sql_injection",
        "web_attack",
        "other",
    )
    assert 0 <= result.risk_score <= 100
    assert result.severity in ("low", "medium", "high", "critical")
    assert isinstance(result.explanation, str) and len(result.explanation) > 0


def test_detection_output_matches_alert_create_schema_fields(trained_pipeline_dirs):
    """
    Confirms DetectionOutput's field names line up with the backend's
    AlertCreate schema (backend/app/schemas/alert.py) closely enough to
    be mapped directly — this is the contract Module 9 (Integration)
    depends on.
    """
    import pandas as pd

    service = DetectionService(
        artifacts_dir=trained_pipeline_dirs["artifacts_dir"],
        processed_dir=trained_pipeline_dirs["processed_dir"],
    )

    feature_columns = [
        c
        for c in pd.read_csv(trained_pipeline_dirs["processed_dir"] / "train.csv").columns
        if c != "attack_type_encoded"
    ]
    result = service.detect({col: 0.0 for col in feature_columns})

    # AlertCreate required/relevant fields from the backend schema.
    alert_create_fields = {
        "title",
        "source",
        "attack_type",
        "severity",
        "anomaly_score",
        "risk_score",
        "confidence",
        "mitre_technique_id",
        "mitre_technique_name",
        "raw_event",
    }
    result_fields = set(result.__dataclass_fields__.keys())
    assert alert_create_fields.issubset(result_fields)
