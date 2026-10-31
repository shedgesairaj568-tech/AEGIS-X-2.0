"""
Integration test: runs the full preprocessing pipeline end-to-end,
exactly the way Module 6 will invoke it, against a small synthetic
sample generated on the fly (not the full 15k-row file, to keep tests
fast).
"""

import numpy as np
import pytest

from ai_engine.pipelines.label_mapper import ATTACK_TYPES
from ai_engine.pipelines.preprocessing_pipeline import run_preprocessing_pipeline
from ai_engine.utils.synthetic_data_generator import write_sample_csv


@pytest.fixture
def sample_csv(tmp_path):
    return write_sample_csv(tmp_path / "raw" / "sample.csv", n_rows=1000, seed=1)


def test_pipeline_runs_end_to_end_without_error(tmp_path, sample_csv):
    result = run_preprocessing_pipeline(
        sample_csv, output_dir=tmp_path / "processed", generate_eda=False
    )
    assert len(result.X_train) > 0
    assert len(result.X_test) > 0


def test_pipeline_output_has_no_missing_or_infinite_values(tmp_path, sample_csv):
    result = run_preprocessing_pipeline(
        sample_csv, output_dir=tmp_path / "processed", generate_eda=False
    )
    assert not result.X_train.isna().any().any()
    assert not np.isinf(result.X_train.to_numpy()).any()


def test_pipeline_train_test_split_is_disjoint(tmp_path, sample_csv):
    result = run_preprocessing_pipeline(
        sample_csv, output_dir=tmp_path / "processed", generate_eda=False
    )
    train_idx = set(result.X_train.index)
    test_idx = set(result.X_test.index)
    assert train_idx.isdisjoint(test_idx)


def test_pipeline_class_names_match_backend_attack_types(tmp_path, sample_csv):
    result = run_preprocessing_pipeline(
        sample_csv, output_dir=tmp_path / "processed", generate_eda=False
    )
    assert set(result.class_names) == set(ATTACK_TYPES)


def test_pipeline_saves_expected_artifacts(tmp_path, sample_csv):
    output_dir = tmp_path / "processed"
    run_preprocessing_pipeline(sample_csv, output_dir=output_dir, generate_eda=False)

    assert (output_dir / "train.csv").exists()
    assert (output_dir / "test.csv").exists()
    assert (output_dir / "scaler.joblib").exists()
    assert (output_dir / "label_encoder.joblib").exists()


def test_pipeline_generates_eda_plots_when_enabled(tmp_path, sample_csv):
    output_dir = tmp_path / "processed"
    result = run_preprocessing_pipeline(sample_csv, output_dir=output_dir, generate_eda=True)

    assert "attack_distribution" in result.eda_plot_paths
    assert "correlation_matrix" in result.eda_plot_paths
    assert "feature_importance" in result.eda_plot_paths
    for path in result.eda_plot_paths.values():
        assert path.exists()
        assert path.stat().st_size > 0


def test_scaler_and_label_encoder_are_reloadable(tmp_path, sample_csv):
    """
    Confirms the saved artifacts actually round-trip through joblib —
    this is exactly how Module 6's inference code will load them to
    score live traffic the same way training data was scaled.
    """
    import joblib

    output_dir = tmp_path / "processed"
    run_preprocessing_pipeline(sample_csv, output_dir=output_dir, generate_eda=False)

    scaler = joblib.load(output_dir / "scaler.joblib")
    label_encoder = joblib.load(output_dir / "label_encoder.joblib")

    assert hasattr(scaler, "transform")
    assert set(label_encoder.classes_) == set(ATTACK_TYPES)
