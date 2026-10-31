"""
Tests for ai_engine.pipelines.encoder.
"""

import numpy as np
import pandas as pd

from ai_engine.pipelines.encoder import encode_and_scale
from ai_engine.pipelines.label_mapper import ATTACK_TYPES


def _sample_df():
    return pd.DataFrame(
        {
            "feature_a": [1.0, 2.0, 3.0, 4.0, 100.0, 200.0],
            "feature_b": [10.0, 20.0, 30.0, 40.0, 500.0, 600.0],
            "Label": ["BENIGN", "BENIGN", "DDoS", "DDoS", "PortScan", "PortScan"],
        }
    )


def test_encode_and_scale_produces_correct_row_count():
    result = encode_and_scale(_sample_df())
    assert len(result.X) == 6
    assert len(result.y) == 6


def test_scaled_features_have_approximately_zero_mean():
    result = encode_and_scale(_sample_df())
    means = result.X.mean()
    assert np.allclose(means, 0, atol=1e-10)


def test_label_encoder_covers_full_fixed_attack_type_set():
    """
    The encoder is fit on the FULL fixed ATTACK_TYPES list, not just labels
    present in this particular dataframe — this test would catch a
    regression where a rare class (e.g. "sql_injection") silently
    disappears from the encoder just because a given batch doesn't
    contain any examples of it.
    """
    result = encode_and_scale(_sample_df())
    assert set(result.label_encoder.classes_) == set(ATTACK_TYPES)


def test_attack_type_mapping_is_correct():
    result = encode_and_scale(_sample_df())
    decoded = result.label_encoder.inverse_transform(result.y)
    assert list(decoded) == ["normal", "normal", "ddos", "ddos", "port_scan", "port_scan"]


def test_non_numeric_columns_are_dropped_from_features():
    df = _sample_df()
    df["some_text_column"] = ["x", "y", "z", "a", "b", "c"]
    result = encode_and_scale(df)
    assert "some_text_column" not in result.X.columns
