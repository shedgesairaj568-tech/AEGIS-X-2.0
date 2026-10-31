"""
Tests for ai_engine.pipelines.feature_engineering.
"""

import pandas as pd

from ai_engine.pipelines.feature_engineering import (
    drop_zero_variance_columns,
    engineer_features,
    select_features,
)


def test_select_features_keeps_only_known_columns_plus_label():
    df = pd.DataFrame(
        {
            "Destination Port": [80],
            "Flow Duration": [100],
            "Some Unrelated Column": ["x"],
            "Label": ["BENIGN"],
        }
    )
    result = select_features(df)
    assert "Some Unrelated Column" not in result.columns
    assert "Destination Port" in result.columns
    assert "Label" in result.columns


def test_select_features_handles_missing_expected_columns_gracefully():
    df = pd.DataFrame({"Destination Port": [80], "Label": ["BENIGN"]})
    result = select_features(df)  # should not raise despite missing most expected columns
    assert "Destination Port" in result.columns


def test_drop_zero_variance_columns_removes_constants():
    df = pd.DataFrame({"constant": [1, 1, 1], "varies": [1, 2, 3], "Label": ["a", "b", "c"]})
    result = drop_zero_variance_columns(df, exclude=["Label"])
    assert "constant" not in result.columns
    assert "varies" in result.columns


def test_engineer_features_adds_bytes_per_packet():
    df = pd.DataFrame(
        {
            "Total Fwd Packets": [10],
            "Total Backward Packets": [10],
            "Total Length of Fwd Packets": [1000],
            "Total Length of Bwd Packets": [1000],
        }
    )
    result = engineer_features(df)
    assert "bytes_per_packet" in result.columns
    assert result["bytes_per_packet"].iloc[0] == 100.0  # 2000 bytes / 20 packets


def test_engineer_features_handles_zero_packets_without_error():
    df = pd.DataFrame(
        {
            "Total Fwd Packets": [0],
            "Total Backward Packets": [0],
            "Total Length of Fwd Packets": [0],
            "Total Length of Bwd Packets": [0],
        }
    )
    result = engineer_features(df)
    assert result["bytes_per_packet"].iloc[0] == 0.0
