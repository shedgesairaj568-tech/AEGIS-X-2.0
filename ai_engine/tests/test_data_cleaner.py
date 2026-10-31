"""
Tests for ai_engine.pipelines.data_cleaner.
"""

import numpy as np
import pandas as pd

from ai_engine.pipelines.data_cleaner import clean_data


def test_infinite_values_are_replaced_and_imputed():
    df = pd.DataFrame(
        {
            "Flow Bytes/s": [1.0, np.inf, 3.0, -np.inf],
            "Label": ["BENIGN", "BENIGN", "BENIGN", "BENIGN"],
        }
    )
    cleaned = clean_data(df)
    assert not np.isinf(cleaned["Flow Bytes/s"]).any()
    assert not cleaned["Flow Bytes/s"].isna().any()


def test_duplicate_rows_are_dropped():
    df = pd.DataFrame({"a": [1, 1, 2], "Label": ["BENIGN", "BENIGN", "DDoS"]})
    cleaned = clean_data(df)
    assert len(cleaned) == 2


def test_missing_numeric_values_imputed_with_median():
    df = pd.DataFrame({"a": [1.0, np.nan, 3.0], "Label": ["BENIGN", "BENIGN", "BENIGN"]})
    cleaned = clean_data(df)
    assert not cleaned["a"].isna().any()
    assert cleaned["a"].iloc[1] == 2.0  # median of [1, 3]


def test_rows_with_missing_label_are_dropped():
    df = pd.DataFrame({"a": [1, 2, 3], "Label": ["BENIGN", None, "DDoS"]})
    cleaned = clean_data(df)
    assert len(cleaned) == 2
    assert cleaned["Label"].isna().sum() == 0
