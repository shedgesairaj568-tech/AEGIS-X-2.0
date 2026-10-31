"""
CIC-IDS2017 data cleaning.

Handles the dataset's well-known quirks:

1. `Flow Bytes/s` and `Flow Packets/s` can be +/-Infinity when a flow's
   duration was recorded as 0 (division by zero during the original
   CICFlowMeter capture) — these are replaced with NaN, then imputed.
2. A meaningful number of duplicate rows exist across the 8 source files
   (the same flow sometimes appears in more than one day's export) —
   these are dropped.
3. Missing values in numeric columns are imputed with the column median
   rather than dropped, since dropping rows with any NaN would silently
   discard a large fraction of attack samples (attacks are the minority
   class we care most about detecting).
"""

import numpy as np
import pandas as pd

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


def clean_data(df: pd.DataFrame, label_column: str = "Label") -> pd.DataFrame:
    """
    Clean a raw (but column-name-normalized) CIC-IDS2017 DataFrame.

    Returns a new DataFrame — does not mutate the input in place, so the
    caller can always compare before/after for the EDA report.
    """
    original_rows = len(df)
    df = df.copy()

    # --- 1. Replace +/-Infinity with NaN so they can be imputed like any
    # other missing value, instead of poisoning every downstream
    # calculation (mean, scaler, model training all break on Infinity). ---
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_count = np.isinf(df[numeric_cols]).sum().sum()
    if inf_count > 0:
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        logger.info("Replaced %d infinite values with NaN.", inf_count)

    # --- 2. Drop exact duplicate rows. ---
    duplicate_count = df.duplicated().sum()
    if duplicate_count > 0:
        df = df.drop_duplicates()
        logger.info("Dropped %d duplicate rows.", duplicate_count)

    # --- 3. Impute missing numeric values with the column median. Median
    # (not mean) because network flow metrics like packet size are
    # heavily right-skewed — a few huge flows would drag the mean up. ---
    na_count = df[numeric_cols].isna().sum().sum()
    if na_count > 0:
        medians = df[numeric_cols].median()
        df[numeric_cols] = df[numeric_cols].fillna(medians)
        logger.info("Imputed %d missing numeric values with column medians.", na_count)

    # --- 4. Drop rows with a missing label — a row we can't classify by
    # attack type is not useful for supervised training. ---
    if label_column in df.columns:
        before = len(df)
        df = df.dropna(subset=[label_column])
        dropped_unlabeled = before - len(df)
        if dropped_unlabeled > 0:
            logger.info("Dropped %d rows with a missing label.", dropped_unlabeled)

    df = df.reset_index(drop=True)
    logger.info(
        "Cleaning complete: %d -> %d rows (%d removed).",
        original_rows,
        len(df),
        original_rows - len(df),
    )
    return df
