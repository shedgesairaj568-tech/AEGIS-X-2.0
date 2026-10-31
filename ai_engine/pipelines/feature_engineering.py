"""
Feature selection and engineering for CIC-IDS2017.

CIC-IDS2017's full export has 78 numeric features, many of which are
near-duplicates of each other (e.g. several slightly different packet
length statistics) or constant/zero-variance in practice. Rather than
feeding all 78 into the model, this module:

1. Selects a well-established, well-documented subset of ~20 features
   that the network-security ML literature consistently finds most
   discriminative for this exact dataset (flow timing, packet size
   statistics, and flag counts).
2. Drops any selected column that turns out to be constant in the actual
   data (zero variance carries no information and can break scalers).
3. Adds one engineered ratio feature: bytes-per-packet, which is a
   stronger DDoS/port-scan signal than either raw count alone (e.g. a
   port scan's packets are typically tiny; a DDoS flood's are often
   uniformly sized).
"""

import pandas as pd

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)

# Subset of CIC-IDS2017's columns we train on. Column names here already
# assume whitespace has been stripped by data_loader.py.
SELECTED_FEATURES: list[str] = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd PSH Flags",
    "SYN Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
]

LABEL_COLUMN = "Label"


def select_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Keep only the label column plus features from SELECTED_FEATURES that
    are actually present in df. Missing expected columns are logged and
    skipped rather than raising, so the pipeline still works against a
    partial/sample file that doesn't have every one of the 78 original
    columns.
    """
    available = [c for c in SELECTED_FEATURES if c in df.columns]
    missing = [c for c in SELECTED_FEATURES if c not in df.columns]
    if missing:
        logger.warning("Expected feature columns not found in data, skipping: %s", missing)

    columns_to_keep = available + ([LABEL_COLUMN] if LABEL_COLUMN in df.columns else [])
    return df[columns_to_keep].copy()


def drop_zero_variance_columns(df: pd.DataFrame, exclude: list[str] | None = None) -> pd.DataFrame:
    """Drop numeric columns that are constant across every row (no information for a model)."""
    exclude = set(exclude or [])
    numeric_cols = df.select_dtypes(include="number").columns
    zero_variance = [c for c in numeric_cols if c not in exclude and df[c].nunique(dropna=True) <= 1]
    if zero_variance:
        logger.info("Dropping zero-variance columns: %s", zero_variance)
        df = df.drop(columns=zero_variance)
    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add engineered features on top of the selected raw ones."""
    df = df.copy()

    total_packets = df.get("Total Fwd Packets", 0) + df.get("Total Backward Packets", 0)
    total_bytes = df.get("Total Length of Fwd Packets", 0) + df.get("Total Length of Bwd Packets", 0)
    # Avoid division by zero for flows with no packets recorded.
    bytes_per_packet = total_bytes / total_packets.replace(0, pd.NA)
    df["bytes_per_packet"] = bytes_per_packet.fillna(0).astype(float)

    return df
