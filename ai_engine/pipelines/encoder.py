"""
Label encoding and feature scaling.

Two separate, saveable artifacts come out of this step:
  - a fitted StandardScaler (so new/live traffic can be scaled the exact
    same way at inference time in Module 6 — fitting a new scaler on live
    data would silently drift from what the model was trained on)
  - a fitted LabelEncoder + the label mapping, so a model's numeric
    prediction (e.g. class 2) can be turned back into a human-readable
    attack_type string ("port_scan") that matches the backend's enum.
"""

from dataclasses import dataclass

import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

from ai_engine.pipelines.label_mapper import ATTACK_TYPES, map_label
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class EncodedDataset:
    X: pd.DataFrame  # scaled numeric features
    y: pd.Series  # encoded integer labels
    scaler: StandardScaler
    label_encoder: LabelEncoder
    feature_columns: list[str]


def encode_and_scale(df: pd.DataFrame, label_column: str = "Label") -> EncodedDataset:
    """
    Map raw labels -> AttackType strings -> integer classes, and scale all
    numeric feature columns to zero mean / unit variance.

    Fits the LabelEncoder on the full, fixed ATTACK_TYPES list (not just
    whatever labels happen to appear in this particular df) so the
    integer-to-string mapping is stable across different training runs
    and datasets, even if a given sample happens to be missing a rare
    class like "sql_injection".
    """
    df = df.copy()

    df["attack_type"] = df[label_column].astype(str).map(map_label)

    label_encoder = LabelEncoder()
    label_encoder.fit(list(ATTACK_TYPES))
    y = pd.Series(label_encoder.transform(df["attack_type"]), name="attack_type_encoded")

    feature_columns = [c for c in df.columns if c not in (label_column, "attack_type")]
    X_raw = df[feature_columns].select_dtypes(include="number")
    dropped_non_numeric = set(feature_columns) - set(X_raw.columns)
    if dropped_non_numeric:
        logger.warning("Dropping non-numeric feature columns before scaling: %s", dropped_non_numeric)

    scaler = StandardScaler()
    X_scaled = pd.DataFrame(
        scaler.fit_transform(X_raw), columns=X_raw.columns, index=X_raw.index
    )

    logger.info(
        "Encoded %d rows into %d classes, scaled %d numeric features.",
        len(df),
        len(label_encoder.classes_),
        X_scaled.shape[1],
    )

    return EncodedDataset(
        X=X_scaled,
        y=y,
        scaler=scaler,
        label_encoder=label_encoder,
        feature_columns=list(X_scaled.columns),
    )
