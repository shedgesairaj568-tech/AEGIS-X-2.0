"""
End-to-end CIC-IDS2017 preprocessing pipeline.

Ties together every step in this package into one function:
    load -> clean -> select/engineer features -> encode + scale -> split
    -> save artifacts -> generate EDA report

This is the single entry point Module 6 (AI models) will import to get
a ready-to-train dataset, and the entry point this module's own tests
and CLI script call.
"""

from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split

from ai_engine.eda.generate_eda_report import generate_eda_report
from ai_engine.pipelines.data_cleaner import clean_data
from ai_engine.pipelines.data_loader import load_cic_ids2017
from ai_engine.pipelines.encoder import EncodedDataset, encode_and_scale
from ai_engine.pipelines.feature_engineering import (
    drop_zero_variance_columns,
    engineer_features,
    select_features,
)
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)

LABEL_COLUMN = "Label"


@dataclass
class PreprocessingResult:
    X_train: pd.DataFrame
    X_test: pd.DataFrame
    y_train: pd.Series
    y_test: pd.Series
    feature_columns: list[str]
    class_names: list[str]
    eda_plot_paths: dict[str, Path]


def run_preprocessing_pipeline(
    source: str | Path,
    output_dir: str | Path = "datasets/processed",
    test_size: float = 0.2,
    random_state: int = 42,
    generate_eda: bool = True,
) -> PreprocessingResult:
    """
    Run the full pipeline against `source` (a directory of CIC-IDS2017
    CSVs, or a single CSV such as our synthetic sample) and write all
    artifacts to `output_dir`:

        {output_dir}/train.csv, test.csv   — the actual split, scaled data
        {output_dir}/scaler.joblib          — fitted StandardScaler
        {output_dir}/label_encoder.joblib   — fitted LabelEncoder
        {output_dir}/eda/*.png              — the three EDA plots
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=== Step 1/5: Loading raw data ===")
    df = load_cic_ids2017(source)

    logger.info("=== Step 2/5: Cleaning data ===")
    df = clean_data(df, label_column=LABEL_COLUMN)

    logger.info("=== Step 3/5: Selecting and engineering features ===")
    df = select_features(df)
    df = engineer_features(df)
    df = drop_zero_variance_columns(df, exclude=[LABEL_COLUMN])

    logger.info("=== Step 4/5: Encoding labels and scaling features ===")
    encoded: EncodedDataset = encode_and_scale(df, label_column=LABEL_COLUMN)

    # Keep the human-readable attack_type alongside the scaled features
    # purely for the EDA attack-distribution plot, which needs the string
    # label, not the encoded integer.
    attack_type_series = encoded.label_encoder.inverse_transform(encoded.y)
    df_for_eda = encoded.X.copy()
    df_for_eda["attack_type"] = attack_type_series

    class_counts = encoded.y.value_counts()
    can_stratify = (class_counts >= 2).all()
    if not can_stratify:
        rare_classes = class_counts[class_counts < 2].index.tolist()
        logger.warning(
            "Some classes have fewer than 2 samples (encoded classes: %s) — "
            "falling back to a non-stratified split. This is expected for "
            "extremely rare attack types (e.g. Heartbleed has ~11 rows in "
            "the full real dataset); it will not happen once trained on "
            "the complete CIC-IDS2017 files.",
            rare_classes,
        )

    X_train, X_test, y_train, y_test = train_test_split(
        encoded.X,
        encoded.y,
        test_size=test_size,
        random_state=random_state,
        stratify=encoded.y if can_stratify else None,
    )
    logger.info("Train/test split: %d train rows, %d test rows.", len(X_train), len(X_test))

    logger.info("=== Step 5/5: Saving artifacts ===")
    X_train.assign(attack_type_encoded=y_train.values).to_csv(output_dir / "train.csv", index=False)
    X_test.assign(attack_type_encoded=y_test.values).to_csv(output_dir / "test.csv", index=False)
    joblib.dump(encoded.scaler, output_dir / "scaler.joblib")
    joblib.dump(encoded.label_encoder, output_dir / "label_encoder.joblib")
    logger.info("Saved train.csv, test.csv, scaler.joblib, label_encoder.joblib to %s", output_dir)

    eda_paths: dict[str, Path] = {}
    if generate_eda:
        logger.info("Generating EDA report...")
        eda_paths = generate_eda_report(
            df_for_eda,
            encoded.X,
            encoded.y,
            attack_type_column="attack_type",
            output_dir=output_dir / "eda",
        )

    return PreprocessingResult(
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        feature_columns=encoded.feature_columns,
        class_names=list(encoded.label_encoder.classes_),
        eda_plot_paths=eda_paths,
    )


if __name__ == "__main__":
    import sys

    src = sys.argv[1] if len(sys.argv) > 1 else "datasets/cic_ids2017/raw"
    result = run_preprocessing_pipeline(src)
    print(f"Done. Classes: {result.class_names}")
    print(f"Train shape: {result.X_train.shape}, Test shape: {result.X_test.shape}")
