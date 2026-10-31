"""
Exploratory Data Analysis (EDA) for the preprocessed CIC-IDS2017 data.

Produces the three graphs called for in the project spec:
  1. Attack distribution — how many samples of each attack type exist
     (reveals the class imbalance that Module 6's training strategy needs
     to account for, e.g. via class weighting).
  2. Correlation matrix — which features move together, useful for
     spotting redundant features and sanity-checking that engineered
     features behave as expected.
  3. Feature importance — which features actually separate attack traffic
     from benign traffic, computed with a quick RandomForest (a full,
     tuned model comes in Module 6; this is diagnostic, not the product).

All three are saved as PNG files rather than displayed inline, since this
runs as a script/pipeline step, not a notebook.
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # non-interactive backend — safe for headless/server execution
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)

sns.set_theme(style="whitegrid")


def plot_attack_distribution(df: pd.DataFrame, attack_type_column: str, output_path: str | Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    counts = df[attack_type_column].value_counts().sort_values(ascending=False)

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(counts.index, counts.values, color="#4C72B0")
    ax.set_yscale("log")  # log scale: benign traffic dwarfs rare attack classes otherwise
    ax.set_ylabel("Number of samples (log scale)")
    ax.set_xlabel("Attack type")
    ax.set_title("Attack Type Distribution")
    plt.xticks(rotation=45, ha="right")

    for bar, count in zip(bars, counts.values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(count), ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    logger.info("Saved attack distribution plot to %s", output_path)
    return output_path


def plot_correlation_matrix(X: pd.DataFrame, output_path: str | Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    corr = X.corr()

    fig, ax = plt.subplots(figsize=(12, 10))
    sns.heatmap(corr, cmap="coolwarm", center=0, square=True, ax=ax, cbar_kws={"shrink": 0.8})
    ax.set_title("Feature Correlation Matrix")
    plt.xticks(rotation=45, ha="right", fontsize=7)
    plt.yticks(fontsize=7)

    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    logger.info("Saved correlation matrix plot to %s", output_path)
    return output_path


def plot_feature_importance(
    X: pd.DataFrame, y: pd.Series, output_path: str | Path, n_estimators: int = 100, random_state: int = 42
) -> Path:
    """
    Fit a quick RandomForest purely to rank feature importance for this
    EDA report. This is NOT the anomaly/classification model itself
    (that's Isolation Forest + XGBoost in Module 6) — it's a fast,
    well-understood way to answer "which features actually matter?"
    before we commit to the real model architecture.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    clf = RandomForestClassifier(n_estimators=n_estimators, random_state=random_state, n_jobs=-1, max_depth=12)
    clf.fit(X, y)

    importances = pd.Series(clf.feature_importances_, index=X.columns).sort_values(ascending=True)

    fig, ax = plt.subplots(figsize=(10, 8))
    ax.barh(importances.index, importances.values, color="#55A868")
    ax.set_xlabel("Importance")
    ax.set_title("Feature Importance (RandomForest, diagnostic only)")

    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    logger.info("Saved feature importance plot to %s", output_path)
    return output_path


def generate_eda_report(
    df_with_labels: pd.DataFrame,
    X: pd.DataFrame,
    y: pd.Series,
    attack_type_column: str,
    output_dir: str | Path,
) -> dict[str, Path]:
    """Generate all three EDA plots and return their output paths."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    return {
        "attack_distribution": plot_attack_distribution(
            df_with_labels, attack_type_column, output_dir / "attack_distribution.png"
        ),
        "correlation_matrix": plot_correlation_matrix(X, output_dir / "correlation_matrix.png"),
        "feature_importance": plot_feature_importance(X, y, output_dir / "feature_importance.png"),
    }
