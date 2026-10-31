"""
CIC-IDS2017 data loader.

The real dataset (MachineLearningCSV.zip from the official CIC source)
ships as 8 separate CSV files, one per day/time-of-day
(e.g. "Monday-WorkingHours.pcap_ISCX.csv",
"Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"). This loader combines
all of them into one DataFrame and immediately fixes two well-documented
quirks in the raw files:

1. Column names have inconsistent leading/trailing whitespace
   (e.g. " Destination Port" with a leading space) — this is a known
   quirk of the original CICFlowMeter export, not something we introduced.
2. The "Label" column's text encoding is inconsistent between files (some
   rows use a proper hyphen, others an en-dash/mojibake byte) — handled in
   label_mapper.py, not here, but flagged since it's related.
"""

from pathlib import Path

import pandas as pd

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


def _clean_column_name(name: str) -> str:
    return name.strip()


def load_cic_ids2017(source: str | Path) -> pd.DataFrame:
    """
    Load CIC-IDS2017 data from either:
      - a directory containing one or more of the original CSV files, or
      - a single CSV file path (e.g. our synthetic sample for testing).

    Returns one combined DataFrame with cleaned column names. Does NOT
    clean the data itself (missing values, duplicates, etc.) — that's
    data_cleaner.py's job. This function's only responsibility is
    "get the raw rows into a DataFrame reliably".
    """
    source = Path(source)

    if source.is_dir():
        csv_paths = sorted(source.glob("*.csv"))
        if not csv_paths:
            raise FileNotFoundError(
                f"No CSV files found in '{source}'. Expected the original "
                f"CIC-IDS2017 CSV files (e.g. 'Monday-WorkingHours.pcap_ISCX.csv') "
                f"or a preprocessed sample CSV."
            )
        logger.info("Loading %d CSV file(s) from %s", len(csv_paths), source)
        frames = [pd.read_csv(p, low_memory=False, encoding="latin1") for p in csv_paths]
        df = pd.concat(frames, ignore_index=True)
    elif source.is_file():
        logger.info("Loading single CSV file: %s", source)
        df = pd.read_csv(source, low_memory=False, encoding="latin1")
    else:
        raise FileNotFoundError(f"'{source}' does not exist.")

    df.columns = [_clean_column_name(c) for c in df.columns]
    logger.info("Loaded %d rows, %d columns.", len(df), len(df.columns))
    return df
