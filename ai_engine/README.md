# Module 5 — Dataset Preprocessing

Cleans, engineers, and encodes the CIC-IDS2017 dataset into a form ready
for Module 6 (AI model training): Isolation Forest for anomaly detection
and XGBoost for attack classification.

## What this pipeline does, step by step

1. **Load** — reads the raw CIC-IDS2017 CSV file(s) and normalizes column
   names (the original files have inconsistent leading/trailing whitespace).
2. **Clean** — replaces `+/-Infinity` values (a known quirk: `Flow Bytes/s`
   and `Flow Packets/s` divide by a flow duration that's sometimes 0) with
   NaN, drops duplicate rows, and imputes remaining missing numeric values
   with the column median.
3. **Select & engineer features** — keeps a well-established ~20-feature
   subset (flow timing, packet size statistics, flag counts) instead of
   all 78 raw columns, drops any that turn out to be constant, and adds
   one engineered feature: `bytes_per_packet`.
4. **Encode & scale** — maps CIC-IDS2017's 15 raw attack labels onto
   AEGIS-X's 8 `attack_type` categories (see `pipelines/label_mapper.py`
   — this mapping is the single source of truth also used by the backend's
   `attack_type` enum), then scales all numeric features to zero mean /
   unit variance with `StandardScaler`.
5. **Split & save** — stratified 80/20 train/test split, and saves
   `train.csv`, `test.csv`, the fitted `scaler.joblib`, and
   `label_encoder.joblib` — the last two are what Module 6's inference
   code will load to score live traffic exactly the way training data
   was scaled.
6. **EDA report** — generates three plots: attack type distribution,
   feature correlation matrix, and feature importance (via a quick
   diagnostic RandomForest — not the production model).

## Running it on the real dataset

This pipeline was built and tested using a synthetic sample (see
"About the test data" below), because the sandbox this was built in
can't reach the official CIC-IDS2017 hosting server. To run it on the
real dataset:

1. Download **MachineLearningCSV.zip** from the official source:
   https://www.unb.ca/cic/datasets/ids-2017.html
   (or search "CIC-IDS2017" on Kaggle for a mirror)
2. Unzip it into `datasets/cic_ids2017/raw/` — you should end up with
   8 CSV files like `Monday-WorkingHours.pcap_ISCX.csv`,
   `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`, etc.
3. Install dependencies and run:
   ```bash
   pip install -r ai_engine/requirements.txt
   python -m ai_engine.pipelines.preprocessing_pipeline datasets/cic_ids2017/raw
   ```
4. Output lands in `datasets/processed/`: `train.csv`, `test.csv`,
   `scaler.joblib`, `label_encoder.joblib`, and `eda/*.png`.

The pipeline automatically combines all 8 files, so no manual merging is
needed.

## About the test data

`ai_engine/utils/synthetic_data_generator.py` generates a ~15,000-row
sample that matches CIC-IDS2017's real column structure and realistic
class imbalance (mostly benign traffic, with attack types generated at
proportions similar to the real dataset). It's used only so this
pipeline's automated tests can run without needing the actual multi-GB
dataset on disk. **It is not real captured network traffic** — swap in
the real dataset before training the actual detection models in Module 6.

To regenerate it:
```bash
python -m ai_engine.utils.synthetic_data_generator
```

## Tests

```bash
pip install -r ai_engine/requirements.txt
pytest ai_engine/tests/ -v
```

34 tests covering: infinite-value/duplicate/missing-value handling, label
mapping correctness (all 15 raw CIC-IDS2017 labels against all 8 backend
attack types), feature selection/engineering, encoding/scaling
correctness, and a full end-to-end integration test of the pipeline
(including the artifact-reload round-trip Module 6 depends on).

## Label mapping reference

| Raw CIC-IDS2017 label | AEGIS-X attack_type |
|---|---|
| BENIGN | `normal` |
| DDoS | `ddos` |
| DoS Hulk / GoldenEye / slowloris / Slowhttptest | `other` |
| PortScan | `port_scan` |
| FTP-Patator / SSH-Patator | `brute_force` |
| Bot | `botnet` |
| Web Attack – Brute Force / XSS | `web_attack` |
| Web Attack – Sql Injection | `sql_injection` |
| Infiltration / Heartbleed | `other` |

This keeps the AI model's output vocabulary identical to the
`AttackType` enum the backend API already accepts (see
`backend/app/core/enums.py`), so Module 6 can write a prediction
straight into the `alerts` table with no translation step.
