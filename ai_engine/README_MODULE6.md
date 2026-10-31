# Module 6 — AI Models

Trains and serves the two detection models called for in the spec:
**Isolation Forest** (anomaly detection) and **XGBoost** (attack
classification), plus **SHAP** explainability and MITRE ATT&CK mapping —
on top of the data Module 5 prepared.

## How the two models work together

- **Isolation Forest** — trained UNSUPERVISED, on normal traffic only.
  Answers: *"does this look unusual at all?"* It can flag something as
  anomalous even if it's a brand-new attack type the classifier below has
  never seen labeled examples of.
- **XGBoost** — trained SUPERVISED, on all 8 attack_type classes.
  Answers: *"given it's unusual, what specific kind of attack does it
  most resemble?"*

These are deliberately complementary, not redundant — that's why the
project spec calls for both instead of just one classifier.

## Pipeline

```
DetectionService.detect(raw_features)
    |
    +--> scale features (Module 5's saved StandardScaler)
    +--> Isolation Forest -> anomaly_score (0-1)
    +--> XGBoost -> attack_type + confidence (0-1)
    +--> risk_scoring.py -> risk_score (0-100) + severity
    +--> mitre_mapping.py -> MITRE ATT&CK technique
    +--> SHAP -> human-readable "why" explanation
    |
    v
DetectionOutput  (field names match backend AlertCreate schema exactly)
```

`DetectionOutput`'s fields (`title`, `source`, `attack_type`, `severity`,
`anomaly_score`, `risk_score`, `confidence`, `mitre_technique_id`,
`mitre_technique_name`, `raw_event`) line up directly with
`backend/app/schemas/alert.py::AlertCreate` — Module 9 (Integration) can
POST this straight to `/api/v1/alerts` with no translation step.

## Running it

```bash
pip install -r ai_engine/requirements.txt

# 1. Preprocessing (Module 5) must have already run:
python -m ai_engine.pipelines.preprocessing_pipeline datasets/cic_ids2017/raw

# 2. Train both models on the preprocessed output:
python -m ai_engine.training.train_pipeline
```

Output lands in:
- `models/artifacts/isolation_forest.joblib`, `xgboost_classifier.joblib`
- `models/metadata/training_metadata.json` — accuracy, per-class
  precision/recall/F1, training timestamp, feature list
- `models/metadata/confusion_matrix.png`

## Results on the synthetic sample

**97.82% test accuracy, 0.73 macro F1** across all 8 classes. The one
weak class is `sql_injection`, with only 3 test-set rows total — too few
to learn from reliably. This is an honest, expected limitation of any
rare class, not a bug (the real dataset's rarest class, Heartbleed, has a
similar problem: ~11 total rows).

**These numbers are from the synthetic sample, not real attack traffic**
— see Module 5's README for how to run this on the real CIC-IDS2017
dataset. Expect real numbers to differ; the synthetic generator's
attack-type distributions are simplified approximations, not captured
network behavior.

## Bugs found and fixed while building this

1. **Label index mismatch (real bug, not cosmetic):** `sklearn.LabelEncoder`
   always sorts classes alphabetically internally, regardless of the
   order you pass in. The training script initially assumed `"normal"`
   was always index `0` (its position in our declared `ATTACK_TYPES`
   tuple) — but the encoder actually assigned it index `3`. This silently
   trained the "normal-only" Isolation Forest on `botnet` traffic instead.
   Fixed by always reading the class order from the actual saved
   `LabelEncoder`, never re-deriving it.
2. **Risk score inflation for benign traffic:** the risk formula
   originally gave classification confidence a flat weight regardless of
   attack type — so being 100%-confident traffic was `normal` still added
   ~25 points toward risk, pushing confidently-benign traffic into
   "medium" severity. Fixed so confidence only counts as a risk-increasing
   signal when the traffic was actually classified as an attack; normal
   traffic's risk score now comes from the anomaly score alone (so a
   genuinely novel pattern can still surface, without confidently-normal
   traffic being falsely flagged).
3. **XGBoost crash on <=2 classes:** an explicitly hardcoded
   `objective="multi:softprob"` broke for binary classification (used only
   in fast unit tests, not the real 8-class case, but still a latent bug).
   Fixed by letting `XGBClassifier` auto-select the correct objective.

All three were caught by actually running the pipeline end-to-end and
inspecting the numbers, not just from the code compiling — e.g. bug #1
was caught by noticing "120 normal-traffic rows" looked wrong (normal
should be the majority class, not a rare one).

## Tests

```bash
pytest ai_engine/tests/ -v
```

66 tests total (34 from Module 5 + 32 new for Module 6): Isolation Forest
correctness (outlier scores really are higher than typical points),
XGBoost correctness and save/load round-trips, risk scoring (including a
regression test for bug #2 above), MITRE mapping completeness, SHAP
explanation structure, and a full integration test that runs
preprocessing -> training -> live detection end-to-end and checks the
output against the backend's `AlertCreate` schema fields.
