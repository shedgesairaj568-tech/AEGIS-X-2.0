# Module 9 — Integration

Connects Modules 6, 7, and 8 to the real backend (Modules 2/3): a
detected attack now becomes an actual `Alert` row in the database, with
its investigation timeline and incident report attached — queryable
through `/docs` like any other alert.

## What's new

| File | Purpose |
|---|---|
| `ai_engine/integration/backend_client.py` | HTTP client for the backend API — login, create alert, add history, create report, fetch related alerts. Handles token expiry transparently (401 → re-login → retry once). |
| `ai_engine/integration/pipeline_connector.py` | Runs `InvestigationPipeline.investigate()` and writes the result into the backend via `BackendClient`. |
| `ai_engine/integration/live_feed_runner.py` | Simulates a live feed by replaying dataset rows through the connector — the script you'd run to actually populate a backend with realistic traffic. |
| `backend/app/api/v1/endpoints/alerts.py` | **New endpoint**: `GET /alerts/related` — exposes the correlation lookup the Investigation Agent needs, which wasn't accessible via the API before this module. |

## How correlation actually works end-to-end

The Investigation Agent (Module 8) needs `related_events` as part of the
graph's *initial* state — LangGraph can't fetch it mid-graph. So the flow is:

1. `PipelineConnector` fetches related alerts from the backend **by
   `source_ip` only** (the one correlation key known before detection runs)
2. The graph runs: `ThreatDetectionAgent` determines `attack_type`, then
   `InvestigationAgent` further narrows those pre-fetched events down to
   ones matching the *same* `attack_type` or `source_ip`
3. The connector writes the alert, then (if the router didn't skip
   investigation) a `correlation` timeline entry and the final report

Verified this actually works, not just that it doesn't crash: ran 6
DDoS events from a source IP that repeats every 5 events — the 6th event
correctly showed `correlated_event_count: 1`, correlating with the 1st.

## Running it yourself

```bash
# 1. Start the real backend (Module 2/3) — see backend/README or docker-compose
# 2. Register a service account for the pipeline to authenticate as:
curl -X POST http://localhost:8000/api/v1/auth/register -H "Content-Type: application/json" \
  -d '{"email":"pipeline@aegis-x.io","full_name":"AI Pipeline Service","password":"changeme123"}'

# 3. Make sure Module 6's models are trained and Module 7's vector store is ingested:
python -m ai_engine.training.train_pipeline
python -m rag.ingestion.ingest_knowledge_base

# 4. Run the live feed:
python -m ai_engine.integration.live_feed_runner \
  --backend-url http://localhost:8000 \
  --email pipeline@aegis-x.io \
  --password changeme123 \
  --max-rows 20
```

Then check `http://localhost:8000/docs` -> `GET /api/v1/alerts` — real
detected alerts, with real timelines and reports, sitting in your actual
database.

## A real bug found and fixed while building this

**Two disagreeing definitions of "is anomaly" in different places.**
`DetectionService.detect()` (Module 6) internally computes the *real*
Isolation Forest anomaly decision, but `DetectionOutput` never exposed
it as a field — so `ThreatDetectionAgent` (Module 8) had no choice but
to re-derive its own approximation (`anomaly_score >= 0.5`), which
disagreed with the real decision in edge cases.

This produced a genuinely confusing, self-contradictory result caught by
watching real live-feed output: a BENIGN row got the title **"Anomalous
traffic (unclassified)"** (from the real Isolation Forest decision used
inside `DetectionService`) but was simultaneously routed as
**"confidently normal"** and had its full investigation *skipped* (from
the agent's separate, disagreeing re-derivation) — the alert's own title
contradicted what the system actually did with it.

**Fixed** by adding `is_anomaly: bool` directly to `DetectionOutput` as
the single source of truth, and having `ThreatDetectionAgent` read it
directly instead of re-deriving anything. Re-ran the same scenario after
the fix: the row now correctly shows `investigated=True`, matching its
"Anomalous" title. Covered by a regression test
(`test_is_anomaly_reflects_isolation_forest_decision_not_a_score_threshold`).

This is exactly the kind of bug that's easy to miss from reading code in
isolation — both pieces of code were individually reasonable — and was
only caught by actually running the full system end-to-end against real
data and reading the output critically.

## Tests

```bash
pytest ai_engine/integration/tests/ -v
```

16 tests:
- **7 fast, mocked tests** for `BackendClient` (auth flow, 401-retry,
  correct endpoints/params for every operation)
- **7 fast, mocked tests** for `PipelineConnector` (correct backend calls
  for both the "skip" and "full investigation" branches, correlation
  lookup failure doesn't block detection)
- **2 full-stack tests** that start a REAL uvicorn server in a background
  thread, train real models, ingest a real vector store, and verify —
  via real HTTP requests, not mocks — that alerts and reports are
  genuinely queryable back from the database afterward

**Project-wide total: 140 tests passing** across Modules 5-9 (backend's
own 32-test suite from Module 2/3 not re-counted here since it wasn't
changed in this delivery, but its live functionality was directly
exercised by the full-stack tests above).
