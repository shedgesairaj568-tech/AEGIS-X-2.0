# AEGIS-X — Testing Strategy

## Philosophy

Every module in this project was tested the same way as it was built,
not afterward: write the code, run it for real against real (or
realistic synthetic) data, read the actual output critically, fix what's
wrong, and only then write the automated test that locks the fix in.
Several real bugs were caught this way that a code review alone would
have missed — see "Bugs found through testing" below.

## Test pyramid

```
                    ▲
                   /2\        Full-stack (Module 9): real server,
                  /----\      real HTTP, real trained models
                 / 155  \
                /  unit/  \   Unit + integration tests per module
               / integr.  \  (mocked dependencies where appropriate,
              /------------\ real logic under test)
             /   Manual      \
            /  verification   \  Every module manually run against
           /____________________\ real data before automated tests
                                    were even written
```

**Manual verification first, always.** Before any automated test was
written for a module, that module was run for real — a real server
started, real HTTP requests sent, real model predictions inspected, real
plots visually checked. This is what caught bugs automated tests alone
would have missed, because the automated tests were often *written
after* discovering a bug this way, specifically to prevent it recurring.

## What's tested, by module

| Module | Test count | What's covered |
|---|---|---|
| Backend (2-3) | 15 | Auth flow (register/login/refresh/me), Alert CRUD, history auto-logging, related-alerts correlation endpoint |
| AI Models (5-6) | 66 | Data cleaning (infinity/duplicate/NaN handling), label mapping, feature engineering, Isolation Forest, XGBoost, risk scoring, MITRE mapping, SHAP, full training pipeline |
| RAG (7) | 25 | Embedding (including offline fallback), Qdrant CRUD, ingestion, retrieval correctness (a query using a document's own vocabulary must retrieve that document) |
| Multi-Agent AI (8) | 33 | Each agent in isolation (mocked deps), LLM client fallback behavior, full graph integration with real trained models |
| Integration (9) | 16 | Backend HTTP client (auth, retry-on-401), pipeline connector, **2 full-stack tests with a real live server** |
| **Total** | **155** | |

## Why some tests use mocks and some use the real thing

- **Fast unit tests (mocked dependencies)**: for testing *logic* —
  "does the Investigation Agent correlate correctly given this input?"
  doesn't need a real database or trained model; a mock that returns
  known data is faster and more precise for isolating that one behavior.
- **Slow full-stack tests (real everything)**: for testing *integration*
  — "does a detected DDoS actually become a queryable alert in a real
  database?" can only be answered by actually doing it. Two tests in
  Module 9 start a real uvicorn server in a background thread, train
  real models, ingest a real vector store, and verify results via real
  HTTP GET requests afterward — not assertions on mocked call arguments.

Both kinds matter. Mocked tests alone can pass while the real pieces
don't fit together (this happened — see bugs below); real-only tests
would be too slow to run constantly during development.

## Running everything

```bash
python tests/health_check.py         # confirm the environment is set up correctly
python tests/run_all_tests.py        # run every suite, one consolidated summary
python tests/run_all_tests.py --fast # skip the 2 slow full-stack tests (~10s saved)
python tests/run_all_tests.py --module agents  # run just one suite
```

## Bugs found through testing (not through code review)

These are documented in more detail in each module's own README, but
collected here to show the pattern — every one of these looked correct
on paper and was only caught by actually running the system:

1. **Module 6**: `sklearn.LabelEncoder` silently sorts classes
   alphabetically regardless of input order — caused the "normal-only"
   anomaly detector to train on `botnet` traffic instead. Caught by
   noticing a suspiciously low training row count.
2. **Module 6**: Risk score formula gave confidently-benign traffic a
   flat ~25 points just for high classification confidence, pushing it
   into "medium" severity. Caught by inspecting actual risk scores on
   real predictions, not just checking they were in range.
3. **Module 8**: The Knowledge Agent's retrieval query was polluted with
   raw SHAP explanation text (ML feature names meaningless to a security
   policy document), causing two *different* attack types to retrieve
   the *same wrong* company policy. Caught by comparing real retrieval
   results across two different alerts side by side.
4. **Module 9**: Two different, disagreeing definitions of "is this
   anomalous" existed in different files — one used for the alert's
   *title*, a different one for the *routing decision* — producing
   alerts whose title contradicted what the system actually did with
   them. Caught by reading live pipeline output critically instead of
   just checking it didn't crash.

Every one of these bugs is now covered by a regression test specifically
named after what it prevents (e.g.
`test_is_anomaly_reflects_isolation_forest_decision_not_a_score_threshold`),
so the same mistake can't silently reappear.

## Known test environment limitations (and why they don't undermine the results)

Two external dependencies weren't reachable from the sandbox this project
was built in:
- **huggingface.co** (real embedding model download) — Module 7 built and
  tested an honest offline fallback; both paths share the identical
  interface, so real deployment needs zero code changes.
- **Anthropic API key** (real LLM generation) — Module 8 built and tested
  the deterministic template fallback the same way.

Both fallbacks are real, tested, functional code paths — not stubs — and
`tests/health_check.py` reports which mode is active so this is never a
silent surprise.
