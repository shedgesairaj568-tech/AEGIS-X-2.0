# Module 8 — Multi-Agent AI

Four AI agents, orchestrated with LangGraph, that turn a raw network flow
into a fully investigated, explained, and mitigated security incident —
using everything built in Modules 6 and 7.

## The four agents

| Agent | Responsibility | Built on |
|---|---|---|
| **Threat Detection Agent** | Detect attacks, calculate anomaly score, generate risk score | Module 6 (`DetectionService`) |
| **Investigation Agent** | Correlate events, build attack timeline, find root cause | Simple, explainable heuristics (not a black-box model — an analyst needs to audit *why* events were linked) |
| **Knowledge Agent** | Search vector DB, retrieve MITRE ATT&CK, CVE, company policy | Module 7 (`RetrievalService`) |
| **Response Agent** | Generate mitigation, generate incident report, suggest response | Real LLM (Anthropic API) for high/critical alerts, deterministic template otherwise |

## The graph

```
ThreatDetectionAgent
        |
  [router: confidently normal traffic?]
    /                        \
  yes                         no
   |                           |
  END                 InvestigationAgent
                               |
                        KnowledgeAgent
                               |
                        ResponseAgent
                               |
                              END
```

The conditional edge after detection is a deliberate design choice, not
just a LangGraph feature demo: there's no reason to spend a vector search
(and potentially an LLM call) investigating traffic the Threat Detection
Agent is confident is benign. Verified this actually works — normal
traffic short-circuits straight to `END` with `investigation`,
`knowledge`, and `response` correctly never populated.

## Running it

```bash
pip install -r ai_engine/requirements.txt -r rag/requirements.txt -r ai_engine/agents/requirements.txt

python -m rag.ingestion.ingest_knowledge_base   # if not already done (Module 7)
python -m ai_engine.training.train_pipeline     # if not already done (Module 6)
```

```python
from ai_engine.agents.graph import InvestigationPipeline

pipeline = InvestigationPipeline()
result = pipeline.investigate(raw_features)  # raw_features: dict of the Module 5 feature columns

print(result["detection"])       # attack_type, severity, risk_score, ...
print(result["investigation"])   # timeline, root_cause_hypothesis
print(result["knowledge"])       # relevant MITRE/CVE/policy docs
print(result["response"])        # final incident report: summary, root_cause, mitigation
```

## The LLM: real API + honest fallback

`ai_engine/agents/llm_client.py` calls the real Anthropic API when
`ANTHROPIC_API_KEY` is set in the environment. **This sandbox has no API
key available**, so this module was built and tested entirely against
the fallback path — same honest situation as Module 7's embedding model.

The fallback isn't just "no key = broken": it's a deterministic template
generator that assembles a report directly from the structured data the
other three agents already gathered (SHAP explanation, MITRE technique,
CVE, and policy text) — genuinely useful output, not a placeholder.

**On your machine:** set `ANTHROPIC_API_KEY` in your environment (get one
from https://console.anthropic.com) and the Response Agent will
automatically use real LLM generation for high/critical severity alerts —
no code changes needed. Low/medium severity alerts use the template path
by design even with a key configured (see `USE_LLM_FOR_SEVERITIES` in
`llm_client.py`) — spending an LLM call on every single low-severity
alert isn't worth it in a real deployment with high alert volume.

```bash
# to enable real LLM generation:
export ANTHROPIC_API_KEY="your-key-here"
```

## Verified output (using the template fallback)

Running the full pipeline on a real DDoS sample from the synthetic
dataset:

```
attack_type: ddos, severity: critical, risk_score: 93.99
mitigation: "MITRE-recommended mitigation: Deploy rate limiting and
traffic filtering at network edges... Per company policy 'DDoS Response
Procedure': Upon detection of a suspected DDoS attack (sustained traffic
exceeding 3x baseline for over 2 minutes from more than 20 distinct
source IPs)..."
```

Correctly cites the DDoS-specific MITRE technique (T1498) and the
DDoS-specific company policy (POL-002) — not a generic or mismatched one.

## Two real bugs found and fixed while building this

1. **Query pollution in the Knowledge Agent (the important one):** the
   first version passed the Threat Detection Agent's raw SHAP explanation
   text (e.g. `"Flagged mainly due to: Total Fwd Packets (3.07), Average
   Packet Size (1.91)"`) into the retrieval query. Those ML feature names
   are meaningless to a security policy document and actively diluted the
   query — caught because BOTH a DDoS alert and a PortScan alert were
   retrieving the same wrong policy (a generic web-attack one) instead of
   their own specific, obviously-correct policies. Fixed by using the
   clean MITRE technique name as query context instead of the noisy SHAP
   text. Covered by a regression test
   (`test_run_uses_mitre_technique_name_not_raw_shap_explanation`).

2. **Qdrant client lock conflict (same root cause as a Module 7 bug, new
   location):** running ingestion and retrieval in the same process (as
   the integration test does) opened two separate `QdrantClient`
   instances on the same local storage path, which Qdrant's embedded mode
   forbids. Fixed by letting both `ingest_all()` and `RetrievalService`
   accept an optional pre-built shared client.

Both were caught by actually running the full pipeline end-to-end on real
data and inspecting the output, not from the code merely running without
errors — bug #1 in particular produced results that "worked" (no crash,
plausible-looking text) but were factually wrong, which is the more
dangerous kind of bug in a system meant to inform real security
decisions.

## Tests

```bash
pytest ai_engine/agents/tests/ -v
```

32 tests: each agent tested in isolation with mocked dependencies (fast,
no trained models needed), the LLM client's fallback and real-call paths,
the Response Agent's severity-gated LLM-vs-template routing, and a full
integration test that trains real models, ingests a real vector store,
and runs the complete graph end-to-end — including forcing both the
"skip" and "full investigation" branches of the router to confirm the
conditional routing actually works, not just that it compiles.

**Project-wide total: 123 tests passing** across Modules 5, 6, 7, and 8.
