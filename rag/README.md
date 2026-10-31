# Module 7 — RAG (Retrieval-Augmented Generation)

Gives AEGIS-X the ability to look up MITRE ATT&CK technique details,
relevant CVEs, and company security policy — so alerts can be enriched
with real context instead of just a bare classification label. This is
what the Knowledge Agent (Module 8) will call directly.

## Architecture

```
Knowledge base (JSON files)
    |
    v
Ingestion  ---embed each doc--->  Qdrant vector store (3 collections:
                                    mitre_attck, cve, security_policies)
                                        ^
                                        | semantic search
                                        |
Query text  ---embed query--->  RetrievalService.search() / enrich_alert()
```

- **`rag/knowledge_base/`** — the source data: 6 MITRE ATT&CK techniques
  (matching the ones our AI models reference — see Module 6), 5 CVE
  records, 5 original company security policies.
- **`rag/vector_store/`** — the embedding model wrapper and the Qdrant
  client wrapper.
- **`rag/ingestion/`** — loads the JSON, embeds each document, upserts
  into Qdrant. Run once (or whenever the knowledge base changes).
- **`rag/retrieval/`** — the query-time search service. `enrich_alert()`
  is the convenience method Module 8 will call: given an attack_type,
  get back relevant MITRE + CVE + policy documents in one call.

## Running it

```bash
pip install -r rag/requirements.txt

# One-time: embed and load the knowledge base into the vector store
python -m rag.ingestion.ingest_knowledge_base

# Then, in your own code:
from rag.retrieval.retrieval_service import RetrievalService
service = RetrievalService()
results = service.enrich_alert("ddos")
```

**Important — always run ingestion fresh on a new machine, don't copy
`rag/vector_store/qdrant_data/` between environments.** If you ingest
once using the offline fallback embedder (no internet), then later
install `sentence-transformers` successfully, the two embedders produce
vectors from *different, incompatible vector spaces* even though both
happen to be 384-dimensional — comparing a real semantic query vector
against old fallback-embedded documents would silently return meaningless
results with no error. `rag/vector_store/qdrant_data/` is intentionally
NOT included in this delivery for that reason — run
`python -m rag.ingestion.ingest_knowledge_base` fresh after installing
dependencies on your machine, and it will build the store using whichever
embedder is actually available in that environment.

## Two honest limitations, and how they resolve on your machine

**1. Qdrant runs in embedded/local mode here, not as a separate server.**
`qdrant-client` supports running fully in-process, persisting to a local
folder (`rag/vector_store/qdrant_data/`) — no Docker container or
separate Qdrant server needed for development. The exact same client
code points at a real Qdrant server in production by passing a `url=`
instead of a local path (see `get_qdrant_client()` in
`rag/vector_store/qdrant_store.py`) — nothing else in the codebase
changes.

**2. The real embedding model (`all-MiniLM-L6-v2`) needs to download from
huggingface.co on first use — which this sandbox can't reach.** On your
machine, with normal internet access, this happens automatically and
transparently the first time `EmbeddingModel` is constructed (a one-time
~80MB download, then cached locally). To keep this pipeline fully
testable in an environment without that access, `EmbeddingModel`
automatically falls back to a deterministic offline word-hashing embedder
with the identical interface — the code detects the failed download and
switches over with a logged warning, no crash.

**What this means for you:** everything in this module was built and
tested using the fallback embedder, since that's what my environment
had access to. On your machine, the real semantic model will download
and be used automatically — you don't need to change any code. If you
want to confirm this yourself, run the ingestion command above and watch
the log output: you should see `"Loading sentence-transformer model..."`
succeed (no fallback warning), and search results should show noticeably
better semantic matching than the examples below (e.g. a query like
"repeated failed SSH logins" should retrieve the Brute Force technique
even without the literal words "brute force" in the query — the fallback
embedder can only do that if the exact words overlap).

## Verified retrieval results (using the fallback embedder)

```
Query: "brute force password attack"  -> top MITRE match: T1110 Brute Force
Query: "distributed denial of service flood" -> top matches: T1499, T1498 (both DoS-related)
enrich_alert("port_scan", "scanning destination ports discovery")
    -> correctly surfaces T1046 Network Service Discovery
```

Even with the degraded fallback, retrieval correctly surfaces the right
technique when query vocabulary overlaps with the document — confirming
the ingestion -> embedding -> vector search -> retrieval pipeline is
correctly wired end-to-end. The real model will do meaningfully better
on queries that don't share exact words.

## Tests

```bash
pytest rag/tests/ -v
```

25 tests: embedding correctness (including the fallback's determinism
and its "shared vocabulary = higher similarity" property), Qdrant CRUD
operations (upsert, batch upsert, dedup-on-same-id, top-k search
ordering), full ingestion (correct document counts per collection), and
retrieval correctness (including a hard check that a
document's-own-vocabulary query retrieves that exact document as the top
result — not just that search runs without error).

## A real bug found and fixed while building this

**Qdrant embedded mode locks its entire storage folder** — only one
`QdrantClient` may have a given local path open at a time. The first
version of the ingestion code created a separate client per collection
(mitre_attck, cve, policies), all pointed at the same local folder, which
crashed with `RuntimeError: Storage folder ... is already accessed by
another instance`. Fixed by building ONE shared `QdrantClient` via
`get_qdrant_client()` and passing it into every `VectorStore` instance —
collections are namespaces within one client/storage location, not
separate clients.

A second, smaller issue: the installed `qdrant-client` version (1.19.0)
has fully removed the older `.search()` method in favor of
`.query_points()`, which wraps results differently (`response.points`
instead of a bare list). Fixed in `VectorStore.search()`.
