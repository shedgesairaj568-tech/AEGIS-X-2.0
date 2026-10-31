"""
Knowledge base ingestion.

Loads the three JSON knowledge sources (MITRE ATT&CK techniques, CVE
records, security policies), builds one embeddable text blob per
document, embeds them, and upserts into three separate Qdrant
collections. Separate collections (rather than one mixed collection)
because the Knowledge Agent (Module 8) often wants to search within just
one source type — e.g. "find the MITRE technique for this" is a
different query than "find relevant company policy for this".
"""

import json
from pathlib import Path

from ai_engine.utils.logging_utils import get_logger
from rag.vector_store.embedding_model import EMBEDDING_DIM, EmbeddingModel
from rag.vector_store.qdrant_store import VectorStore, get_qdrant_client

logger = get_logger(__name__)

DEFAULT_KB_DIR = Path("rag/knowledge_base")


def _mitre_to_text(doc: dict) -> str:
    return (
        f"{doc['name']} ({doc['id']}, {doc['tactic']} tactic). {doc['description']} "
        f"Mitigation: {doc['mitigation']} Detection notes: {doc['detection_notes']}"
    )


def _cve_to_text(doc: dict) -> str:
    return (
        f"{doc['id']}: {doc['title']} (severity: {doc['severity']}, CVSS {doc['cvss_score']}). "
        f"{doc['summary']} Remediation: {doc['remediation']}"
    )


def _policy_to_text(doc: dict) -> str:
    return f"{doc['title']} ({doc['category']}). {doc['content']}"


def ingest_mitre_attck(
    kb_dir: Path = DEFAULT_KB_DIR,
    qdrant_client=None,
    embedding_model: EmbeddingModel | None = None,
) -> VectorStore:
    docs = json.loads((kb_dir / "mitre_attck" / "techniques.json").read_text())
    embedder = embedding_model or EmbeddingModel.get_shared()
    client = qdrant_client or get_qdrant_client()
    store = VectorStore(client=client, collection_name="mitre_attck", vector_size=EMBEDDING_DIM)

    texts = [_mitre_to_text(d) for d in docs]
    vectors = embedder.embed_batch(texts)
    store.upsert_batch([(d["id"], v, {**d, "text": t}) for d, v, t in zip(docs, vectors, texts)])

    logger.info("Ingested %d MITRE ATT&CK techniques.", len(docs))
    return store


def ingest_cve(
    kb_dir: Path = DEFAULT_KB_DIR,
    qdrant_client=None,
    embedding_model: EmbeddingModel | None = None,
) -> VectorStore:
    docs = json.loads((kb_dir / "cve" / "cve_records.json").read_text())
    embedder = embedding_model or EmbeddingModel.get_shared()
    client = qdrant_client or get_qdrant_client()
    store = VectorStore(client=client, collection_name="cve", vector_size=EMBEDDING_DIM)

    texts = [_cve_to_text(d) for d in docs]
    vectors = embedder.embed_batch(texts)
    store.upsert_batch([(d["id"], v, {**d, "text": t}) for d, v, t in zip(docs, vectors, texts)])

    logger.info("Ingested %d CVE records.", len(docs))
    return store


def ingest_policies(
    kb_dir: Path = DEFAULT_KB_DIR,
    qdrant_client=None,
    embedding_model: EmbeddingModel | None = None,
) -> VectorStore:
    docs = json.loads((kb_dir / "policies" / "security_policies.json").read_text())
    embedder = embedding_model or EmbeddingModel.get_shared()
    client = qdrant_client or get_qdrant_client()
    store = VectorStore(client=client, collection_name="security_policies", vector_size=EMBEDDING_DIM)

    texts = [_policy_to_text(d) for d in docs]
    vectors = embedder.embed_batch(texts)
    store.upsert_batch([(d["id"], v, {**d, "text": t}) for d, v, t in zip(docs, vectors, texts)])

    logger.info("Ingested %d security policies.", len(docs))
    return store


def ingest_all(
    kb_dir: Path = DEFAULT_KB_DIR,
    local_path: str | None = "rag/vector_store/qdrant_data",
    qdrant_client=None,
) -> dict[str, VectorStore]:
    embedder = EmbeddingModel.get_shared()  # load once, reuse for all three
    # ONE shared client for all collections. If the caller already has a
    # client open (e.g. a test that also constructs a RetrievalService
    # against the same local_path in the same process), pass it in via
    # qdrant_client= instead of letting this build a second one — Qdrant's
    # embedded mode locks its storage folder, so two open clients on the
    # same path in one process will raise a RuntimeError.
    client = qdrant_client or get_qdrant_client(local_path=local_path)
    return {
        "mitre_attck": ingest_mitre_attck(kb_dir, client, embedder),
        "cve": ingest_cve(kb_dir, client, embedder),
        "security_policies": ingest_policies(kb_dir, client, embedder),
    }


if __name__ == "__main__":
    stores = ingest_all()
    for name, store in stores.items():
        print(f"{name}: {store.count()} documents")
