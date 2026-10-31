"""
Retrieval service — the query-time half of RAG.

Ingestion (rag/ingestion/ingest_knowledge_base.py) happens once, offline.
This module is what runs on every query: embed the query text, search
the relevant Qdrant collection(s), return the most semantically similar
documents. This is what Module 8's Knowledge Agent will call directly.
"""

from dataclasses import dataclass

from ai_engine.utils.logging_utils import get_logger
from rag.vector_store.embedding_model import EMBEDDING_DIM, EmbeddingModel
from rag.vector_store.qdrant_store import VectorStore, get_qdrant_client

logger = get_logger(__name__)

COLLECTIONS = ("mitre_attck", "cve", "security_policies")


@dataclass
class RetrievedDocument:
    doc_id: str
    score: float
    source: str  # which collection this came from
    payload: dict


class RetrievalService:
    def __init__(
        self,
        local_path: str | None = "rag/vector_store/qdrant_data",
        embedding_model: EmbeddingModel | None = None,
        qdrant_client=None,
    ):
        self.embedder = embedding_model or EmbeddingModel.get_shared()
        # See the note in rag/ingestion/ingest_knowledge_base.py::ingest_all
        # — pass an existing client via qdrant_client= if one is already
        # open on this local_path in the same process (e.g. tests that
        # ingest and then retrieve without restarting the process).
        client = qdrant_client or get_qdrant_client(local_path=local_path)
        self.stores: dict[str, VectorStore] = {
            name: VectorStore(client=client, collection_name=name, vector_size=EMBEDDING_DIM) for name in COLLECTIONS
        }

    def search(
        self, query: str, source: str, top_k: int = 3, score_threshold: float | None = None
    ) -> list[RetrievedDocument]:
        """Search ONE collection (source must be one of COLLECTIONS)."""
        if source not in self.stores:
            raise ValueError(f"Unknown source '{source}'. Must be one of {COLLECTIONS}.")

        query_vector = self.embedder.embed(query)
        results = self.stores[source].search(query_vector, top_k=top_k, score_threshold=score_threshold)
        return [RetrievedDocument(doc_id=r.id, score=r.score, source=source, payload=r.payload) for r in results]

    def search_all(self, query: str, top_k_per_source: int = 2) -> list[RetrievedDocument]:
        """Search ALL three collections and return combined, per-source results."""
        query_vector = self.embedder.embed(query)
        all_results: list[RetrievedDocument] = []
        for source, store in self.stores.items():
            results = store.search(query_vector, top_k=top_k_per_source)
            all_results.extend(
                RetrievedDocument(doc_id=r.id, score=r.score, source=source, payload=r.payload) for r in results
            )
        return all_results

    def enrich_alert(self, attack_type: str, description: str = "") -> dict[str, list[RetrievedDocument]]:
        """
        Convenience method for the exact use case Module 8's Knowledge
        Agent needs: given a detected attack_type (and optional extra
        context from the alert), fetch relevant MITRE technique(s), CVEs,
        and company policy in one call.
        """
        query = f"{attack_type.replace('_', ' ')} attack. {description}".strip()
        return {
            "mitre_attck": self.search(query, source="mitre_attck", top_k=2),
            "cve": self.search(query, source="cve", top_k=2),
            "security_policies": self.search(query, source="security_policies", top_k=2),
        }
