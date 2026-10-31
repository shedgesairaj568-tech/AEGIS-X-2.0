"""
Qdrant vector store client wrapper.

Supports two modes via the SAME code path:

  - LOCAL/EMBEDDED (default here, no server needed): QdrantClient(path=...)
    runs Qdrant entirely in-process, persisting to a local directory. This
    is what lets this module's tests and this development environment run
    without standing up a separate Qdrant server.
  - REMOTE SERVER (production): QdrantClient(url=...) points at a real
    Qdrant instance (e.g. the official Docker image). Swapping modes is a
    one-line change in how get_qdrant_client() is called — nothing else
    in this codebase needs to change, since both modes expose the
    identical client API.

Qdrant stores each document as one point: a vector (the embedding) plus
a payload (the original text and metadata) so a search result can return
the human-readable source document, not just a bare vector.

IMPORTANT: embedded/local mode locks its entire storage folder for the
lifetime of the client — only ONE QdrantClient may have a given
local_path open at a time. Since this project uses multiple collections
(mitre_attck, cve, security_policies) that all live in the same local
storage folder, callers must build ONE shared client via
get_qdrant_client() and pass it into every VectorStore instance, rather
than letting each VectorStore create its own client.
"""

import uuid
from dataclasses import dataclass

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


def get_qdrant_client(local_path: str | None = "rag/vector_store/qdrant_data", url: str | None = None) -> QdrantClient:
    """
    Build ONE client, shared across every VectorStore/collection that
    uses the same storage location. Pass this same instance to each
    VectorStore(client=...) call — do not construct multiple clients
    against the same local_path.
    """
    if url:
        logger.info("Connecting to remote Qdrant server at %s", url)
        return QdrantClient(url=url)
    logger.info("Using embedded local Qdrant at %s", local_path)
    return QdrantClient(path=local_path)


@dataclass
class SearchResult:
    id: str
    score: float  # cosine similarity, higher = more relevant
    payload: dict


class VectorStore:
    def __init__(self, client: QdrantClient, collection_name: str, vector_size: int):
        self.client = client
        self.collection_name = collection_name
        self.vector_size = vector_size
        self._ensure_collection()

    def _ensure_collection(self) -> None:
        existing = [c.name for c in self.client.get_collections().collections]
        if self.collection_name not in existing:
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=qmodels.VectorParams(size=self.vector_size, distance=qmodels.Distance.COSINE),
            )
            logger.info("Created Qdrant collection '%s' (dim=%d)", self.collection_name, self.vector_size)

    def upsert(self, doc_id: str, vector: list[float], payload: dict) -> None:
        """
        doc_id: a stable string ID (e.g. "T1110", "CVE-2021-44228") — we
        deterministically derive a UUID from it, since Qdrant requires
        point IDs to be either an integer or a UUID, not an arbitrary
        string. Using a deterministic UUID (not random) means re-ingesting
        the same doc_id always updates the same point instead of creating
        a duplicate.
        """
        point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, doc_id))
        self.client.upsert(
            collection_name=self.collection_name,
            points=[qmodels.PointStruct(id=point_id, vector=vector, payload={**payload, "doc_id": doc_id})],
        )

    def upsert_batch(self, docs: list[tuple[str, list[float], dict]]) -> None:
        points = [
            qmodels.PointStruct(
                id=str(uuid.uuid5(uuid.NAMESPACE_DNS, doc_id)), vector=vector, payload={**payload, "doc_id": doc_id}
            )
            for doc_id, vector, payload in docs
        ]
        self.client.upsert(collection_name=self.collection_name, points=points)
        logger.info("Upserted %d documents into '%s'.", len(points), self.collection_name)

    def search(
        self, query_vector: list[float], top_k: int = 5, score_threshold: float | None = None
    ) -> list[SearchResult]:
        response = self.client.query_points(
            collection_name=self.collection_name,
            query=query_vector,
            limit=top_k,
            score_threshold=score_threshold,
        )
        return [
            SearchResult(id=r.payload.get("doc_id", str(r.id)), score=r.score, payload=r.payload)
            for r in response.points
        ]

    def count(self) -> int:
        return self.client.count(collection_name=self.collection_name).count
