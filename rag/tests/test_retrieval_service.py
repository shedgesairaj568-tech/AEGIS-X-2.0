"""
Tests for rag.retrieval.retrieval_service.

Runs a real ingestion into a temp Qdrant store, then exercises the actual
RetrievalService a Knowledge Agent (Module 8) would use.
"""

import pytest

from rag.ingestion.ingest_knowledge_base import ingest_all
from rag.retrieval.retrieval_service import COLLECTIONS, RetrievalService
from rag.vector_store.embedding_model import EmbeddingModel


@pytest.fixture(scope="module")
def retrieval_service(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("rag_retrieval_test")
    local_path = str(tmp_dir / "qdrant_data")
    embedder = EmbeddingModel.get_shared()

    ingest_all(local_path=local_path)  # populate the store first
    return RetrievalService(local_path=local_path, embedding_model=embedder)


def test_search_single_source_returns_results(retrieval_service):
    results = retrieval_service.search("brute force login attempt", source="mitre_attck", top_k=3)
    assert len(results) > 0
    assert all(r.source == "mitre_attck" for r in results)


def test_search_unknown_source_raises(retrieval_service):
    with pytest.raises(ValueError):
        retrieval_service.search("test query", source="not_a_real_collection")


def test_search_all_covers_every_collection(retrieval_service):
    results = retrieval_service.search_all("network attack", top_k_per_source=1)
    sources_seen = {r.source for r in results}
    assert sources_seen == set(COLLECTIONS)


def test_brute_force_query_retrieves_brute_force_technique_as_top_result(retrieval_service):
    """
    Even with the offline fallback embedder (no internet access to
    huggingface.co in this test environment), a query built from the
    document's own vocabulary should retrieve that exact document first —
    this is the minimum bar for "retrieval actually works" rather than
    just "the code runs without crashing".
    """
    results = retrieval_service.search("brute force techniques password", source="mitre_attck", top_k=1)
    assert results[0].doc_id == "T1110"


def test_enrich_alert_returns_all_three_sources(retrieval_service):
    result = retrieval_service.enrich_alert("port_scan", "many connections to different ports")
    assert set(result.keys()) == set(COLLECTIONS)
    for docs in result.values():
        assert isinstance(docs, list)


def test_enrich_alert_port_scan_surfaces_port_scan_technique(retrieval_service):
    result = retrieval_service.enrich_alert("port_scan", "scanning destination ports discovery")
    top_ids = [d.doc_id for d in result["mitre_attck"]]
    assert "T1046" in top_ids  # Network Service Discovery
