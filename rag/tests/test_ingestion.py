"""
Tests for rag.ingestion.ingest_knowledge_base.
"""

import pytest

from rag.ingestion.ingest_knowledge_base import ingest_all
from rag.vector_store.embedding_model import EmbeddingModel


@pytest.fixture(scope="module")
def ingested_stores(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("rag_ingestion_test")
    return ingest_all(local_path=str(tmp_dir / "qdrant_data"))


def test_ingest_all_returns_all_three_collections(ingested_stores):
    assert set(ingested_stores.keys()) == {"mitre_attck", "cve", "security_policies"}


def test_mitre_attck_collection_has_expected_document_count(ingested_stores):
    assert ingested_stores["mitre_attck"].count() == 6


def test_cve_collection_has_expected_document_count(ingested_stores):
    assert ingested_stores["cve"].count() == 5


def test_security_policies_collection_has_expected_document_count(ingested_stores):
    assert ingested_stores["security_policies"].count() == 5


def test_ingested_document_has_expected_payload_fields(ingested_stores):
    query_vector = EmbeddingModel.get_shared().embed("brute force attack")
    results = ingested_stores["mitre_attck"].search(query_vector, top_k=1)

    assert len(results) == 1
    assert "text" in results[0].payload
    assert "id" in results[0].payload
    assert "name" in results[0].payload
