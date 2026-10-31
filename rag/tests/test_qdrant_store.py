"""
Tests for rag.vector_store.qdrant_store.

Uses a fresh temp-directory local Qdrant instance per test (via the
`vector_store` fixture) so tests never interfere with each other or with
the real ingested knowledge base.
"""

import pytest

from rag.vector_store.qdrant_store import VectorStore, get_qdrant_client

DIM = 8


@pytest.fixture
def vector_store(tmp_path):
    client = get_qdrant_client(local_path=str(tmp_path / "qdrant_test_data"))
    return VectorStore(client=client, collection_name="test_collection", vector_size=DIM)


def _fake_vector(seed: float) -> list[float]:
    """Simple deterministic fake embedding for testing, not real semantics."""
    return [seed] * DIM


def test_upsert_and_count(vector_store):
    vector_store.upsert("doc1", _fake_vector(0.1), {"text": "hello"})
    assert vector_store.count() == 1


def test_upsert_batch_and_count(vector_store):
    docs = [
        ("doc1", _fake_vector(0.1), {"text": "a"}),
        ("doc2", _fake_vector(0.2), {"text": "b"}),
        ("doc3", _fake_vector(0.3), {"text": "c"}),
    ]
    vector_store.upsert_batch(docs)
    assert vector_store.count() == 3


def test_upsert_same_doc_id_updates_not_duplicates(vector_store):
    vector_store.upsert("doc1", _fake_vector(0.1), {"text": "original"})
    vector_store.upsert("doc1", _fake_vector(0.1), {"text": "updated"})
    assert vector_store.count() == 1


def test_search_returns_closest_vector_first(vector_store):
    vector_store.upsert("close", _fake_vector(0.5), {"text": "close"})
    vector_store.upsert("far", _fake_vector(-0.9), {"text": "far"})

    results = vector_store.search(_fake_vector(0.5), top_k=2)
    assert results[0].id == "close"


def test_search_respects_top_k(vector_store):
    for i in range(5):
        vector_store.upsert(f"doc{i}", _fake_vector(i * 0.1), {"text": f"doc{i}"})

    results = vector_store.search(_fake_vector(0.0), top_k=2)
    assert len(results) == 2


def test_search_result_payload_contains_original_data(vector_store):
    vector_store.upsert("doc1", _fake_vector(0.1), {"text": "important content", "extra_field": 42})

    results = vector_store.search(_fake_vector(0.1), top_k=1)
    assert results[0].payload["text"] == "important content"
    assert results[0].payload["extra_field"] == 42
