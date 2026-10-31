"""
Tests for rag.vector_store.embedding_model.
"""

import numpy as np

from rag.vector_store.embedding_model import EMBEDDING_DIM, EmbeddingModel, _hash_embed


def test_hash_embed_produces_correct_dimension():
    vec = _hash_embed("some example text")
    assert len(vec) == EMBEDDING_DIM


def test_hash_embed_is_normalized():
    vec = _hash_embed("some example text about brute force attacks")
    norm = np.linalg.norm(vec)
    assert abs(norm - 1.0) < 1e-6


def test_hash_embed_is_deterministic():
    vec1 = _hash_embed("brute force attack")
    vec2 = _hash_embed("brute force attack")
    assert vec1 == vec2


def test_hash_embed_empty_string_does_not_crash():
    vec = _hash_embed("")
    assert len(vec) == EMBEDDING_DIM
    assert all(v == 0.0 for v in vec)


def test_shared_texts_produce_more_similar_vectors_than_unrelated_texts():
    """
    Even the crude hashing fallback should give overlapping-vocabulary
    texts higher cosine similarity than completely unrelated ones.
    """
    a = np.array(_hash_embed("brute force password login attack"))
    b = np.array(_hash_embed("brute force login attempt password"))
    c = np.array(_hash_embed("completely unrelated topic about gardening"))

    sim_ab = np.dot(a, b)
    sim_ac = np.dot(a, c)
    assert sim_ab > sim_ac


def test_embedding_model_embed_returns_correct_dimension():
    model = EmbeddingModel.get_shared()
    vec = model.embed("test query about network attacks")
    assert len(vec) == EMBEDDING_DIM


def test_embedding_model_embed_batch_returns_correct_shape():
    model = EmbeddingModel.get_shared()
    vecs = model.embed_batch(["first text", "second text", "third text"])
    assert len(vecs) == 3
    assert all(len(v) == EMBEDDING_DIM for v in vecs)


def test_get_shared_returns_same_instance():
    a = EmbeddingModel.get_shared()
    b = EmbeddingModel.get_shared()
    assert a is b
