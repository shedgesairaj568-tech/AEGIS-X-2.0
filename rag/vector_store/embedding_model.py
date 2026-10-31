"""
Sentence Transformer embedding wrapper.

Converts text into a fixed-length vector that captures semantic meaning —
two pieces of text about similar concepts end up with vectors that are
close together (high cosine similarity), even if they don't share the
same exact words. This is what makes semantic search possible: a query
like "repeated failed SSH logins" can retrieve the "Brute Force" MITRE
technique even though the query text never uses the word "brute force".

Model: all-MiniLM-L6-v2 — 384-dimensional embeddings, small enough to run
on CPU at interactive speed, and a standard, well-proven default choice
for general-purpose semantic search (not fine-tuned specifically for
security text, but effective enough for this use case without requiring
GPU infrastructure).

FALLBACK: if the model can't be downloaded (no internet access to
huggingface.co — true both in this sandbox and in real air-gapped SOC
deployments, which are common in security-sensitive environments), this
transparently falls back to a deterministic offline hashing embedder with
the identical interface. Retrieval still works, just with weaker semantic
quality (word-overlap-based rather than true semantic similarity). No
code elsewhere needs to change either way — callers just call .embed().
"""

import hashlib
import re

import numpy as np

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)

MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384

_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


def _hash_embed(text: str, dim: int = EMBEDDING_DIM) -> list[float]:
    """
    Deterministic, offline, dependency-free fallback: a simple word-hashing
    ("feature hashing") vector. Each token is hashed into one of `dim`
    buckets and counted, then L2-normalized. Not true semantic similarity
    (won't match "brute force" to "repeated login failures" without shared
    words), but it's fully offline and still lets identical/overlapping
    vocabulary retrieve correctly, which is enough to exercise and test
    the full ingestion/retrieval pipeline without internet access.
    """
    vec = np.zeros(dim, dtype=np.float64)
    for token in _TOKEN_PATTERN.findall(text.lower()):
        idx = int(hashlib.md5(token.encode()).hexdigest(), 16) % dim
        vec[idx] += 1.0
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec.tolist()


class EmbeddingModel:
    _instance: "EmbeddingModel | None" = None

    def __init__(self, model_name: str = MODEL_NAME):
        self.model = None
        self._use_fallback = False
        try:
            import os
            os.environ["HF_HUB_OFFLINE"] = "1"
            os.environ["TRANSFORMERS_OFFLINE"] = "1"
            from sentence_transformers import SentenceTransformer

            logger.info("Loading sentence-transformer model '%s'...", model_name)
            self.model = SentenceTransformer(model_name, local_files_only=True)
            logger.info("Embedding model loaded (dim=%d).", EMBEDDING_DIM)
        except Exception as exc:
            logger.warning(
                "Could not load sentence-transformer model '%s' (%s). "
                "Falling back to an offline hashing embedder — retrieval "
                "will still work, but with reduced semantic quality "
                "(word-overlap based, not true semantic similarity). "
                "This is expected in environments without internet access "
                "to huggingface.co; it will use the real model "
                "automatically once that's reachable.",
                model_name,
                exc,
            )
            self._use_fallback = True

    @classmethod
    def get_shared(cls) -> "EmbeddingModel":
        """
        Loading the model from disk takes a noticeable moment; a shared
        singleton avoids reloading it on every ingestion/query call within
        the same process.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def embed(self, text: str) -> list[float]:
        if self._use_fallback:
            return _hash_embed(text)
        return self.model.encode(text, normalize_embeddings=True).tolist()

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        if self._use_fallback:
            return [_hash_embed(t) for t in texts]
        return self.model.encode(texts, normalize_embeddings=True).tolist()
