"""
Opt-in neural retrieval for compliance-kb (audit AG-07): `retrieval.backend: neural` in `config/models.yaml`.

Replaces two hand-built pieces of the hybrid pipeline with real models, loaded once per process:
  * dense candidates: a sentence-transformers bi-encoder (`retrieval.embedding_model`, L2-normalised cosine);
  * final rerank: a cross-encoder (`retrieval.reranker_model`), scores mapped to 0..1 with a sigmoid.
Abstention is deliberately unchanged (the calibrated BM25/coverage signals), so no thresholds are tuned on the
benchmark. Needs the `[rag]` extra; when it is missing, `get_neural_retriever` raises `NeuralBackendUnavailable`
and compliance-kb falls back to the builtin path with a warning.
"""

from __future__ import annotations

import math
import threading
from typing import Any

import numpy as np

_LOCK = threading.Lock()
_CACHE: dict[tuple[str, str, int], NeuralRetriever] = {}


class NeuralBackendUnavailable(RuntimeError):
    """The `[rag]` extra (sentence-transformers) is not installed or a model could not be loaded."""


class NeuralRetriever:
    def __init__(self, texts: list[str], embedding_model: str, reranker_model: str, query_prefix: str = "") -> None:
        try:
            from sentence_transformers import CrossEncoder, SentenceTransformer
        except ImportError as exc:  # optional dependency
            raise NeuralBackendUnavailable("install the [rag] extra: pip install -e '.[rag]'") from exc
        self._texts = texts
        self._prefix = query_prefix
        self._encoder: Any = SentenceTransformer(embedding_model, device="cpu")
        self._reranker: Any = CrossEncoder(reranker_model, device="cpu")
        self._doc = np.asarray(
            self._encoder.encode(texts, normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False)
        )

    def dense_scores_all(self, query: str) -> list[float]:
        q = self._encoder.encode([self._prefix + query], normalize_embeddings=True, convert_to_numpy=True)
        return [float(x) for x in self._doc @ np.asarray(q)[0]]

    def rerank(self, query: str, candidates: list[int]) -> list[tuple[int, float]]:
        if not candidates:
            return []
        logits = self._reranker.predict([(query, self._texts[i]) for i in candidates], show_progress_bar=False)
        scored = [(i, round(1.0 / (1.0 + math.exp(-float(s))), 4)) for i, s in zip(candidates, logits, strict=True)]
        return sorted(scored, key=lambda x: -x[1])


def get_neural_retriever(
    texts: list[str], embedding_model: str, reranker_model: str, query_prefix: str = ""
) -> NeuralRetriever:
    """Process-wide cached retriever for one corpus/model pair (models and corpus embeddings load once)."""
    key = (embedding_model, reranker_model, hash(tuple(texts)))
    with _LOCK:
        if key not in _CACHE:
            try:
                _CACHE[key] = NeuralRetriever(texts, embedding_model, reranker_model, query_prefix)
            except (OSError, ValueError) as exc:  # model download/load failure
                raise NeuralBackendUnavailable(f"could not load retrieval models: {exc}") from exc
        return _CACHE[key]
