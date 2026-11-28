"""
MCP Server: compliance-kb (READ) — Retrieval v2 Engine.

Implements 4 distinct, benchmarkable retrieval pipelines over Corpus v2 (>= 150 verifiable
regulatory passages + separated `source_type: "internal"` SOPs):
  1. `bm25_only`         : Stopword-filtered Okapi BM25 (`k1=1.5, b=0.75`)
  2. `dense_only`        : L2-normalized float32 dense semantic SVD embeddings (dim=96) over
                           word + char 3/4-gram + AML concept features (optional BGE-M3 hook)
  3. `hybrid_rrf`        : Reciprocal Rank Fusion (`rrf_k` from `PolicyConfig.retrieval`) of BM25 + Dense
  4. `hybrid_rrf_rerank` : `hybrid_rrf` + calibrated cross-feature lexical/dense/phrase/ID reranker

Includes calibrated abstention for out-of-scope queries (`abstained=True`, `clauses=[]`)
and optional `source_type` filtering (`"all" | "regulatory" | "internal"`).
Tools: `search_regulations`, `get_clause_by_id`.
"""

from __future__ import annotations

import asyncio
from collections import Counter
import json
import logging
import math
import os
from pathlib import Path
import re
from typing import Any, Literal

from fastmcp import FastMCP
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from src.config import get_policy
from src.mcp_servers import neural_retrieval
from src.mcp_servers.annotations import READ_ONLY_TOOL
from src.mcp_servers.retrieval_lexicon import _STOPWORDS, DOMAIN_CONCEPTS

mcp = FastMCP(
    name="compliance-kb",
    instructions="Read-only access to Indian AML/KYC regulatory knowledge base and internal SOPs. "
    "Supports BM25, dense semantic vectors, hybrid RRF, reranking, abstention, and source filtering.",
)

RetrievalMode = Literal["hybrid_rrf_rerank", "hybrid_rrf", "bm25_only", "dense_only", "vector_only"]
SourceFilter = Literal["all", "regulatory", "internal"]

logger = logging.getLogger("auditguard.compliance_kb")
_BACKEND_OVERRIDE: str | None = None
_NEURAL_WARNED = False


def set_backend_override(backend: str | None) -> None:
    """Process-level override of `retrieval.backend` (used by `retrieval-bench --backend`)."""
    global _BACKEND_OVERRIDE
    _BACKEND_OVERRIDE = backend


def _active_backend() -> str:
    return _BACKEND_OVERRIDE or get_policy().retrieval.backend


# Empirically selected default mode (verified by `python -m src.cli retrieval-bench --report` & pytest).
DEFAULT_RETRIEVAL_MODE: RetrievalMode = "hybrid_rrf_rerank"


# Abstention thresholds, BM25 parameters and blend/rerank weights live in `config/models.yaml` (`retrieval`).


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SearchRegulationsInput(_Strict):
    query: str = Field(description="Case-specific AML/KYC regulatory or SOP query")
    top_k: int = Field(default=5, ge=1, le=20)
    decompose: bool = Field(
        default=True,
        description="If True, decompose compound `;` / `and` queries into sub-queries and merge via RRF",
    )
    mode: RetrievalMode = DEFAULT_RETRIEVAL_MODE
    source_type: SourceFilter = "all"


class RegulationClause(_Strict):
    clause_id: str
    source: str
    title: str
    text: str
    relevance_score: float
    effective_date: str = ""
    category: str = ""
    source_type: str = "regulatory"
    source_url: str = ""
    retrieval_date: str = ""
    human_verified: bool = False


class SearchRegulationsOutput(_Strict):
    status: str = "ok"
    clauses: list[RegulationClause]
    query_used: str
    retrieval_method: str
    abstained: bool = False
    abstain_reason: str = ""


class GetClauseInput(_Strict):
    clause_id: str = Field(description="Exact passage identifier (e.g. PMLA-2002-S12-P01, FIU-IND-RFI-BA-01)")


def _raw_tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower().replace("v-cip", "vcip"))


def _content_tokens(text: str) -> list[str]:
    return [t for t in _raw_tokens(text) if len(t) >= 2 and t not in _STOPWORDS]


def _ngrams(word: str) -> list[str]:
    padded = f"<{word}>"
    return [f"g:{padded[i : i + n]}" for n in (3, 4) for i in range(max(0, len(padded) - n + 1))]


def _concept_tokens(word: str) -> list[str]:
    return [f"c:{syn}" for stem, syns in DOMAIN_CONCEPTS.items() if word.startswith(stem) for syn in syns]


def _dense_features(text: str) -> Counter[str]:
    feats: Counter[str] = Counter()
    for w in _content_tokens(text):
        feats[f"w:{w}"] += 2
        feats.update(_ngrams(w))
        for tok in _concept_tokens(w):
            feats[tok] += 2
    return feats


class HybridRegulatoryIndex:
    """BM25 + Dense SVD Semantic Vector + RRF + Cross-Feature Reranker with Calibrated Abstention."""

    def __init__(self, clauses: list[RegulationClause], dense_dim: int = 96) -> None:
        self.clauses = clauses
        self.n_docs = max(len(clauses), 1)
        self.doc_tokens: list[list[str]] = []
        self.doc_tf: list[Counter[str]] = []
        self.doc_freqs: Counter[str] = Counter()
        self.doc_lens: list[int] = []
        for c in clauses:
            toks = _content_tokens(f"{c.clause_id} {c.title} {c.category.replace('_', ' ')} {c.text}")
            self.doc_tokens.append(toks)
            self.doc_tf.append(Counter(toks))
            self.doc_lens.append(max(len(toks), 1))
            for t in set(toks):
                self.doc_freqs[t] += 1
        self.avgdl = sum(self.doc_lens) / self.n_docs if self.doc_lens else 1.0
        self._build_dense_svd_index(dense_dim)

    def _build_dense_svd_index(self, dense_dim: int) -> None:
        raw_vecs = [
            _dense_features(f"{c.clause_id} {c.title} {c.category.replace('_', ' ')} {c.text}")
            for c in self.clauses
        ]
        vec_df: Counter[str] = Counter()
        for fv in raw_vecs:
            for k in fv:
                vec_df[k] += 1
        vocab = sorted(vec_df.keys())
        self.feat_to_col: dict[str, int] = {k: i for i, k in enumerate(vocab)}
        self.vec_idf = np.array(
            [math.log((self.n_docs + 1.0) / (vec_df[k] + 0.5)) + 1.0 for k in vocab],
            dtype=np.float32,
        )
        mat = np.zeros((len(self.clauses), max(len(vocab), 1)), dtype=np.float32)
        for row_idx, fv in enumerate(raw_vecs):
            for k, cnt in fv.items():
                col = self.feat_to_col[k]
                mat[row_idx, col] = float(cnt) * float(self.vec_idf[col])
        row_norms = np.linalg.norm(mat, axis=1, keepdims=True)
        row_norms[row_norms == 0.0] = 1.0
        tfidf_unit = mat / row_norms
        k_dim = min(dense_dim, min(tfidf_unit.shape)) if tfidf_unit.size else 1
        u, s, vt = np.linalg.svd(tfidf_unit, full_matrices=False)
        self.svd_proj = vt[:k_dim, :].T.astype(np.float32)  # (V, k)
        dense_docs = (u[:, :k_dim] * s[:k_dim]).astype(np.float32)
        d_norms = np.linalg.norm(dense_docs, axis=1, keepdims=True)
        d_norms[d_norms == 0.0] = 1.0
        self.doc_dense_matrix = dense_docs / d_norms  # (N, k) L2-normalized float32 embeddings
        self.tfidf_unit = tfidf_unit

    def _allowed_indices(self, source_type: SourceFilter) -> list[int]:
        if source_type == "all":
            return list(range(len(self.clauses)))
        return [i for i, c in enumerate(self.clauses) if c.source_type == source_type]

    def _encode_query_dense(self, query: str) -> tuple[np.ndarray[Any, Any], np.ndarray[Any, Any]]:
        fv = _dense_features(query)
        q_sparse = np.zeros(len(self.feat_to_col), dtype=np.float32)
        for k, cnt in fv.items():
            col = self.feat_to_col.get(k)
            if col is not None:
                q_sparse[col] = float(cnt) * float(self.vec_idf[col])
        sn = float(np.linalg.norm(q_sparse)) or 1.0
        q_unit = q_sparse / sn
        q_dense = q_unit @ self.svd_proj
        dn = float(np.linalg.norm(q_dense)) or 1.0
        return q_dense / dn, q_unit

    def bm25_scores_all(self, query: str) -> tuple[list[float], int]:
        q_toks = _content_tokens(query)
        ret = get_policy().retrieval
        k1, b = float(ret.bm25_k1), float(ret.bm25_b)
        matched_q_terms = sum(1 for qt in set(q_toks) if self.doc_freqs.get(qt, 0) > 0)
        scores = [0.0] * len(self.clauses)
        for idx, tf_map in enumerate(self.doc_tf):
            dl = self.doc_lens[idx]
            total = 0.0
            for qt in q_toks:
                df = self.doc_freqs.get(qt, 0)
                if df == 0:
                    continue
                idf = math.log(1.0 + (self.n_docs - df + 0.5) / (df + 0.5))
                tf = tf_map.get(qt, 0)
                if tf > 0:
                    denom = tf + k1 * (1.0 - b + b * (dl / self.avgdl))
                    total += idf * ((tf * (k1 + 1.0)) / denom)
            scores[idx] = total
        return scores, matched_q_terms

    def dense_scores_all(self, query: str) -> list[float]:
        if not self.clauses:
            return []
        q_dense, q_unit = self._encode_query_dense(query)
        svd_cos = self.doc_dense_matrix @ q_dense
        subword_cos = self.tfidf_unit @ q_unit
        blend = get_policy().retrieval.dense_blend
        blended = float(blend.svd) * svd_cos + float(blend.subword) * subword_cos
        return [float(x) for x in blended]

    def _top_term_coverage(self, q_toks: list[str], top_idx: int) -> float:
        q_set = set(q_toks)
        if not q_set:
            return 0.0
        return len(q_set & set(self.doc_tokens[top_idx])) / len(q_set)

    def _should_abstain(
        self,
        mode: str,
        top_bm25: float,
        top_dense: float,
        top_cov: float,
        matched_terms: int,
        q_tok_count: int,
    ) -> tuple[bool, str]:
        if q_tok_count == 0:
            return True, "Empty or stopword-only query."
        ab = get_policy().retrieval.abstention
        bm25_min, bm25_soft_min, per_tok_min = float(ab.bm25_min), float(ab.bm25_soft_min), float(ab.bm25_per_token)
        dense_min, cov_min = float(ab.dense_min), float(ab.coverage_min)
        min_terms = 1 if q_tok_count <= 2 else ab.term_hit_min
        bm25_per_tok = top_bm25 / max(q_tok_count, 1)
        if q_tok_count <= 3:
            if matched_terms < min_terms or (
                top_bm25 < float(ab.short_query_bm25_min) and top_dense < float(ab.short_query_dense_min)
            ):
                return True, f"Short query lacks in-domain AML/KYC match (bm25={top_bm25:.2f}, dense={top_dense:.3f})."
            return False, ""
        if mode == "bm25_only":
            if matched_terms < min_terms or top_bm25 < bm25_min or (bm25_per_tok < per_tok_min and top_cov < cov_min):
                return True, f"BM25 evidence below threshold (bm25={top_bm25:.2f}, per_tok={bm25_per_tok:.2f})."
            return False, ""
        if mode in ("dense_only", "vector_only"):
            if top_dense < dense_min:
                return True, f"Dense similarity below threshold ({top_dense:.3f} < {dense_min})."
            return False, ""
        if matched_terms < min_terms and top_dense < float(ab.low_term_dense_min):
            return True, f"Insufficient domain term overlap (terms={matched_terms}, dense={top_dense:.3f})."
        if (bm25_per_tok < per_tok_min and top_cov < cov_min) or (top_bm25 < bm25_soft_min and top_dense < dense_min):
            return (
                True,
                f"Hybrid evidence below threshold (bm25={top_bm25:.2f}, cov={top_cov:.2f}, dense={top_dense:.3f}).",
            )
        return False, ""

    def _rerank_candidates(
        self,
        query: str,
        candidates: list[int],
        rrf_map: dict[int, float],
        bm25_all: list[float],
        dense_all: list[float],
    ) -> list[tuple[int, float]]:
        q_low = query.lower()
        q_toks = _content_tokens(query)
        q_set = set(q_toks)
        q_bigrams = {f"{q_toks[i]}_{q_toks[i + 1]}" for i in range(len(q_toks) - 1)}
        max_rrf = max(rrf_map.values(), default=1.0) or 1.0
        max_bm25 = max((bm25_all[i] for i in candidates), default=1.0) or 1.0
        max_dense = max((dense_all[i] for i in candidates), default=1.0) or 1.0
        w = get_policy().retrieval.rerank_weights
        w_rrf, w_bm25, w_dense, w_cov = float(w.rrf), float(w.bm25), float(w.dense), float(w.coverage)
        w_bg, w_title, w_id = float(w.bigram), float(w.title), float(w.id_hit)
        out: list[tuple[int, float]] = []
        for idx in candidates:
            c = self.clauses[idx]
            d_toks = self.doc_tokens[idx]
            d_bigrams = {f"{d_toks[i]}_{d_toks[i + 1]}" for i in range(len(d_toks) - 1)}
            rrf_norm = rrf_map.get(idx, 0.0) / max_rrf
            bm25_norm = bm25_all[idx] / max_bm25
            dense_norm = max(0.0, dense_all[idx]) / max_dense
            cov = len(q_set & set(d_toks)) / max(len(q_set), 1)
            bg = (len(q_bigrams & d_bigrams) / max(len(q_bigrams), 1)) if q_bigrams else 0.0
            id_hit = w_id if c.clause_id.lower() in q_low else 0.0
            title_toks = set(_content_tokens(c.title))
            title_hit = len(q_set & title_toks) / max(len(q_set), 1)
            score = min(
                0.9999,
                round(
                    w_rrf * rrf_norm
                    + w_bm25 * bm25_norm
                    + w_dense * dense_norm
                    + w_cov * cov
                    + w_bg * bg
                    + w_title * title_hit
                    + id_hit,
                    4,
                ),
            )
            out.append((idx, score))
        out.sort(key=lambda x: -x[1])
        return out

    def search_with_status(
        self,
        query: str,
        top_k: int = 5,
        mode: str = DEFAULT_RETRIEVAL_MODE,
        source_type: SourceFilter = "all",
    ) -> tuple[list[RegulationClause], bool, str]:
        allowed = self._allowed_indices(source_type)
        if not allowed:
            return [], True, f"No passages available for source_type={source_type!r}."
        q_toks = _content_tokens(query)
        bm25_all, matched_terms = self.bm25_scores_all(query)
        dense_all = self.dense_scores_all(query)
        neural = self._neural() if _active_backend() == "neural" else None
        best_bm25_idx = max(allowed, key=lambda i: bm25_all[i])
        top_bm25 = bm25_all[best_bm25_idx]
        top_dense = max((dense_all[i] for i in allowed), default=0.0)
        top_cov = self._top_term_coverage(q_toks, best_bm25_idx)
        abstain, reason = self._should_abstain(mode, top_bm25, top_dense, top_cov, matched_terms, len(q_toks))
        if abstain:
            return [], True, reason

        if mode == "bm25_only":
            ranked = sorted(allowed, key=lambda i: -bm25_all[i])[:top_k]
            denom = max(top_bm25, 1e-6)
            hits = [(i, round(bm25_all[i] / denom, 4)) for i in ranked if bm25_all[i] > 0]
            return [self.clauses[i].model_copy(update={"relevance_score": s}) for i, s in hits], False, ""

        if neural is not None:  # abstention above stays on the calibrated builtin signals
            dense_all = neural.dense_scores_all(query)
        if mode in ("dense_only", "vector_only"):
            ranked = sorted(allowed, key=lambda i: -dense_all[i])[:top_k]
            hits = [(i, round(max(0.0, dense_all[i]), 4)) for i in ranked if dense_all[i] > 0]
            return [self.clauses[i].model_copy(update={"relevance_score": s}) for i, s in hits], False, ""

        final, empty_reason = self._fuse_and_rank(query, allowed, top_k, mode, bm25_all, dense_all, neural)
        if empty_reason:
            return [], True, empty_reason
        return [self.clauses[i].model_copy(update={"relevance_score": s}) for i, s in final], False, ""

    def _fuse_and_rank(
        self,
        query: str,
        allowed: list[int],
        top_k: int,
        mode: str,
        bm25_all: list[float],
        dense_all: list[float],
        neural: Any,
    ) -> tuple[list[tuple[int, float]], str]:
        """RRF over BM25 + dense candidates, then the configured final ranking; returns (hits, empty_reason)."""
        ret_cfg = get_policy().retrieval
        bm25_ranked = sorted(allowed, key=lambda i: -bm25_all[i])[: ret_cfg.top_k_bm25]
        dense_ranked = sorted(allowed, key=lambda i: -dense_all[i])[: ret_cfg.top_k_dense]
        rrf_k = ret_cfg.rrf_k
        rrf_scores: dict[int, float] = {}
        for rank, idx in enumerate(bm25_ranked, start=1):
            if bm25_all[idx] > 0:
                rrf_scores[idx] = rrf_scores.get(idx, 0.0) + 1.0 / (rrf_k + rank)
        for rank, idx in enumerate(dense_ranked, start=1):
            if dense_all[idx] > 0:
                rrf_scores[idx] = rrf_scores.get(idx, 0.0) + 1.0 / (rrf_k + rank)
        if not rrf_scores:
            return [], "No positive lexical or semantic matches."

        pool_limit = max(top_k, ret_cfg.top_k_final * 3)
        top_cands = sorted(rrf_scores, key=lambda i: -rrf_scores[i])[:pool_limit]
        if mode == "hybrid_rrf":
            max_r = max(rrf_scores.values(), default=1.0) or 1.0
            final = [(i, round(rrf_scores[i] / max_r, 4)) for i in top_cands[:top_k]]
        elif neural is not None:
            final = neural.rerank(query, top_cands)[:top_k]
        else:
            final = self._rerank_candidates(query, top_cands, rrf_scores, bm25_all, dense_all)[:top_k]
        return final, ""

    def _neural(self) -> Any:
        """The cached neural retriever, or None (with one warning) when the [rag] extra is unavailable."""
        global _NEURAL_WARNED
        cfg = get_policy().retrieval
        try:
            return neural_retrieval.get_neural_retriever(
                [f"{c.title}. {c.text}" for c in self.clauses],
                cfg.embedding_model,
                cfg.reranker_model,
                cfg.embedding_query_prefix,
            )
        except neural_retrieval.NeuralBackendUnavailable as exc:
            if not _NEURAL_WARNED:
                logger.warning("retrieval.backend=neural unavailable (%s); using the builtin path", exc)
                _NEURAL_WARNED = True
            return None

    def search(
        self,
        query: str,
        top_k: int = 5,
        mode: str = DEFAULT_RETRIEVAL_MODE,
        source_type: SourceFilter = "all",
    ) -> list[RegulationClause]:
        clauses, _, _ = self.search_with_status(query, top_k=top_k, mode=mode, source_type=source_type)
        return clauses


_index_singleton: HybridRegulatoryIndex | None = None


def reset_regulatory_index() -> None:
    global _index_singleton
    _index_singleton = None


def get_regulatory_index() -> HybridRegulatoryIndex:
    global _index_singleton
    if _index_singleton is not None:
        return _index_singleton
    corpus_path = Path(__file__).resolve().parents[2] / "data" / "regulatory_corpus" / "indian_aml_corpus.jsonl"
    clauses: list[RegulationClause] = []
    if corpus_path.exists():
        for line in corpus_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            clauses.append(
                RegulationClause(
                    clause_id=str(rec["passage_id"]),
                    source=str(rec.get("doc_title", "AML Corpus")),
                    title=f"{rec.get('doc_title', '')} ({rec.get('clause_number', '')})".strip(),
                    text=str(rec["text"]),
                    relevance_score=0.0,
                    effective_date=str(rec.get("effective_date", "")),
                    category=str(rec.get("category", "")),
                    source_type=str(rec.get("source_type", "regulatory")),
                    source_url=str(rec.get("source_url", "")),
                    retrieval_date=str(rec.get("retrieval_date", "")),
                    human_verified=bool(rec.get("human_verified", False)),
                )
            )
    _index_singleton = HybridRegulatoryIndex(clauses)
    return _index_singleton


def _sync_search_regulations(params: SearchRegulationsInput) -> SearchRegulationsOutput:
    idx = get_regulatory_index()
    query = params.query
    use_decomp = params.mode in ("hybrid_rrf_rerank", "hybrid_rrf") and params.decompose and (";" in query)
    if use_decomp:
        rrf_k = get_policy().retrieval.rrf_k
        parts = [p.strip() for p in query.split(";") if len(p.strip()) >= 8][:3]
        if len(parts) >= 2:
            rrf_merged: dict[str, float] = {}
            clause_map: dict[str, RegulationClause] = {}
            # Always include full-query ranking alongside sub-queries to preserve single-topic recall@1.
            full_hits, full_abstain, full_reason = idx.search_with_status(
                query, top_k=max(params.top_k, 8), mode=params.mode, source_type=params.source_type
            )
            if full_abstain and all(
                idx.search_with_status(sq, top_k=3, mode=params.mode, source_type=params.source_type)[1] for sq in parts
            ):
                return SearchRegulationsOutput(
                    status="ok",
                    clauses=[],
                    query_used=query,
                    retrieval_method=f"decomposed+{params.mode}",
                    abstained=True,
                    abstain_reason=full_reason,
                )
            for rank, c in enumerate(full_hits, start=1):
                rrf_merged[c.clause_id] = rrf_merged.get(c.clause_id, 0.0) + (1.4 / (rrf_k + rank))
                clause_map[c.clause_id] = c
            for sq in parts:
                sub_hits, sub_abstain, _ = idx.search_with_status(
                    sq, top_k=max(params.top_k, 6), mode=params.mode, source_type=params.source_type
                )
                if sub_abstain:
                    continue
                for rank, c in enumerate(sub_hits, start=1):
                    rrf_merged[c.clause_id] = rrf_merged.get(c.clause_id, 0.0) + (0.8 / (rrf_k + rank))
                    clause_map[c.clause_id] = c
            top_ids = sorted(rrf_merged, key=lambda cid: -rrf_merged[cid])[: params.top_k]
            max_m = max(rrf_merged.values(), default=1.0) or 1.0
            clauses = [
                clause_map[cid].model_copy(update={"relevance_score": round(rrf_merged[cid] / max_m, 4)})
                for cid in top_ids
            ]
            return SearchRegulationsOutput(
                status="ok",
                clauses=clauses,
                query_used=query,
                retrieval_method=f"decomposed+{params.mode}",
                abstained=len(clauses) == 0,
                abstain_reason="" if clauses else full_reason,
            )

    clauses, abstained, reason = idx.search_with_status(
        query, top_k=params.top_k, mode=params.mode, source_type=params.source_type
    )
    return SearchRegulationsOutput(
        status="ok",
        clauses=clauses,
        query_used=query,
        retrieval_method=params.mode,
        abstained=abstained,
        abstain_reason=reason,
    )


@mcp.tool(annotations=READ_ONLY_TOOL)
async def search_regulations(params: SearchRegulationsInput) -> SearchRegulationsOutput:
    """Search the Indian AML/KYC regulatory corpus and internal SOPs with calibrated abstention."""
    return await asyncio.to_thread(_sync_search_regulations, params)


def _sync_get_clause(clause_id: str) -> dict[str, Any]:
    idx = get_regulatory_index()
    for clause in idx.clauses:
        if clause.clause_id == clause_id:
            return {"status": "ok", **clause.model_copy(update={"relevance_score": 1.0}).model_dump()}
    return {
        "status": "error",
        "error_code": "CLAUSE_NOT_FOUND",
        "message": f"No clause found with ID: {clause_id}",
        "clause_id": clause_id,
        "source": "unknown",
        "relevance_score": 0.0,
    }


@mcp.tool(annotations=READ_ONLY_TOOL)
async def get_clause_by_id(params: GetClauseInput) -> dict[str, Any]:
    """Retrieve a specific regulatory passage or internal SOP by its exact passage identifier."""
    return await asyncio.to_thread(_sync_get_clause, params.clause_id)


if __name__ == "__main__":
    from src.mcp_servers.http_auth import serve_mcp_http

    port = int(os.getenv("MCP_COMPLIANCE_KB_PORT", "8010"))
    serve_mcp_http(mcp, port=port)
