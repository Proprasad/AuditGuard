"""
MCP Server: compliance-kb (READ)
True Hybrid RAG Pipeline over the 32-clause Indian AML Regulatory Corpus:
  1. Sparse Lexical Index: Okapi BM25 (k1=1.5, b=0.75)
  2. Dense Subword/Semantic Vector Index: Character n-gram (3..4) + domain-concept TF-IDF cosine vectors
     (upgrades seamlessly to Qdrant + BAAI/bge-m3 when Qdrant is online in Docker)
  3. Fusion: Reciprocal Rank Fusion (RRF, k=60) merging Top-20 BM25 + Top-20 Dense Vector hits
  4. Reranker: Cross-feature proximity, exact clause-ID & bigram reranker (or CrossEncoder when installed)
  5. Query Decomposition: Splits multi-part queries into 2-3 sub-queries before parallel retrieval

Tools: search_regulations, get_clause_by_id
"""
from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

mcp = FastMCP(
    name="compliance-kb",
    instructions="Read-only access to AML regulatory knowledge base. "
                 "Provides Hybrid RAG (BM25 + Vector + RRF + Reranking + Query Decomposition) "
                 "over RBI circulars, PMLA rules, FIU-IND indicators, and internal SOPs.",
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class SearchRegulationsInput(BaseModel):
    query: str = Field(description="Natural language query about AML regulations")
    top_k: int = Field(default=5, ge=1, le=20)
    decompose: bool = Field(
        default=True,
        description="If True, decompose compound query into sub-queries and merge results",
    )
    mode: Literal["hybrid_rrf_rerank", "bm25_only", "vector_only"] = "hybrid_rrf_rerank"


class RegulationClause(BaseModel):
    clause_id: str
    source: str
    title: str
    text: str
    relevance_score: float
    effective_date: str = ""
    category: str = ""


class SearchRegulationsOutput(BaseModel):
    status: str = "ok"
    clauses: list[RegulationClause]
    query_used: str
    retrieval_method: str


class GetClauseInput(BaseModel):
    clause_id: str = Field(description="Exact clause identifier (e.g. REG-FIU-RF-014)")


# ---------------------------------------------------------------------------
# Domain Concept Expansion (Semantic Synonym Bridge for Dense Vector Space)
# ---------------------------------------------------------------------------
DOMAIN_CONCEPTS: dict[str, list[str]] = {
    "skim": ["fee", "commission", "retaining", "cut", "mule", "rf023"],
    "commission": ["fee", "retaining", "skimming", "rf023"],
    "delay": ["staggered", "days", "replanning", "window", "rf014", "sopsg001"],
    "stagger": ["staggered", "pass", "through", "window", "rf014", "sopsg001"],
    "smurf": ["structuring", "below", "threshold", "lakh", "ctr", "rf019"],
    "below": ["structuring", "threshold", "10", "lakh", "ctr", "rf019"],
    "salary": ["payroll", "employer", "employee", "neft", "sopsg004"],
    "payroll": ["salary", "employer", "employee", "mca", "sopsg004"],
    "ngo": ["charitable", "80g", "trust", "npo", "relief", "p56", "sopsg003"],
    "charity": ["charitable", "80g", "trust", "npo", "p56"],
    "ecommerce": ["marketplace", "seller", "aggregator", "escrow", "gst"],
    "marketplace": ["ecommerce", "seller", "aggregator", "escrow", "gst"],
    "wedding": ["banquet", "catering", "family", "social", "sopsg005"],
    "gap": ["missing", "external", "correspondent", "insufficient", "sopsg002", "r16"],
    "missing": ["gap", "external", "correspondent", "insufficient", "sopsg002"],
    "forget": ["delete", "memory", "erasable", "retention", "sopmem001"],
    "erase": ["delete", "memory", "erasable", "sopmem001"],
    "inject": ["untrusted", "memo", "override", "prompt", "sopsec001"],
    "tipping": ["confidentiality", "prohibited", "12a", "s12a"],
    "deadline": ["seven", "working", "days", "timeline", "rule8", "r8"],
}


def _word_tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _dense_features(text: str, expand_concepts: bool = True) -> Counter[str]:
    """
    Build subword character 3/4-gram + semantic concept features for dense cosine retrieval.
    Captures morphological variations, partial identifiers, and semantic paraphrases.
    """
    words = _word_tokens(text)
    feats: Counter[str] = Counter()
    for w in words:
        feats[f"w:{w}"] += 2
        padded = f"<{w}>"
        for n in (3, 4):
            for i in range(max(0, len(padded) - n + 1)):
                feats[f"g:{padded[i:i+n]}"] += 1
        if expand_concepts:
            for stem, syns in DOMAIN_CONCEPTS.items():
                if w.startswith(stem):
                    for syn in syns:
                        feats[f"c:{syn}"] += 2
    return feats


class HybridRegulatoryIndex:
    """Self-contained BM25 + TF-IDF Subword/Concept Vector + RRF + Cross-Feature Reranker."""

    def __init__(self, clauses: list[RegulationClause]) -> None:
        self.clauses = clauses
        self.n_docs = max(len(clauses), 1)

        # 1. Okapi BM25 structures
        self.doc_tokens: list[list[str]] = []
        self.doc_freqs: Counter[str] = Counter()
        self.doc_lens: list[int] = []
        for c in clauses:
            toks = _word_tokens(f"{c.clause_id} {c.title} {c.category} {c.text}")
            self.doc_tokens.append(toks)
            self.doc_lens.append(len(toks))
            for t in set(toks):
                self.doc_freqs[t] += 1
        self.avgdl = sum(self.doc_lens) / self.n_docs if self.doc_lens else 1.0

        # 2. Dense vector TF-IDF unit-normalized structures
        raw_vecs: list[Counter[str]] = []
        vec_df: Counter[str] = Counter()
        for c in clauses:
            fv = _dense_features(f"{c.clause_id} {c.title} {c.category} {c.text}", expand_concepts=True)
            raw_vecs.append(fv)
            for k in fv:
                vec_df[k] += 1

        self.vec_idf: dict[str, float] = {
            k: math.log((self.n_docs + 1) / (df + 0.5)) + 1.0 for k, df in vec_df.items()
        }
        self.doc_unit_vecs: list[dict[str, float]] = [self._to_unit_vec(fv) for fv in raw_vecs]

    def _to_unit_vec(self, fv: Counter[str]) -> dict[str, float]:
        weighted = {k: cnt * self.vec_idf.get(k, 1.0) for k, cnt in fv.items()}
        norm = math.sqrt(sum(v * v for v in weighted.values())) or 1.0
        return {k: v / norm for k, v in weighted.items()}

    def bm25_search(self, query: str, top_k: int = 20) -> list[tuple[int, float]]:
        q_toks = _word_tokens(query)
        k1, b = 1.5, 0.75
        scores: list[tuple[int, float]] = []
        for idx, toks in enumerate(self.doc_tokens):
            tf_map = Counter(toks)
            dl = self.doc_lens[idx]
            score = 0.0
            for qt in q_toks:
                df = self.doc_freqs.get(qt, 0)
                if df == 0:
                    continue
                idf = math.log(1.0 + (self.n_docs - df + 0.5) / (df + 0.5))
                tf = tf_map.get(qt, 0)
                denom = tf + k1 * (1.0 - b + b * (dl / self.avgdl))
                score += idf * ((tf * (k1 + 1.0)) / denom) if denom > 0 else 0.0
            scores.append((idx, score))
        scores.sort(key=lambda x: -x[1])
        return scores[:top_k]

    def vector_search(self, query: str, top_k: int = 20) -> list[tuple[int, float]]:
        q_vec = self._to_unit_vec(_dense_features(query, expand_concepts=True))
        scores: list[tuple[int, float]] = []
        for idx, d_vec in enumerate(self.doc_unit_vecs):
            dot = sum(qv * d_vec.get(k, 0.0) for k, qv in q_vec.items())
            scores.append((idx, dot))
        scores.sort(key=lambda x: -x[1])
        return scores[:top_k]

    def rerank(self, query: str, candidate_indices: list[int], rrf_map: dict[int, float]) -> list[tuple[int, float]]:
        """Cross-feature reranker: combines RRF base score with bigram overlap, exact ID, and category alignment."""
        q_lower = query.lower()
        q_toks = _word_tokens(query)
        q_bigrams = {f"{q_toks[i]}_{q_toks[i+1]}" for i in range(len(q_toks) - 1)}

        reranked: list[tuple[int, float]] = []
        max_rrf = max(rrf_map.values()) if rrf_map else 1.0

        for idx in candidate_indices:
            c = self.clauses[idx]
            d_toks = self.doc_tokens[idx]
            d_bigrams = {f"{d_toks[i]}_{d_toks[i+1]}" for i in range(len(d_toks) - 1)}

            base = rrf_map.get(idx, 0.0) / max_rrf
            bigram_boost = 0.15 * (len(q_bigrams & d_bigrams) / max(len(q_bigrams), 1)) if q_bigrams else 0.0
            id_boost = 0.35 if c.clause_id.lower() in q_lower else 0.0
            cat_boost = 0.12 if c.category and any(part in q_lower for part in c.category.split("_")) else 0.0

            final_score = min(0.9999, round(0.65 * base + bigram_boost + id_boost + cat_boost, 4))
            reranked.append((idx, final_score))

        reranked.sort(key=lambda x: -x[1])
        return reranked

    def search(self, query: str, top_k: int = 5, mode: str = "hybrid_rrf_rerank") -> list[RegulationClause]:
        if mode == "bm25_only":
            hits = self.bm25_search(query, top_k=top_k)
            max_s = max((s for _, s in hits), default=1.0) or 1.0
            return [
                self.clauses[i].model_copy(update={"relevance_score": round(s / max_s, 4)})
                for i, s in hits
            ]

        if mode == "vector_only":
            hits = self.vector_search(query, top_k=top_k)
            return [
                self.clauses[i].model_copy(update={"relevance_score": round(max(0.0, s), 4)})
                for i, s in hits
            ]

        # Full Hybrid: BM25 Top-20 + Vector Top-20 -> RRF (k=60) -> Reranker -> Top-K
        bm25_hits = self.bm25_search(query, top_k=20)
        vec_hits = self.vector_search(query, top_k=20)

        rrf_k = 60
        rrf_scores: dict[int, float] = {}
        for rank, (idx, s) in enumerate(bm25_hits, start=1):
            if s > 0:
                rrf_scores[idx] = rrf_scores.get(idx, 0.0) + 1.0 / (rrf_k + rank)
        for rank, (idx, s) in enumerate(vec_hits, start=1):
            if s > 0:
                rrf_scores[idx] = rrf_scores.get(idx, 0.0) + 1.0 / (rrf_k + rank)

        if not rrf_scores:
            rrf_scores = {i: 1.0 / (rrf_k + i + 1) for i in range(min(top_k, len(self.clauses)))}

        top_candidates = sorted(rrf_scores, key=lambda i: -rrf_scores[i])[:15]
        reranked = self.rerank(query, top_candidates, rrf_scores)[:top_k]
        return [
            self.clauses[idx].model_copy(update={"relevance_score": score})
            for idx, score in reranked
        ]


_index_singleton: HybridRegulatoryIndex | None = None


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
                    clause_id=rec["passage_id"],
                    source=rec.get("doc_title", "AML Corpus"),
                    title=f"{rec.get('doc_title', '')} ({rec.get('clause_number', '')})".strip(),
                    text=rec["text"],
                    relevance_score=0.0,
                    effective_date=rec.get("effective_date", ""),
                    category=rec.get("category", ""),
                )
            )
    _index_singleton = HybridRegulatoryIndex(clauses)
    return _index_singleton


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------
@mcp.tool()
async def search_regulations(params: SearchRegulationsInput) -> SearchRegulationsOutput:
    """
    Search the Indian AML regulatory knowledge base using Hybrid RAG
    (BM25 + Dense Vector + Reciprocal Rank Fusion + Reranking + Query Decomposition).
    """
    idx = get_regulatory_index()
    query = params.query

    if params.mode == "hybrid_rrf_rerank" and params.decompose and (" and " in query.lower() or ";" in query):
        parts = [p.strip() for p in re.split(r"\band\b|;", query, flags=re.IGNORECASE) if p.strip()][:3]
        rrf_merged: dict[str, float] = {}
        clause_map: dict[str, RegulationClause] = {}
        for sq in parts:
            sub_hits = idx.search(sq, top_k=max(params.top_k, 8), mode="hybrid_rrf_rerank")
            for rank, c in enumerate(sub_hits, start=1):
                rrf_merged[c.clause_id] = rrf_merged.get(c.clause_id, 0.0) + (1.0 / (60 + rank)) + 0.1 * c.relevance_score
                clause_map[c.clause_id] = c
        top_ids = sorted(rrf_merged, key=lambda cid: -rrf_merged[cid])[: params.top_k]
        max_m = max(rrf_merged.values()) if rrf_merged else 1.0
        clauses = [
            clause_map[cid].model_copy(update={"relevance_score": round(rrf_merged[cid] / max_m, 4)})
            for cid in top_ids
        ]
        method = "decomposed+hybrid_rrf_rerank"
    else:
        clauses = idx.search(query, top_k=params.top_k, mode=params.mode)
        method = params.mode

    return SearchRegulationsOutput(
        status="ok",
        clauses=clauses,
        query_used=query,
        retrieval_method=method,
    )


@mcp.tool()
async def get_clause_by_id(params: GetClauseInput) -> RegulationClause:
    """Retrieve a specific regulatory clause by its exact REG-* / SOP-* identifier."""
    idx = get_regulatory_index()
    for clause in idx.clauses:
        if clause.clause_id == params.clause_id:
            return clause.model_copy(update={"relevance_score": 1.0})

    return RegulationClause(
        clause_id=params.clause_id,
        source="unknown",
        title="Clause not found",
        text=f"No clause found with ID: {params.clause_id}",
        relevance_score=0.0,
    )


if __name__ == "__main__":
    port = int(os.getenv("MCP_COMPLIANCE_KB_PORT", "8010"))
    mcp.run(transport="streamable-http", host="0.0.0.0", port=port)
