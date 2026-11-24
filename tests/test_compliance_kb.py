"""Hybrid RAG Compliance KB & Retrieval Benchmark v2 Regression Test (`tests/test_compliance_kb.py`)."""

from __future__ import annotations

from eval.retrieval_eval import run_retrieval_benchmark
from src.mcp_servers.compliance_kb import DEFAULT_RETRIEVAL_MODE


def test_hybrid_retrieval_v2_benchmark_beats_or_ties_bm25() -> None:
    summary = run_retrieval_benchmark()
    assert summary["total_queries"] >= 100
    bm25 = summary["results"]["bm25_only"]
    default = summary["results"][DEFAULT_RETRIEVAL_MODE]

    assert default["recall_at_5"] >= 0.85
    assert default["recall_at_1"] >= bm25["recall_at_1"]
    assert default["abstain_precision"] >= 0.85
