"""Hybrid RAG Compliance KB & 35-Query Retrieval Benchmark Tests"""
import json
from pathlib import Path
import pytest

from src.mcp_servers import compliance_kb


@pytest.mark.asyncio
async def test_35_query_hybrid_retrieval_benchmark():
    bench_path = Path("eval/retrieval_bench.jsonl")
    queries = [json.loads(line) for line in bench_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(queries) >= 35

    fn = getattr(compliance_kb.search_regulations, "fn", compliance_kb.search_regulations)

    bm25_hits = 0
    hybrid_hits = 0
    for q in queries:
        expected = set(q["expected_ids"])
        r_bm25 = await fn(compliance_kb.SearchRegulationsInput(query=q["query"], top_k=5, mode="bm25_only"))
        r_hyb = await fn(compliance_kb.SearchRegulationsInput(query=q["query"], top_k=5, mode="hybrid_rrf_rerank"))

        if expected & {c.clause_id for c in r_bm25.clauses}:
            bm25_hits += 1
        if expected & {c.clause_id for c in r_hyb.clauses}:
            hybrid_hits += 1

    bm25_recall5 = bm25_hits / len(queries)
    hybrid_recall5 = hybrid_hits / len(queries)

    # Hybrid RRF + Reranking must achieve >= 90% Recall@5 and >= BM25-only
    assert hybrid_recall5 >= 0.90
    assert hybrid_recall5 >= bm25_recall5
