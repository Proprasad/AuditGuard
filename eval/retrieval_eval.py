"""
Retrieval v2 Benchmark Evaluator (`eval/retrieval_eval.py`).

Evaluates all 4 pipelines (`bm25_only`, `dense_only`, `hybrid_rrf`, `hybrid_rrf_rerank`)
on `eval/retrieval_bench_v2.jsonl` (>= 100 queries with 20% unanswerable) and computes:
  - Recall@1, Recall@3, Recall@5 (capped IR recall over answerable queries)
  - MRR (Mean Reciprocal Rank over answerable queries)
  - nDCG@5 (Normalized Discounted Cumulative Gain @ 5 over answerable queries)
  - Abstain Precision, Abstain Recall, Abstain F1 (on unanswerable vs answerable queries)
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from src.mcp_servers.compliance_kb import (
    DEFAULT_RETRIEVAL_MODE,
    RetrievalMode,
    SearchRegulationsInput,
    _sync_search_regulations,
)

BENCH_V2_PATH = Path("eval/retrieval_bench_v2.jsonl")
ALL_PIPELINES: tuple[RetrievalMode, ...] = (
    "bm25_only",
    "dense_only",
    "hybrid_rrf",
    "hybrid_rrf_rerank",
)


def _dcg_at_k(returned: list[str], relevant: set[str], k: int = 5) -> float:
    return sum(
        1.0 / math.log2(rank + 1)
        for rank, cid in enumerate(returned[:k], start=1)
        if cid in relevant
    )


def _ndcg_at_k(returned: list[str], relevant: set[str], k: int = 5) -> float:
    n_rel = min(len(relevant), k)
    if n_rel == 0:
        return 0.0
    idcg = sum(1.0 / math.log2(rank + 1) for rank in range(1, n_rel + 1))
    return _dcg_at_k(returned, relevant, k=k) / idcg


def evaluate_pipeline(
    queries: list[dict[str, Any]],
    mode: RetrievalMode,
    *,
    decompose: bool = True,
) -> dict[str, Any]:
    """Run one retrieval pipeline across all benchmark queries and compute IR + abstention metrics."""
    r1_sum = r3_sum = r5_sum = mrr_sum = ndcg5_sum = 0.0
    n_ans = 0
    tp_abstain = fp_abstain = fn_abstain = tn_abstain = 0

    for q in queries:
        out = _sync_search_regulations(
            SearchRegulationsInput(query=str(q["query"]), top_k=5, decompose=decompose, mode=mode)
        )
        returned = [c.clause_id for c in out.clauses]
        expected = {str(cid) for cid in q.get("expected_ids", [])}
        unanswerable = bool(q.get("unanswerable", len(expected) == 0))
        abstained = bool(out.abstained or len(returned) == 0)

        if unanswerable:
            if abstained:
                tp_abstain += 1
            else:
                fn_abstain += 1
            continue

        n_ans += 1
        if abstained:
            fp_abstain += 1
        else:
            tn_abstain += 1

        r1_sum += len(expected & set(returned[:1])) / min(1, len(expected))
        r3_sum += len(expected & set(returned[:3])) / min(3, len(expected))
        r5_sum += len(expected & set(returned[:5])) / min(5, len(expected))
        ndcg5_sum += _ndcg_at_k(returned, expected, k=5)
        for rank, cid in enumerate(returned[:5], start=1):
            if cid in expected:
                mrr_sum += 1.0 / rank
                break

    denom = max(n_ans, 1)
    abstain_prec = tp_abstain / (tp_abstain + fp_abstain) if (tp_abstain + fp_abstain) > 0 else 0.0
    abstain_rec = tp_abstain / (tp_abstain + fn_abstain) if (tp_abstain + fn_abstain) > 0 else 0.0
    abstain_f1 = (
        (2.0 * abstain_prec * abstain_rec / (abstain_prec + abstain_rec))
        if (abstain_prec + abstain_rec) > 0
        else 0.0
    )
    return {
        "mode": mode,
        "n_answerable": n_ans,
        "n_unanswerable": tp_abstain + fn_abstain,
        "recall_at_1": round(r1_sum / denom, 4),
        "recall_at_3": round(r3_sum / denom, 4),
        "recall_at_5": round(r5_sum / denom, 4),
        "mrr": round(mrr_sum / denom, 4),
        "ndcg_at_5": round(ndcg5_sum / denom, 4),
        "abstain_precision": round(abstain_prec, 4),
        "abstain_recall": round(abstain_rec, 4),
        "abstain_f1": round(abstain_f1, 4),
        "tp_abstain": tp_abstain,
        "fp_abstain": fp_abstain,
        "fn_abstain": fn_abstain,
        "tn_abstain": tn_abstain,
    }


def run_retrieval_benchmark(bench_path: Path = BENCH_V2_PATH) -> dict[str, Any]:
    """Evaluate all 4 pipelines on `bench_path` and identify the empirical best mode."""
    queries = [json.loads(ln) for ln in bench_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    results = {mode: evaluate_pipeline(queries, mode) for mode in ALL_PIPELINES}
    best_mode = max(
        ALL_PIPELINES,
        key=lambda m: (
            results[m]["recall_at_1"],
            results[m]["ndcg_at_5"],
            results[m]["mrr"],
            results[m]["abstain_f1"],
        ),
    )
    bm25_r1 = results["bm25_only"]["recall_at_1"]
    default_r1 = results[DEFAULT_RETRIEVAL_MODE]["recall_at_1"]
    return {
        "benchmark_path": str(bench_path),
        "total_queries": len(queries),
        "n_answerable": sum(1 for q in queries if not q.get("unanswerable", False)),
        "n_unanswerable": sum(1 for q in queries if q.get("unanswerable", False)),
        "default_mode": DEFAULT_RETRIEVAL_MODE,
        "empirical_best_mode": best_mode,
        "default_beats_or_ties_bm25_r1": default_r1 >= bm25_r1,
        "results": results,
    }


def format_retrieval_report(summary: dict[str, Any]) -> str:
    """Format a Markdown comparison table across all 4 pipelines."""
    lines = [
        f"# Retrieval v2 Benchmark Report (`{summary['benchmark_path']}`)",
        "",
        f"- **Queries:** `{summary['total_queries']}` "
        f"(`{summary['n_answerable']}` answerable, `{summary['n_unanswerable']}` unanswerable = "
        f"`{summary['n_unanswerable'] / max(summary['total_queries'], 1):.1%}`)",
        f"- **Configured Default Mode:** `{summary['default_mode']}`",
        f"- **Empirical Best Mode (R@1 -> nDCG@5 -> MRR):** `{summary['empirical_best_mode']}`",
        f"- **Default >= BM25 on Recall@1:** `{summary['default_beats_or_ties_bm25_r1']}`",
        "",
        "| Pipeline | Recall@1 | Recall@3 | Recall@5 | MRR | nDCG@5 | Abstain Prec | Abstain Rec | Abstain F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for mode in ALL_PIPELINES:
        m = summary["results"][mode]
        tag = " **(default)**" if mode == summary["default_mode"] else ""
        lines.append(
            f"| `{mode}`{tag} | {m['recall_at_1']:.3f} | {m['recall_at_3']:.3f} | {m['recall_at_5']:.3f} | "
            f"{m['mrr']:.3f} | {m['ndcg_at_5']:.3f} | {m['abstain_precision']:.3f} | "
            f"{m['abstain_recall']:.3f} | {m['abstain_f1']:.3f} |"
        )
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    rep = run_retrieval_benchmark()
    print(format_retrieval_report(rep))
