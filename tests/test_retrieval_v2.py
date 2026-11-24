"""
Phase 6 — Retrieval v2 Acceptance & Integrity Test Suite (`tests/test_retrieval_v2.py`).

Covers all `docs/AGENT_GUIDE.md` §4 Phase 6 requirements:
  1. Corpus v2: >= 150 passages, 100-300 words each, verifiable statutory metadata (`source_url`,
     `retrieval_date`, `clause_number`), `source_type` separation (`regulatory` vs `internal`),
     zero legacy invented `REG-*` IDs, and `[HUMAN]` verification checklist.
  2. Benchmark v2: >= 100 queries with paraphrases, multi-clause queries, and ~20% unanswerable.
  3. All 4 pipelines (`bm25_only`, `dense_only`, `hybrid_rrf`, `hybrid_rrf_rerank`) measured on
     Recall@1/3/5, MRR, nDCG@5, and abstain precision; enforces hybrid >= BM25 on R@1 (or hybrid
     removed from the default path).
  4. Calibrated abstention on out-of-scope queries and `source_type` filtering via MCP tool.
  5. Case-specific regulatory query formulation (typology, benign hypothesis, missing evidence)
     and Verifier v2 `citations_exist` enforcement on v2 passage IDs.
  6. CLI `python -m src.cli retrieval-bench --report` prints all required metrics and pipelines.
"""

from __future__ import annotations

from decimal import Decimal
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from eval.retrieval_eval import ALL_PIPELINES, run_retrieval_benchmark
from src.agent.gathering import build_case_regulatory_queries
from src.cli import app as cli_app
from src.core.verifier import verify_worksheet
from src.mcp_servers.client import call_mcp_tool
from src.mcp_servers.compliance_kb import DEFAULT_RETRIEVAL_MODE
from src.models import Alert, FundFlowPath, RiskLevel

CORPUS_PATH = Path("data/regulatory_corpus/indian_aml_corpus.jsonl")
CHECKLIST_PATH = Path("data/regulatory_corpus/HUMAN_VERIFICATION_CHECKLIST.md")
BENCH_V2_PATH = Path("eval/retrieval_bench_v2.jsonl")


def test_corpus_v2_structure_size_word_count_and_provenance() -> None:
    records = [json.loads(ln) for ln in CORPUS_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(records) >= 150
    assert CHECKLIST_PATH.exists()

    reg = [r for r in records if r.get("source_type") == "regulatory"]
    internal = [r for r in records if r.get("source_type") == "internal"]
    assert len(reg) >= 120
    assert len(internal) >= 15
    assert len(reg) + len(internal) == len(records)

    seen_ids: set[str] = set()
    for rec in records:
        pid = str(rec["passage_id"])
        assert pid not in seen_ids
        seen_ids.add(pid)
        assert not pid.startswith("REG-"), f"Legacy invented REG-* ID remaining: {pid}"
        assert pid != "PMLA-2002-S13"
        wc = len(str(rec["text"]).split())
        assert 100 <= wc <= 300, f"{pid} word count {wc} outside [100, 300]"
        assert rec.get("source_url")
        assert rec.get("retrieval_date")
        assert rec.get("clause_number")
        if rec["source_type"] == "regulatory":
            assert rec["source_url"].startswith("https://")
            assert rec.get("human_verified") is False
        else:
            assert rec["source_url"].startswith("internal://")


def test_benchmark_v2_composition_and_unanswerable_ratio() -> None:
    corpus_ids = {
        str(json.loads(ln)["passage_id"])
        for ln in CORPUS_PATH.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    }
    queries = [json.loads(ln) for ln in BENCH_V2_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(queries) >= 100

    n_para = sum(1 for q in queries if q["query_type"] == "paraphrase")
    n_multi = sum(1 for q in queries if q["query_type"] == "multi_clause")
    n_unans = sum(1 for q in queries if q["unanswerable"])
    assert n_para >= 50
    assert n_multi >= 20
    assert 0.18 <= (n_unans / len(queries)) <= 0.22

    for q in queries:
        if q["unanswerable"]:
            assert q["expected_ids"] == []
        else:
            assert len(q["expected_ids"]) >= 1
            for eid in q["expected_ids"]:
                assert eid in corpus_ids


def test_retrieval_v2_all_four_pipelines_and_hybrid_ge_bm25_r1() -> None:
    summary = run_retrieval_benchmark(BENCH_V2_PATH)
    results = summary["results"]
    assert set(results.keys()) == set(ALL_PIPELINES)

    required_metrics = (
        "recall_at_1",
        "recall_at_3",
        "recall_at_5",
        "mrr",
        "ndcg_at_5",
        "abstain_precision",
        "abstain_recall",
        "abstain_f1",
    )
    for mode in ALL_PIPELINES:
        for k in required_metrics:
            val = float(results[mode][k])
            assert 0.0 <= val <= 1.0

    # Acceptance gate: hybrid >= BM25 on R@1 OR hybrid is removed from the default path.
    bm25_r1 = results["bm25_only"]["recall_at_1"]
    default_r1 = results[DEFAULT_RETRIEVAL_MODE]["recall_at_1"]
    assert default_r1 >= bm25_r1, f"Default {DEFAULT_RETRIEVAL_MODE} R@1={default_r1} < BM25 R@1={bm25_r1}"
    if DEFAULT_RETRIEVAL_MODE in ("hybrid_rrf", "hybrid_rrf_rerank"):
        assert results["hybrid_rrf"]["recall_at_1"] >= bm25_r1
    if DEFAULT_RETRIEVAL_MODE == "hybrid_rrf_rerank":
        assert results["hybrid_rrf_rerank"]["recall_at_1"] >= results["hybrid_rrf"]["recall_at_1"]

    assert results[DEFAULT_RETRIEVAL_MODE]["abstain_precision"] >= 0.85
    assert results[DEFAULT_RETRIEVAL_MODE]["abstain_recall"] >= 0.75


@pytest.mark.asyncio
async def test_source_type_filter_and_abstention_mcp_tool() -> None:
    reg_only = await call_mcp_tool(
        "compliance-kb",
        "search_regulations",
        {"query": "seven working days STR filing Principal Officer FIU-IND", "top_k": 5, "source_type": "regulatory"},
    )
    assert reg_only["status"] == "ok" and not reg_only["abstained"]
    assert reg_only["clauses"] and all(c["source_type"] == "regulatory" for c in reg_only["clauses"])

    sop_only = await call_mcp_tool(
        "compliance-kb",
        "search_regulations",
        {"query": "bounded graph replanning expand time_window_days", "top_k": 5, "source_type": "internal"},
    )
    assert sop_only["status"] == "ok" and not sop_only["abstained"]
    assert sop_only["clauses"] and all(c["source_type"] == "internal" for c in sop_only["clauses"])

    oos = await call_mcp_tool(
        "compliance-kb",
        "search_regulations",
        {"query": "What is the SEBI insider trading penalty multiplier for unpublished price sensitive information?"},
    )
    assert oos["status"] == "ok"
    assert oos["abstained"] is True
    assert oos["clauses"] == []


def test_case_specific_regulatory_query_formulation_and_verifier_citations_exist() -> None:
    alert_skim = Alert(
        alert_id="ALT-SKIM",
        rule_name="FEE_SKIMMING_MULE",
        root_account="ACC-1",
        total_amount_inr="900000.00",
        risk_level=RiskLevel.HIGH,
    )
    path_skim = FundFlowPath(
        path_id="PATH-1",
        nodes=["ACC-1", "ACC-2", "ACC-3"],
        edge_tx_ids=["TXN-1", "TXN-2"],
        total_outflow_inr=Decimal("900000.00"),
        total_consolidated_inr=Decimal("828000.00"),
        net_difference_inr=Decimal("72000.00"),
        retention_pct=Decimal("8.00"),
        amount_leaked_ratio=Decimal("0.0800"),
        hop_count=2,
        time_span_days=3,
    )
    q_skim = build_case_regulatory_queries(alert_skim, [path_skim], [], [])

    alert_mkt = Alert(
        alert_id="ALT-MKT",
        rule_name="SCATTER_GATHER",
        root_account="ACC-MKT",
        total_amount_inr="1500000.00",
        risk_level=RiskLevel.MEDIUM,
    )
    q_mkt = build_case_regulatory_queries(
        alert_mkt,
        [],
        [{"entity_name": "BharatCart Marketplace Escrow", "occupation": "ecommerce payment aggregator"}],
        ["External correspondent bank log unavailable"],
    )

    assert len(q_skim) == 3 and len(q_mkt) == 3
    assert q_skim[0] != q_mkt[0]
    assert "skimming" in q_skim[0].lower()
    assert "payment aggregator" in q_mkt[1].lower()
    assert "correspondent" in q_mkt[2].lower()

    # Verifier v2 enforces `citations_exist` on real Corpus v2 passage IDs
    registry = {
        "TXN-1": {"tx_id": "TXN-1", "amount_inr": "900000.00"},
        "FIU-IND-RFI-BA-04": {"clause_id": "FIU-IND-RFI-BA-04", "category": "fee_skimming"},
        "PMLR-2005-R8-P02": {"clause_id": "PMLR-2005-R8-P02", "category": "filing_timeline"},
    }
    ws_ok = {
        "alert_id": "ALT-SKIM",
        "recommended_disposition": "escalate_str",
        "confidence_score": "0.8500",
        "recommendation_rationale": (
            "Transfer TXN-1 moved INR 900000.00 matching FIU-IND-RFI-BA-04 and PMLR-2005-R8-P02. "
            "Missing evidence: Beneficiary invoices."
        ),
        "regulatory_citations": ["FIU-IND-RFI-BA-04", "PMLR-2005-R8-P02"],
        "alert_amount_inr": "900000.00",
        "hypotheses": [
            {
                "label": "suspicious",
                "explanation": "Mule skimming on TXN-1.",
                "confidence": "0.8500",
                "evidence_ids": ["TXN-1"],
                "regulatory_citations": ["FIU-IND-RFI-BA-04"],
            },
            {
                "label": "benign",
                "explanation": "Checked commercial status on TXN-1.",
                "confidence": "0.1500",
                "evidence_ids": ["TXN-1"],
                "regulatory_citations": ["PMLR-2005-R8-P02"],
            },
        ],
        "missing_evidence": ["Beneficiary invoices"],
    }
    vr_ok = verify_worksheet(ws_ok, registry)
    assert vr_ok.passed is True, vr_ok.errors

    ws_unretrieved = {**ws_ok, "regulatory_citations": ["PMLA-2002-S12-P01"]}
    vr_bad = verify_worksheet(ws_unretrieved, registry)
    assert vr_bad.passed is False and vr_bad.checks["citations_exist"] is False


def test_cli_retrieval_bench_report_prints_all_metrics() -> None:
    runner = CliRunner()
    res = runner.invoke(cli_app, ["retrieval-bench", "--report"])
    assert res.exit_code == 0, res.stdout
    for expected in (
        "bm25_only",
        "dense_only",
        "hybrid_rrf",
        "hybrid_rrf_rerank",
        "Recall@1",
        "Recall@3",
        "Recall@5",
        "MRR",
        "nDCG@5",
        "Abstain Prec",
    ):
        assert expected in res.stdout
