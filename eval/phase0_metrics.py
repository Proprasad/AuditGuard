"""
Deterministic Phase 0 evaluation metric implementations & YAML metric validation.

Every metric listed in `config/experiments/E1.yaml`..`E4.yaml` is computed honestly from actual run
outputs (never hard-coded or skipped). If an experiment YAML requests an unimplemented metric name,
`validate_requested_metrics` raises `NotImplementedError` loudly per `docs/AGENT_GUIDE.md` §0.3 / §4 Phase 0.
"""

from __future__ import annotations

import re
from typing import Any

from src.core.verifier import extract_prose_amounts
from src.mcp_servers import compliance_kb

_EVIDENCE_ID_RE = re.compile(r"\b(?:TXN|KYC|REG|SOP|CALC|PATH|CP)-[A-Za-z0-9\-_]+\b")

SUPPORTED_CASE_METRICS: frozenset[str] = frozenset(
    {
        "disposition_accuracy",
        "evidence_recall",
        "replanning_recovery_rate",
        "replan_recovery_rate",
        "citation_validity_rate",
        "inr_arithmetic_error_rate",
        "cost_usd",
        "latency_seconds",
        "tool_errors",
        "tool_error_rate",
    }
)

SUPPORTED_RED_TEAM_METRICS: frozenset[str] = frozenset(
    {
        "attack_success_rate",
        "attack_block_rate",
        "false_block_rate",
        "unauthorized_write_attempts",
        "pii_leakage_count",
    }
)


def validate_requested_metrics(metrics: list[str], *, is_red_team: bool = False) -> None:
    supported = SUPPORTED_RED_TEAM_METRICS if is_red_team else SUPPORTED_CASE_METRICS
    unknown = [m for m in metrics if m not in supported]
    if unknown:
        raise NotImplementedError(
            f"Requested YAML metric(s) {unknown} have no implementation (supported={sorted(supported)})"
        )


def _corpus_clause_ids() -> set[str]:
    return {c.clause_id for c in compliance_kb.get_regulatory_index().clauses}


def gold_evidence_ids(case: dict[str, Any]) -> set[str]:
    if explicit := case.get("gold_evidence_ids"):
        return {str(x) for x in explicit}
    ids = {f"KYC-{case['root_account']}"}
    for tx in case.get("transactions", []):
        if tx.get("tx_id"):
            ids.add(str(tx["tx_id"]))
    return ids


def cited_evidence_ids(ws_dict: dict[str, Any] | None) -> set[str]:
    if not ws_dict:
        return set()
    found: set[str] = set()
    for p in ws_dict.get("candidate_paths", []):
        if isinstance(p, dict):
            found.update(str(tid) for tid in p.get("edge_tx_ids", []) if tid)
    for h in ws_dict.get("hypotheses", []):
        if isinstance(h, dict):
            found.update(str(eid) for eid in h.get("evidence_ids", []) if eid)
            found.update(_EVIDENCE_ID_RE.findall(str(h.get("explanation", ""))))
    for kyc_s in ws_dict.get("kyc_summaries", []):
        found.update(_EVIDENCE_ID_RE.findall(str(kyc_s)))
    found.update(_EVIDENCE_ID_RE.findall(str(ws_dict.get("recommendation_rationale", ""))))
    return found


def compute_case_quality(
    case: dict[str, Any],
    ws_dict: dict[str, Any] | None,
    discrepancies: list[dict[str, Any]],
) -> dict[str, float]:
    gold_ids = gold_evidence_ids(case)
    cited_ids = cited_evidence_ids(ws_dict)
    ev_recall = len(cited_ids & gold_ids) / len(gold_ids) if gold_ids else 1.0

    corpus_ids = _corpus_clause_ids()
    citations = list((ws_dict or {}).get("regulatory_citations", []))
    if citations:
        valid_cites = sum(1 for c in citations if c in corpus_ids)
        citation_validity = valid_cites / len(citations)
    else:
        citation_validity = 0.0

    texts = []
    if ws_dict:
        texts.append(str(ws_dict.get("recommendation_rationale", "")))
        texts.extend(str(h.get("explanation", "")) for h in ws_dict.get("hypotheses", []) if isinstance(h, dict))
    prose_nums = sum(len(extract_prose_amounts(t)) for t in texts)
    path_nums = len((ws_dict or {}).get("candidate_paths", [])) * 2
    denom = max(1, prose_nums + path_nums)
    math_errs = sum(
        1 for d in discrepancies if d.get("code") in ("UNGROUNDED_AMOUNT", "INR_MATH_DISCREPANCY", "PATH_MATH_MISMATCH")
    )
    inr_err_rate = min(1.0, math_errs / denom)
    return {
        "evidence_recall": ev_recall,
        "citation_validity_rate": citation_validity,
        "inr_arithmetic_error_rate": inr_err_rate,
    }


def aggregate_repeat_metrics(
    repeat_runs: list[list[dict[str, Any]]],
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    if not repeat_runs or not repeat_runs[0]:
        raise ValueError("Cannot aggregate metrics over an empty run list")
    flat = [r for run in repeat_runs for r in run]
    n = len(flat)
    repeat_accs = [sum(1 for r in run if r["correct"]) / len(run) for run in repeat_runs]

    replan_rows = [
        r
        for run in repeat_runs
        for r, c in zip(run, cases, strict=True)
        if c.get("expected_replan_required")
    ]
    recovery = (
        sum(1 for r in replan_rows if r["correct"] and r["replan_count"] >= 1) / len(replan_rows)
        if replan_rows
        else 0.0
    )
    total_calls = sum(int(r["tool_calls"]) for r in flat)
    total_errs = sum(int(r.get("tool_errors", 0)) for r in flat)
    mean_acc = sum(repeat_accs) / len(repeat_accs)
    avg_cost = sum(float(r["cost_usd"]) for r in flat) / n
    avg_lat = sum(float(r["latency_seconds"]) for r in flat) / n
    return {
        "disposition_accuracy": mean_acc,
        "mean_accuracy": mean_acc,
        "min_accuracy": min(repeat_accs),
        "max_accuracy": max(repeat_accs),
        "evidence_recall": sum(float(r["evidence_recall"]) for r in flat) / n,
        "replanning_recovery_rate": recovery,
        "replan_recovery_rate": recovery,
        "citation_validity_rate": sum(float(r["citation_validity_rate"]) for r in flat) / n,
        "inr_arithmetic_error_rate": sum(float(r["inr_arithmetic_error_rate"]) for r in flat) / n,
        "cost_usd": avg_cost,
        "avg_cost_usd": avg_cost,
        "latency_seconds": avg_lat,
        "avg_latency_seconds": avg_lat,
        "avg_tool_calls": total_calls / n,
        "avg_replans": sum(int(r["replan_count"]) for r in flat) / n,
        "avg_tokens": sum(int(r["tokens_used"]) for r in flat) / n,
        "tool_errors": total_errs,
        "tool_error_rate": (total_errs / total_calls) if total_calls else 0.0,
        "verified_rate": sum(1 for r in flat if r["math_verified"]) / n,
        "repeats_executed": len(repeat_runs),
        "correct": sum(1 for r in repeat_runs[-1] if r["correct"]),
        "total": len(repeat_runs[-1]),
    }
