"""
Phase 5 Exact Evaluation Metric Definitions (`eval/metrics.py`).

Implements every metric specified in `docs/AGENT_GUIDE.md` §4 Phase 5:
  * `disposition_accuracy`, `macro_f1`, and `3x3` `confusion_matrix`
  * `weighted_error_cost` (severity-weighted error cost per case)
  * `false_close_rate`: P(close_benign | gold == escalate_str)
  * `evidence_recall`: |cited & gold_evidence_ids| / |gold_evidence_ids|
  * `evidence_precision`: |cited & gold_evidence_ids| / |cited|
  * `replan_recovery_rate`: among cases where first scan misses gold consolidation, P(correct & replan_count >= 1)
  * `needless_replan_rate`: among cases where first scan is sufficient, P(replan_count >= 1)
  * `inr_arithmetic_error_rate`: inr_error_count / inr_numbers_total (from Verifier v2)
  * `citation_validity_rate`: fraction of citations that exist AND are typology-relevant
  * `judge_scores`: per-criterion G1..G7 mean / pass-rate (when judge evaluation is enabled)
  * `cost_usd`, `tokens`, `latency_s`, `tool_calls`: mean, 95% CI, plus `p50` and `p95`
  * `tool_error_rate`: total_tool_errors / total_tool_calls
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
import re
from typing import Any

from eval.judge import BINARY_CRITERIA, ORDINAL_CRITERIA
from eval.stats import cluster_bootstrap_ci, percentile, wilson_ci
from src.config import get_policy
from src.core import graph_math
from src.core.adapters import txn_from_record
from src.core.verifier import VerificationResult, extract_prose_amounts, load_corpus_category_map
from src.mcp_servers import compliance_kb
from src.typology_registry import typology_registry

DISPOSITIONS: tuple[str, ...] = ("close_benign", "request_info", "escalate_str")
_CASE_EVIDENCE_RE = re.compile(r"\b(?:TXN|KYC|REGISTRY|CP)-[A-Za-z0-9\-_]+\b")
_SYNTHETIC_TOOL_PREFIXES = ("PATH-", "CALC-", "REG-", "SOP-")

SUPPORTED_CASE_METRICS: frozenset[str] = frozenset(
    {
        "disposition_accuracy",
        "macro_f1",
        "confusion_matrix",
        "weighted_error_cost",
        "false_close_rate",
        "evidence_recall",
        "evidence_precision",
        "replan_recovery_rate",
        "replanning_recovery_rate",
        "needless_replan_rate",
        "inr_arithmetic_error_rate",
        "citation_validity_rate",
        "judge_scores",
        "cost_usd",
        "tokens",
        "latency_s",
        "latency_seconds",
        "tool_calls",
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
        "end_to_end_asr",
    }
)


def validate_requested_metrics(metrics: Sequence[str], *, is_red_team: bool = False) -> None:
    """Fail loudly with `NotImplementedError` if any metric requested by YAML has no implementation."""
    supported = SUPPORTED_RED_TEAM_METRICS if is_red_team else SUPPORTED_CASE_METRICS
    unknown = [m for m in metrics if m not in supported]
    if unknown:
        raise NotImplementedError(
            f"Requested YAML metric(s) {unknown} have no implementation (supported={sorted(supported)})"
        )


def gold_evidence_ids(case: Mapping[str, Any]) -> set[str]:
    if explicit := case.get("gold_evidence_ids"):
        return {str(x) for x in explicit}
    ids = {f"KYC-{case['root_account']}"}
    for tx in case.get("transactions", []):
        if isinstance(tx, Mapping) and tx.get("tx_id"):
            ids.add(str(tx["tx_id"]))
    return ids


def cited_evidence_ids(ws_dict: Mapping[str, Any] | None, gold_ids: set[str] | None = None) -> set[str]:
    """Extract case-level evidence IDs (`TXN-*`, `KYC-*`, `REGISTRY-*`, `CP-*`) cited in `ws_dict`."""
    if not ws_dict:
        return set()
    extra_allowed = gold_ids or set()
    found: set[str] = set()
    for p in ws_dict.get("candidate_paths", []):
        if isinstance(p, Mapping):
            found.update(str(tid) for tid in p.get("edge_tx_ids", []) if tid)
    for h in ws_dict.get("hypotheses", []):
        if isinstance(h, Mapping):
            for eid in h.get("evidence_ids", []):
                s = str(eid)
                if s and (not s.startswith(_SYNTHETIC_TOOL_PREFIXES) or s in extra_allowed):
                    found.add(s)
            found.update(_CASE_EVIDENCE_RE.findall(str(h.get("explanation", ""))))
    for kyc_s in ws_dict.get("kyc_summaries", []):
        found.update(_CASE_EVIDENCE_RE.findall(str(kyc_s)))
    found.update(_CASE_EVIDENCE_RE.findall(str(ws_dict.get("recommendation_rationale", ""))))
    return found


def first_scan_misses_consolidation(case: Mapping[str, Any]) -> bool:
    """True when the default `7d / 3-hop / 0.10` scan misses gold consolidation on a case."""
    if bool(case.get("expected_replan_required")):
        return True
    gold_disp = str(case.get("gold_disposition") or case.get("expected_disposition") or "")
    gold_consol = Decimal(str((case.get("gold_calc") or {}).get("consolidated") or "0"))
    txs = list(case.get("transactions") or [])
    if gold_disp != "escalate_str" or gold_consol <= Decimal("0") or not txs:
        return False
    txns = [
        txn_from_record(
            {
                "tx_id": str(t.get("tx_id", "")),
                "sender": str(t.get("sender") or t.get("sender_account") or ""),
                "receiver": str(t.get("receiver") or t.get("receiver_account") or ""),
                "amount_inr": str(t.get("amount_inr", "0")),
                "timestamp": str(t.get("timestamp", "")),
            }
        )
        for t in txs
        if isinstance(t, Mapping)
    ]
    policy = get_policy()
    gp = graph_math.GraphParams(**policy.default_graph_params(), anchor=None)
    run = graph_math.find_candidate_paths(txns, str(case["root_account"]), gp, policy.suspicion, policy.graph_limits)
    return not any(p.hop_count >= 2 for p in run.paths)


def compute_case_quality(
    case: Mapping[str, Any],
    ws_dict: Mapping[str, Any] | None,
    discrepancies: Sequence[Mapping[str, Any]],
    vr: VerificationResult | None = None,
) -> dict[str, Any]:
    """Compute per-case grounding, citation validity, and INR arithmetic error metrics."""
    g_ids = gold_evidence_ids(case)
    c_ids = cited_evidence_ids(ws_dict, g_ids)
    ev_recall = len(c_ids & g_ids) / len(g_ids) if g_ids else 1.0
    ev_precision = len(c_ids & g_ids) / len(c_ids) if c_ids else (1.0 if not g_ids else 0.0)

    corpus_ids = {c.clause_id for c in compliance_kb.get_regulatory_index().clauses}
    cat_map = load_corpus_category_map()
    allowed_cats = typology_registry.all_typology_categories("scatter_gather")
    citations = list((ws_dict or {}).get("regulatory_citations", []))
    if citations:
        claim_ok = True if vr is None else bool(vr.checks.get("citations_relevant", True))
        valid_cites = sum(
            1 for c in citations if c in corpus_ids and cat_map.get(str(c), "") in allowed_cats and claim_ok
        )
        citation_validity = valid_cites / len(citations)
    else:
        citation_validity = 0.0

    if vr is not None:
        inr_err_cnt = vr.inr_error_count
        inr_tot = vr.inr_numbers_total
        inr_err_rate = (inr_err_cnt / inr_tot) if inr_tot > 0 else 0.0
    else:
        texts: list[str] = []
        if ws_dict:
            texts.append(str(ws_dict.get("recommendation_rationale", "")))
            texts.extend(str(h.get("explanation", "")) for h in ws_dict.get("hypotheses", []) if isinstance(h, Mapping))
        prose_nums = sum(len(extract_prose_amounts(t)) for t in texts)
        path_nums = len((ws_dict or {}).get("candidate_paths", [])) * 2
        inr_tot = max(1, prose_nums + path_nums)
        inr_err_cnt = sum(
            1
            for d in discrepancies
            if d.get("code") in ("UNGROUNDED_AMOUNT", "UNGROUNDED_PERCENTAGE", "INR_NET_MISMATCH")
        )
        inr_err_rate = min(1.0, inr_err_cnt / inr_tot)
    return {
        "evidence_recall": ev_recall,
        "evidence_precision": ev_precision,
        "citation_validity_rate": citation_validity,
        "inr_error_count": inr_err_cnt,
        "inr_numbers_total": inr_tot,
        "inr_arithmetic_error_rate": inr_err_rate,
    }


def compute_error_cost(actual: str, acceptable: Sequence[str], severity_cost: Mapping[str, Any]) -> float:
    """Return severity cost (`0` if `actual` is in `acceptable`, else family error weight)."""
    if actual in set(acceptable):
        return 0.0
    if actual == "close_benign":
        return float(severity_cost.get("false_close", 10))
    if actual == "escalate_str":
        return float(severity_cost.get("false_escalate", 1))
    return float(severity_cost.get("false_request_info", 2))


def compute_confusion_and_macro_f1(
    gold_labels: Sequence[str],
    pred_labels: Sequence[str],
    acceptables: Sequence[Sequence[str]] | None = None,
) -> tuple[dict[str, dict[str, int]], float, dict[str, float]]:
    """Build `3x3` confusion matrix (`gold x predicted`) and macro-F1 across the 3 canonical dispositions."""
    matrix: dict[str, dict[str, int]] = {g: {p: 0 for p in DISPOSITIONS} for g in DISPOSITIONS}
    eff_gold: list[str] = []
    for idx, (g, p) in enumerate(zip(gold_labels, pred_labels, strict=True)):
        g_norm = g if g in DISPOSITIONS else "request_info"
        p_norm = p if p in DISPOSITIONS else "request_info"
        matrix[g_norm][p_norm] += 1
        acc_set = set(acceptables[idx]) if acceptables is not None else {g_norm}
        eff_gold.append(p_norm if p_norm in acc_set else g_norm)

    per_f1: dict[str, float] = {}
    for cls in DISPOSITIONS:
        tp = sum(1 for g, p in zip(eff_gold, pred_labels, strict=True) if g == cls and p == cls)
        fp = sum(1 for g, p in zip(eff_gold, pred_labels, strict=True) if g != cls and p == cls)
        fn = sum(1 for g, p in zip(eff_gold, pred_labels, strict=True) if g == cls and p != cls)
        denom = 2 * tp + fp + fn
        per_f1[cls] = round((2 * tp / denom) if denom > 0 else 0.0, 6)
    macro_f1 = round(sum(per_f1.values()) / len(DISPOSITIONS), 6)
    return matrix, macro_f1, per_f1


def _slice_breakdown(
    case_rows: Sequence[Mapping[str, Any]], key_fn: Any
) -> dict[str, dict[str, Any]]:
    buckets: dict[str, list[Mapping[str, Any]]] = {}
    for row in case_rows:
        buckets.setdefault(str(key_fn(row)), []).append(row)
    out: dict[str, dict[str, Any]] = {}
    for label, rows in sorted(buckets.items()):
        m = len(rows)
        esc = [r for r in rows if r["is_escalate_gold"]]
        out[label] = {
            "n": m,
            "disposition_accuracy": round(sum(float(r["correct"]) for r in rows) / m, 6),
            "weighted_error_cost": round(sum(float(r["error_cost"]) for r in rows) / m, 6),
            "false_close_rate": round(sum(float(r["false_close"]) for r in esc) / len(esc), 6) if esc else 0.0,
            "evidence_recall": round(sum(float(r["evidence_recall"]) for r in rows) / m, 6),
            "cost_usd": round(sum(float(r["cost_usd"]) for r in rows) / m, 6),
        }
    return out


def aggregate_mode_metrics(
    repeat_runs: list[list[dict[str, Any]]],
    cases: list[dict[str, Any]],
    *,
    seed: int = 42,
    execution_label: str = "llm",
) -> dict[str, Any]:
    """Aggregate repeat runs over `cases` with Wilson & 10k cluster-bootstrap 95% CIs and p50/p95 stats."""
    if not repeat_runs or not repeat_runs[0]:
        raise ValueError("Cannot aggregate metrics over an empty run list")
    n_cases = len(cases)
    n_rep = len(repeat_runs)
    for run in repeat_runs:
        if len(run) != n_cases:
            raise ValueError("Every repeat run must have exact 1:1 alignment with `cases`")

    clusters = [str(c.get("family") or c.get("category") or c["case_id"]) for c in cases]
    missed_flags = [first_scan_misses_consolidation(c) for c in cases]

    per_case: list[dict[str, Any]] = []
    for idx, c in enumerate(cases):
        reps = [repeat_runs[r][idx] for r in range(n_rep)]
        gold_d = str(c.get("gold_disposition") or c.get("expected_disposition"))
        accept = list(c.get("acceptable_dispositions") or [gold_d])
        sev = dict(c.get("severity_cost") or {"false_close": 10, "false_escalate": 1, "false_request_info": 2})
        missed = missed_flags[idx]
        per_case.append(
            {
                "case_id": str(c["case_id"]),
                "family": clusters[idx],
                "family_group": str(c.get("family_group") or clusters[idx].split(".")[0]),
                "difficulty": str(c.get("difficulty", "medium")),
                "is_escalate_gold": gold_d == "escalate_str",
                "first_scan_missed": missed,
                "correct": sum(1.0 if r["correct"] else 0.0 for r in reps) / n_rep,
                "error_cost": sum(compute_error_cost(str(r["actual"]), accept, sev) for r in reps) / n_rep,
                "false_close": sum(
                    1.0 if (gold_d == "escalate_str" and str(r["actual"]) == "close_benign") else 0.0 for r in reps
                )
                / n_rep,
                "evidence_recall": sum(float(r.get("evidence_recall", 0.0)) for r in reps) / n_rep,
                "evidence_precision": sum(float(r.get("evidence_precision", 0.0)) for r in reps) / n_rep,
                "replan_recovered": sum(
                    1.0 if (r["correct"] and int(r.get("replan_count", 0)) >= 1) else 0.0 for r in reps
                )
                / n_rep,
                "needless_replan": sum(1.0 if int(r.get("replan_count", 0)) >= 1 else 0.0 for r in reps) / n_rep,
                "inr_err_rate": sum(float(r.get("inr_arithmetic_error_rate", 0.0)) for r in reps) / n_rep,
                "inr_err_cnt": sum(int(r.get("inr_error_count", 0)) for r in reps),
                "inr_num_tot": sum(int(r.get("inr_numbers_total", 0)) for r in reps),
                "cite_valid": sum(float(r.get("citation_validity_rate", 0.0)) for r in reps) / n_rep,
                "cost_usd": sum(float(r.get("cost_usd", 0.0)) for r in reps) / n_rep,
                "tokens": sum(float(r.get("tokens_used", 0)) for r in reps) / n_rep,
                "latency_s": sum(float(r.get("latency_seconds", 0.0)) for r in reps) / n_rep,
                "tool_calls": sum(float(r.get("tool_calls", 0)) for r in reps) / n_rep,
                "tool_errors": sum(int(r.get("tool_errors", 0)) for r in reps),
                "total_calls_sum": sum(int(r.get("tool_calls", 0)) for r in reps),
                "math_verified": sum(1.0 if r.get("math_verified") else 0.0 for r in reps) / n_rep,
                "replans": sum(float(r.get("replan_count", 0)) for r in reps) / n_rep,
            }
        )

    flat = [r for run in repeat_runs for r in run]
    repeat_accs = [sum(1 for r in run if r["correct"]) / len(run) for run in repeat_runs]
    last_preds = [str(r["actual"]) for r in repeat_runs[-1]]
    gold_labels = [str(c.get("gold_disposition") or c.get("expected_disposition")) for c in cases]
    accept_lists = [list(c.get("acceptable_dispositions") or [g]) for c, g in zip(cases, gold_labels, strict=True)]
    conf_mat, macro_f1, per_class_f1 = compute_confusion_and_macro_f1(gold_labels, last_preds, accept_lists)

    esc_rows = [p for p in per_case if p["is_escalate_gold"]]
    miss_rows = [p for p in per_case if p["first_scan_missed"]]
    suff_rows = [p for p in per_case if not p["first_scan_missed"]]

    acc_w = wilson_ci(sum(p["correct"] for p in per_case), n_cases)
    fcr_w = wilson_ci(sum(p["false_close"] for p in esc_rows), len(esc_rows))
    rec_w = wilson_ci(sum(p["replan_recovered"] for p in miss_rows), len(miss_rows))
    ndl_w = wilson_ci(sum(p["needless_replan"] for p in suff_rows), len(suff_rows))

    err_ci = cluster_bootstrap_ci([p["error_cost"] for p in per_case], clusters, seed=seed)
    ev_rec_ci = cluster_bootstrap_ci([p["evidence_recall"] for p in per_case], clusters, seed=seed)
    ev_pre_ci = cluster_bootstrap_ci([p["evidence_precision"] for p in per_case], clusters, seed=seed)
    cite_ci = cluster_bootstrap_ci([p["cite_valid"] for p in per_case], clusters, seed=seed)
    inr_case_ci = cluster_bootstrap_ci([p["inr_err_rate"] for p in per_case], clusters, seed=seed)
    cost_ci = cluster_bootstrap_ci([p["cost_usd"] for p in per_case], clusters, seed=seed)
    tok_ci = cluster_bootstrap_ci([p["tokens"] for p in per_case], clusters, seed=seed)
    lat_ci = cluster_bootstrap_ci([p["latency_s"] for p in per_case], clusters, seed=seed)
    tc_ci = cluster_bootstrap_ci([p["tool_calls"] for p in per_case], clusters, seed=seed)

    tot_inr_err = sum(int(p["inr_err_cnt"]) for p in per_case)
    tot_inr_num = sum(int(p["inr_num_tot"]) for p in per_case)
    pooled_inr_err = (tot_inr_err / tot_inr_num) if tot_inr_num > 0 else inr_case_ci["mean"]

    tot_calls = sum(int(p["total_calls_sum"]) for p in per_case)
    tot_errs = sum(int(p["tool_errors"]) for p in per_case)
    tool_err_w = wilson_ci(tot_errs, tot_calls)

    judge_rows = [r["judge_scores"] for r in flat if isinstance(r.get("judge_scores"), Mapping)]
    judge_agg: dict[str, Any] | None = None
    if judge_rows:
        judge_agg = {
            **{c: round(sum(float(jr[c]) for jr in judge_rows) / len(judge_rows), 4) for c in ORDINAL_CRITERIA},
            **{
                b: round(sum(1.0 if str(jr[b]) == "pass" else 0.0 for jr in judge_rows) / len(judge_rows), 4)
                for b in BINARY_CRITERIA
            },
        }
        judge_agg["ordinal_mean"] = round(
            sum(judge_agg[c] for c in ORDINAL_CRITERIA) / len(ORDINAL_CRITERIA), 4
        )

    return {
        "execution_type": execution_label,
        "disposition_accuracy": acc_w["mean"],
        "mean_accuracy": acc_w["mean"],
        "min_accuracy": round(min(repeat_accs), 6),
        "max_accuracy": round(max(repeat_accs), 6),
        "macro_f1": macro_f1,
        "per_class_f1": per_class_f1,
        "confusion_matrix": conf_mat,
        "weighted_error_cost": err_ci["mean"],
        "false_close_rate": fcr_w["mean"],
        "evidence_recall": ev_rec_ci["mean"],
        "evidence_precision": ev_pre_ci["mean"],
        "replan_recovery_rate": rec_w["mean"],
        "replanning_recovery_rate": rec_w["mean"],
        "needless_replan_rate": ndl_w["mean"],
        "inr_arithmetic_error_rate": round(pooled_inr_err, 6),
        "inr_error_count": tot_inr_err,
        "inr_numbers_total": tot_inr_num,
        "citation_validity_rate": cite_ci["mean"],
        "judge_scores": judge_agg,
        "cost_usd": cost_ci["mean"],
        "avg_cost_usd": cost_ci["mean"],
        "tokens": tok_ci["mean"],
        "avg_tokens": tok_ci["mean"],
        "latency_s": lat_ci["mean"],
        "latency_seconds": lat_ci["mean"],
        "avg_latency_seconds": lat_ci["mean"],
        "tool_calls": tc_ci["mean"],
        "avg_tool_calls": tc_ci["mean"],
        "avg_replans": round(sum(p["replans"] for p in per_case) / n_cases, 6),
        "tool_errors": tot_errs,
        "tool_error_rate": tool_err_w["mean"],
        "verified_rate": round(sum(p["math_verified"] for p in per_case) / n_cases, 6),
        "repeats_executed": n_rep,
        "correct": sum(1 for r in repeat_runs[-1] if r["correct"]),
        "total": n_cases,
        "ci_95": {
            "disposition_accuracy": acc_w,
            "weighted_error_cost": err_ci,
            "false_close_rate": fcr_w,
            "evidence_recall": ev_rec_ci,
            "evidence_precision": ev_pre_ci,
            "replan_recovery_rate": rec_w,
            "needless_replan_rate": ndl_w,
            "inr_arithmetic_error_rate": {**inr_case_ci, "mean": round(pooled_inr_err, 6)},
            "citation_validity_rate": cite_ci,
            "cost_usd": cost_ci,
            "tokens": tok_ci,
            "latency_s": lat_ci,
            "tool_calls": tc_ci,
            "tool_error_rate": tool_err_w,
        },
        "percentiles": {
            "cost_usd": {
                "p50": round(percentile([float(r.get("cost_usd", 0.0)) for r in flat], 50.0), 6),
                "p95": round(percentile([float(r.get("cost_usd", 0.0)) for r in flat], 95.0), 6),
            },
            "tokens": {
                "p50": round(percentile([float(r.get("tokens_used", 0)) for r in flat], 50.0), 2),
                "p95": round(percentile([float(r.get("tokens_used", 0)) for r in flat], 95.0), 2),
            },
            "latency_s": {
                "p50": round(percentile([float(r.get("latency_seconds", 0.0)) for r in flat], 50.0), 6),
                "p95": round(percentile([float(r.get("latency_seconds", 0.0)) for r in flat], 95.0), 6),
            },
            "tool_calls": {
                "p50": round(percentile([float(r.get("tool_calls", 0)) for r in flat], 50.0), 2),
                "p95": round(percentile([float(r.get("tool_calls", 0)) for r in flat], 95.0), 2),
            },
        },
        "per_family": _slice_breakdown(per_case, lambda r: r["family_group"]),
        "per_subvariant": _slice_breakdown(per_case, lambda r: r["family"]),
        "per_difficulty": _slice_breakdown(per_case, lambda r: r["difficulty"]),
        "_case_series": per_case,
    }
