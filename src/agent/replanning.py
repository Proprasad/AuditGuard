"""
Structured Evidence-Driven Replanning & Before/After Comparison (`src/agent/replanning.py`).

Captures every replan attempt (approved, rejected, or failed) as a typed `ReplanRecord`,
preserves original graph paths/evidence without overwriting history, and measures whether
a replan actually improved evidence coverage or resolved the investigation gap.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from src.core.investigation_contracts import (
    ReplanComparison,
    ReplanExecutionStatus,
    ReplanRecord,
    ReplanSnapshot,
    ReplanValidationStatus,
)
from src.models import FundFlowPath, GraphParams


def _completeness_level(
    paths: Sequence[FundFlowPath], evidence_count: int, unresolved: int
) -> Literal["complete", "partial", "insufficient"]:
    multi = sum(1 for p in paths if p.hop_count >= 2)
    if multi >= 1 and evidence_count >= 4 and unresolved == 0:
        return "complete"
    if paths or evidence_count >= 3:
        return "partial"
    return "insufficient"


def capture_replan_snapshot(
    params: GraphParams,
    paths: Sequence[FundFlowPath],
    evidence_registry: Mapping[str, Any],
    *,
    contradictions_count: int = 0,
    unresolved_questions_count: int = 0,
) -> ReplanSnapshot:
    """Capture point-in-time investigation metrics before or after a replan."""
    multi = sum(1 for p in paths if p.hop_count >= 2)
    substantive_ev = sum(1 for k in evidence_registry if not str(k).startswith("CALC-"))
    return ReplanSnapshot(
        time_window_days=params.time_window_days,
        max_hops=params.max_hops,
        amount_tolerance=params.amount_tolerance,
        candidate_paths_count=len(paths),
        multi_hop_paths_count=multi,
        evidence_count=substantive_ev,
        contradictions_count=contradictions_count,
        unresolved_questions_count=unresolved_questions_count,
        completeness=_completeness_level(paths, substantive_ev, unresolved_questions_count),
    )


def build_replan_comparison(
    before: ReplanSnapshot,
    after: ReplanSnapshot,
    old_path_ids: set[str],
    new_paths: Sequence[FundFlowPath],
) -> ReplanComparison:
    """Compare original vs. replanned investigation passes and determine whether coverage improved."""
    new_ids = [p.path_id for p in new_paths if p.path_id not in old_path_ids]
    evidence_delta = after.evidence_count - before.evidence_count
    gained_multi = after.multi_hop_paths_count > before.multi_hop_paths_count
    gained_paths = bool(new_ids) or after.candidate_paths_count > before.candidate_paths_count
    resolved_gap = after.unresolved_questions_count < before.unresolved_questions_count
    improved = gained_multi or gained_paths or evidence_delta > 0 or resolved_gap

    if improved:
        summary = (
            f"Replan improved coverage: +{len(new_ids)} new path(s) "
            f"(multi-hop {before.multi_hop_paths_count}->{after.multi_hop_paths_count}), "
            f"evidence {before.evidence_count}->{after.evidence_count} "
            f"(window {before.time_window_days}d->{after.time_window_days}d, "
            f"hops {before.max_hops}->{after.max_hops})."
        )
    else:
        summary = (
            f"Replan produced no new paths or evidence improvement "
            f"(paths {before.candidate_paths_count}->{after.candidate_paths_count}, "
            f"evidence {before.evidence_count}->{after.evidence_count}); "
            "recorded without triggering uncontrolled retries."
        )
    return ReplanComparison(
        before=before,
        after=after,
        new_path_ids=new_ids,
        evidence_delta=evidence_delta,
        improved=improved,
        improvement_summary=summary,
    )


def infer_replan_trigger(reason: str, before: ReplanSnapshot) -> tuple[str, str]:
    """Derive structured trigger condition and expected benefit from replan context."""
    low = (reason or "").lower()
    if any(k in low for k in ("stagger", "delay", "window", "day")):
        return "staggered_transaction_window", "Capture delayed downstream consolidation beyond initial window"
    if any(k in low for k in ("hop", "intermediar", "layer", "tier")):
        return "undiscovered_intermediary_layer", "Uncover deeper multi-hop intermediary links"
    if any(k in low for k in ("fee", "skim", "toleran", "leak")):
        return "fee_skim_tolerance_gap", "Capture consolidation paths with intermediary fee retention"
    if any(k in low for k in ("kyc", "contradict", "benign", "registry")):
        return "kyc_hypothesis_contradiction", "Reconcile graph topology against contradictory KYC/registry records"
    if before.multi_hop_paths_count == 0:
        return "unexplained_outbound_dispersal", "Test whether outbound transfers consolidate over wider bounds"
    return "evidence_gap_expansion", "Verify completeness of candidate fund-flow network within policy bounds"


def build_replan_record(
    *,
    seq: int,
    original_params: GraphParams,
    proposed_params: GraphParams,
    reason: str,
    evidence_ids: Sequence[str],
    before: ReplanSnapshot,
    validation_result: ReplanValidationStatus,
    validation_detail: str = "",
    execution_status: ReplanExecutionStatus = "executed",
    comparison: ReplanComparison | None = None,
) -> ReplanRecord:
    """Construct a typed `ReplanRecord` for approved, rejected, or failed replans."""
    trigger, benefit = infer_replan_trigger(reason, before)
    return ReplanRecord(
        replan_id=f"RPL-{seq:02d}",
        trigger_condition=trigger,
        contradiction_or_gap=reason.strip() or "Initial graph scan left unresolved transfer legs",
        evidence_ids=list(dict.fromkeys(str(e) for e in evidence_ids if e))[:12],
        original_params=original_params,
        proposed_params=proposed_params,
        reason=reason.strip() or "Bounded parameter expansion",
        expected_benefit=benefit,
        validation_result=validation_result,
        validation_detail=validation_detail or validation_result,
        execution_status=execution_status,
        comparison=comparison,
    )
