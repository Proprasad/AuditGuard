"""
AuditGuard C0 - Fixed Deterministic Workflow Baseline.

A rigid linear pipeline with policy-default parameters, zero autonomous planning, zero replanning and a
root-only KYC lookup. Used as the fair baseline in Experiment E1. It runs through the SAME guarded toolbox
(RBAC, bounds, BudgetLedger, PII scrubbing, escaped <untrusted_data>, injection detection) and the SAME
fail-closed drafting/verification as C1/C2.
"""
from __future__ import annotations

from typing import Any, Optional

from src.agent.drafting import draft_and_verify, security_notes
from src.agent.telemetry import compute_network_flow_summary
from src.agent.tooling import GuardedToolbox, is_error
from src.config import get_policy
from src.core.adapters import flow_paths_from_result, graph_tx_payload, kyc_summaries
from src.db.database import utc_now_iso
from src.models import (
    Alert,
    DispositionDecision,
    GraphParams,
    Hypothesis,
    HypothesisLabel,
    InvestigationState,
)

ROLE = "c0_fixed"
FIXED_CONFIDENCE_ESCALATE = 0.65
FIXED_CONFIDENCE_INFO = 0.40


def _err(result: dict[str, Any]) -> str:
    return str(result.get("error_code") or result.get("error"))


async def run_fixed_pipeline(alert: Alert, thread_id: Optional[str] = None, verify: bool = True) -> InvestigationState:
    policy = get_policy()
    ledger = policy.new_ledger()
    state = InvestigationState(alert=alert) if thread_id is None else InvestigationState(alert=alert, thread_id=thread_id)
    box = GuardedToolbox(ROLE, ledger, state.thread_id)
    params = GraphParams.policy_default()
    registry: dict[str, Any] = {}
    degraded: list[str] = []

    ctx = await box.call("bank-records", "get_alert_context", {"alert_id": alert.alert_id})
    txs = [] if is_error(ctx) else ctx.get("transactions", [])
    root = alert.root_account if is_error(ctx) else ctx.get("root_account", alert.root_account)
    if is_error(ctx):
        degraded.append(f"Alert context unavailable: {_err(ctx)}")

    graph = await box.call("graph-engine", "find_candidate_fund_flows",
                           {"root_account": root, "transactions": graph_tx_payload(txs), **params.model_dump()})
    paths = []
    if is_error(graph):
        degraded.append(f"Graph analysis unavailable: {_err(graph)}")
    else:
        paths = flow_paths_from_result(graph, limit=3)
        registry[graph["calc_id"]] = graph.get("graph_stats", {})
        registry.update({p.path_id: p.model_dump(mode="json") for p in paths})

    kyc = await box.call("bank-records", "get_kyc_profile", {"account_id": root})
    profiles = [] if is_error(kyc) else [kyc]
    if is_error(kyc):
        degraded.append(f"KYC unavailable: {_err(kyc)}")
    else:
        registry[kyc.get("evidence_id", f"KYC-{root}")] = kyc

    reg = await box.call("compliance-kb", "search_regulations", {"query": "scatter gather red flags", "top_k": 3, "decompose": False})
    clauses = [] if is_error(reg) else reg.get("clauses", [])
    if is_error(reg):
        degraded.append(f"Regulatory retrieval unavailable: {_err(reg)}")
    registry.update({c["clause_id"]: c for c in clauses})
    registry.update({t["tx_id"]: t for t in txs if t.get("tx_id")})
    citations = [c["clause_id"] for c in clauses]
    degraded = sorted({*degraded, *security_notes(box)})

    multi_hop = [p for p in paths if p.hop_count >= 2]
    window = f"{params.time_window_days}d/{params.max_hops}-hop"
    if multi_hop and not degraded:
        disposition, confidence = DispositionDecision.ESCALATE_STR, FIXED_CONFIDENCE_ESCALATE
        rationale = f"C0 Fixed Pipeline: {len(multi_hop)} multi-hop path(s) in fixed {window} scan."
    else:
        disposition, confidence = DispositionDecision.REQUEST_INFO, FIXED_CONFIDENCE_INFO
        rationale = f"C0 Fixed Pipeline: {len(multi_hop)} multi-hop consolidation paths in fixed {window} scan."
    if degraded:
        rationale += " Degraded evidence: " + "; ".join(degraded)

    summaries = kyc_summaries(profiles, limit=1)
    hypotheses = [Hypothesis(label=HypothesisLabel.SUSPICIOUS, explanation="C0 static scatter-gather detector output",
                             confidence=confidence, regulatory_citations=citations, evidence_ids=[p.path_id for p in paths])]
    outcome = await draft_and_verify(
        box=box, ledger=ledger, alert=alert, agent_label="auditguard-c0-fixed", thread_id=state.thread_id,
        disposition=disposition, confidence=confidence, paths=paths, hypotheses=hypotheses, citations=citations,
        summaries=summaries, registry=registry, replan_count=0, base_rationale=rationale, degraded=degraded,
        use_strong_model=False, verify=verify,
    )
    state.worksheet = outcome.worksheet
    state.error = "verification_failed" if outcome.verification_failed else None
    state.transactions, state.fund_flow_paths, state.kyc_profiles = txs, paths, profiles
    state.degraded_evidence = degraded
    state.evidence_registry = registry
    state.active_hypotheses = outcome.worksheet.hypotheses
    state.flow_summary = compute_network_flow_summary(root, txs, paths, profiles)
    state.tool_calls_used = ledger.calls_used
    state.workflow_steps = [
        {"step": 1, "name": "Alert Intake & Validation", "status": "completed"},
        {"step": 2, "name": "Fixed Sequence Setup (No Agent Plan)", "status": "completed"},
        {"step": 3, "name": f"Fixed Graph & KYC Scan ({params.time_window_days}d / {params.max_hops}-hop)", "status": "completed"},
        {"step": 4, "name": "Rule-Based Synthesis", "status": "completed"},
        {"step": 5, "name": "Verification (Deterministic)", "status": "completed"},
        {"step": 6, "name": "Human Approval", "status": "waiting_approval"},
        {"step": 7, "name": "Case Commit & Reporting", "status": "pending"},
    ]
    state.agent_runs = [{
        "agent_id": "c0_pipeline", "agent_name": "Fixed Deterministic Pipeline (C0)",
        "task": "Static scan without replanning or commercial registry checks", "status": "completed",
        "started_at": utc_now_iso(), "tool_calls": ledger.calls_used, "summary": rationale,
    }]
    state.current_node = "completed"
    state.is_complete = True
    return state
