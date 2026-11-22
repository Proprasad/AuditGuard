"""
AuditGuard C0 - Fixed Deterministic Workflow Baseline.

A rigid linear pipeline with policy-default parameters, zero autonomous planning, zero replanning and a
root-only KYC lookup. Used as the fair baseline in Experiment E1. It runs through the SAME guarded toolbox
(RBAC, bounds, BudgetLedger, PII scrubbing, <untrusted_data> tagging) as C1/C2.
"""
from __future__ import annotations

from src.agent.telemetry import compute_network_flow_summary
from src.agent.tooling import GuardedToolbox, is_error
from src.config import get_policy
from src.core.adapters import flow_paths_from_result, graph_tx_payload, kyc_summaries
from src.db.database import utc_now_iso
from src.models import (
    Alert,
    DispositionDecision,
    DispositionWorksheet,
    GraphParams,
    Hypothesis,
    HypothesisLabel,
    InvestigationState,
)

ROLE = "c0_fixed"
FIXED_CONFIDENCE_ESCALATE = 0.65
FIXED_CONFIDENCE_INFO = 0.40


async def run_fixed_pipeline(alert: Alert) -> InvestigationState:
    policy = get_policy()
    ledger = policy.new_ledger()
    box = GuardedToolbox(ROLE, ledger)
    state = InvestigationState(alert=alert)
    params = GraphParams.policy_default()
    registry: dict[str, object] = {}
    degraded: list[str] = []

    ctx = await box.call("bank-records", "get_alert_context", {"alert_id": alert.alert_id})
    txs = [] if is_error(ctx) else ctx.get("transactions", [])
    root = alert.root_account if is_error(ctx) else ctx.get("root_account", alert.root_account)
    if is_error(ctx):
        degraded.append(f"Alert context unavailable: {ctx.get('error_code') or ctx.get('error')}")

    graph = await box.call("graph-engine", "find_candidate_fund_flows",
                           {"root_account": root, "transactions": graph_tx_payload(txs), **params.model_dump()})
    paths = []
    if is_error(graph):
        degraded.append(f"Graph analysis unavailable: {graph.get('error_code') or graph.get('error')}")
    else:
        paths = flow_paths_from_result(graph, limit=3)
        registry[graph["calc_id"]] = graph.get("graph_stats", {})
        registry.update({p.path_id: p.model_dump(mode="json") for p in paths})

    kyc = await box.call("bank-records", "get_kyc_profile", {"account_id": root})
    profiles = [] if is_error(kyc) else [kyc]
    if is_error(kyc):
        degraded.append(f"KYC unavailable: {kyc.get('error_code') or kyc.get('error')}")
    else:
        registry[kyc.get("evidence_id", f"KYC-{root}")] = kyc

    reg = await box.call("compliance-kb", "search_regulations", {"query": "scatter gather red flags", "top_k": 3, "decompose": False})
    clauses = [] if is_error(reg) else reg.get("clauses", [])
    if is_error(reg):
        degraded.append(f"Regulatory retrieval unavailable: {reg.get('error_code') or reg.get('error')}")
    registry.update({c["clause_id"]: c for c in clauses})
    registry.update({t["tx_id"]: t for t in txs if t.get("tx_id")})
    citations = [c["clause_id"] for c in clauses] or ["REG-FIU-RF-014"]

    multi_hop = [p for p in paths if p.hop_count >= 2]
    if multi_hop and not degraded:
        disposition, confidence = DispositionDecision.ESCALATE_STR, FIXED_CONFIDENCE_ESCALATE
        rationale = f"C0 Fixed Pipeline: {len(multi_hop)} multi-hop path(s) in fixed {params.time_window_days}d/{params.max_hops}-hop scan."
    else:
        disposition, confidence = DispositionDecision.REQUEST_INFO, FIXED_CONFIDENCE_INFO
        rationale = f"C0 Fixed Pipeline: 0 multi-hop consolidation paths in fixed {params.time_window_days}d/{params.max_hops}-hop scan."
    if degraded:
        rationale += " Degraded evidence: " + "; ".join(degraded)

    summaries = kyc_summaries(profiles, limit=1)
    draft = await box.call("case-actions", "draft_disposition_report", {
        "alert_id": alert.alert_id, "recommended_disposition": disposition.value, "recommendation_rationale": rationale,
        "confidence_score": confidence, "candidate_paths": [p.model_dump() for p in paths],
        "regulatory_citations": citations, "kyc_summaries": summaries,
    })
    state.worksheet = DispositionWorksheet(
        worksheet_id=draft.get("worksheet_id", ""), alert_id=alert.alert_id, investigator_agent="auditguard-c0-fixed",
        candidate_paths=paths,
        hypotheses=[Hypothesis(label=HypothesisLabel.SUSPICIOUS, explanation="C0 static scatter-gather detector output",
                               confidence=confidence, regulatory_citations=citations,
                               evidence_ids=[p.path_id for p in paths])],
        regulatory_citations=citations, kyc_summaries=summaries, recommended_disposition=disposition,
        recommendation_rationale=rationale, confidence_score=confidence, payload_hash=draft.get("payload_hash", ""),
    )
    state.transactions, state.fund_flow_paths, state.kyc_profiles = txs, paths, profiles
    state.degraded_evidence = degraded
    state.evidence_registry = registry
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
