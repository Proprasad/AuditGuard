"""
AuditGuard C0 - Fixed Deterministic Workflow Baseline compiled as a linear LangGraph `StateGraph`.

Topology: `START -> gather_evidence -> draft -> human_gate(interrupt) -> END`
Policy-default parameters, zero autonomous planning, zero replanning and a root-only KYC lookup, while running
through the SAME `GuardedToolbox` (RBAC, bounds, BudgetLedger, PII scrubbing, escaped <untrusted_data>, injection
withholding), fail-closed `draft_and_verify`, and native LangGraph `interrupt()` human gate as C1/C2.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from decimal import Decimal
from typing import Any, Optional

from src.agent.drafting import draft_and_verify, security_notes
from src.agent.nodes import RunContext
from src.agent.telemetry import compute_network_flow_summary
from src.agent.tooling import is_error
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


async def scan_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    t0 = time.perf_counter()
    box = ctx.box("primary")
    params = GraphParams.policy_default()
    registry: dict[str, Any] = dict(state.evidence_registry)
    degraded: list[str] = list(state.degraded_evidence)

    alert_ctx = await box.call("bank-records", "get_alert_context", {"alert_id": state.alert.alert_id})
    txs = [] if is_error(alert_ctx) else alert_ctx.get("transactions", [])
    root = state.alert.root_account if is_error(alert_ctx) else alert_ctx.get("root_account", state.alert.root_account)
    if is_error(alert_ctx):
        degraded.append(f"Alert context unavailable: {_err(alert_ctx)}")
    registry.update({t["tx_id"]: t for t in txs if t.get("tx_id")})

    graph = await box.call(
        "graph-engine",
        "find_candidate_fund_flows",
        {"root_account": root, "transactions": graph_tx_payload(txs), **params.model_dump()},
    )
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

    reg = await box.call(
        "compliance-kb",
        "search_regulations",
        {"query": "scatter gather red flags", "top_k": 3, "decompose": False},
    )
    clauses = [] if is_error(reg) else [c for c in reg.get("clauses", []) if isinstance(c, dict) and c.get("clause_id")]
    if is_error(reg):
        degraded.append(f"Regulatory retrieval unavailable: {_err(reg)}")
    registry.update({c["clause_id"]: c for c in clauses})
    snippets = [f"[{c['clause_id']}] {c.get('title', '')}: {c.get('text', '')}" for c in clauses]
    degraded = sorted({*degraded, *security_notes(box)})
    ctx.timings["scan_ms"] = (time.perf_counter() - t0) * 1000
    cap = ctx.policy.budgets.max_cost_usd_per_case
    return {
        "transactions": txs,
        "fund_flow_paths": paths,
        "kyc_profiles": profiles,
        "regulatory_clauses": clauses,
        "regulatory_snippets": snippets,
        "evidence_registry": registry,
        "degraded_evidence": degraded,
        "current_node": "gather_evidence",
        "current_step": state.current_step + 1,
        "tool_calls_used": ctx.ledger.calls_used,
        "total_tokens_used": 0,
        "estimated_cost_usd": Decimal("0"),
        "budget_remaining_usd": cap,
    }


async def draft_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    t0 = time.perf_counter()
    box = ctx.box("primary")
    params = GraphParams.policy_default()
    degraded = sorted({*state.degraded_evidence, *security_notes(box)})
    citations = [c["clause_id"] for c in state.regulatory_clauses if c.get("clause_id")]
    multi_hop = [p for p in state.fund_flow_paths if p.hop_count >= 2]
    window = f"{params.time_window_days}d/{params.max_hops}-hop"
    if multi_hop and not degraded:
        disposition, confidence = DispositionDecision.ESCALATE_STR, FIXED_CONFIDENCE_ESCALATE
        rationale = f"C0 Fixed Pipeline: {len(multi_hop)} multi-hop path(s) in fixed {window} scan."
    else:
        disposition, confidence = DispositionDecision.REQUEST_INFO, FIXED_CONFIDENCE_INFO
        rationale = f"C0 Fixed Pipeline: {len(multi_hop)} multi-hop consolidation paths in fixed {window} scan."
    if degraded:
        rationale += " Degraded evidence: " + "; ".join(degraded)

    summaries = kyc_summaries(state.kyc_profiles, limit=1)
    hypotheses = [
        Hypothesis(
            label=HypothesisLabel.SUSPICIOUS,
            explanation="C0 static scatter-gather detector output",
            confidence=confidence,
            regulatory_citations=citations,
            evidence_ids=[p.path_id for p in state.fund_flow_paths],
        )
    ]
    # C0 never invokes the LLM (deterministic baseline)
    from unittest.mock import patch

    with patch("src.agent.llm_client.is_live_llm_active", return_value=False):
        outcome = await draft_and_verify(
            box=box,
            ledger=ctx.ledger,
            alert=state.alert,
            agent_label="auditguard-c0-fixed",
            thread_id=state.thread_id,
            disposition=disposition,
            confidence=confidence,
            paths=state.fund_flow_paths,
            hypotheses=hypotheses,
            citations=citations,
            summaries=summaries,
            registry=state.evidence_registry,
            replan_count=0,
            base_rationale=rationale,
            degraded=degraded,
            use_strong_model=False,
            verify=ctx.deterministic_verifier,
        )
    draft_ms = (time.perf_counter() - t0) * 1000
    scan_ms = ctx.timings.get("scan_ms", 0.0)
    ws = outcome.worksheet
    flow_summary = compute_network_flow_summary(
        state.alert.root_account, state.transactions, state.fund_flow_paths, state.kyc_profiles
    )
    steps = [
        {"step": 1, "name": "Alert Intake & Validation", "status": "completed"},
        {"step": 2, "name": "Fixed Sequence Setup (No Agent Plan)", "status": "completed"},
        {
            "step": 3,
            "name": f"Fixed Graph & KYC Scan ({params.time_window_days}d / {params.max_hops}-hop)",
            "status": "completed",
            "duration_ms": round(scan_ms, 1),
        },
        {"step": 4, "name": "Rule-Based Synthesis", "status": "completed"},
        {
            "step": 5,
            "name": "Verification (Deterministic)",
            "status": "completed",
            "duration_ms": round(draft_ms, 1),
        },
        {"step": 6, "name": "Human Approval", "status": "waiting_approval"},
        {"step": 7, "name": "Case Commit & Reporting", "status": "pending"},
    ]
    runs = [
        {
            "agent_id": "c0_pipeline",
            "agent_name": "Fixed Deterministic Pipeline (C0)",
            "task": "Static scan without replanning or commercial registry checks",
            "status": "completed",
            "started_at": utc_now_iso(),
            "duration_ms": round(scan_ms + draft_ms, 1),
            "tool_calls": ctx.ledger.calls_used,
            "summary": rationale,
        }
    ]
    return {
        "worksheet": ws,
        "active_hypotheses": ws.hypotheses,
        "degraded_evidence": degraded,
        "flow_summary": flow_summary,
        "error": "verification_failed" if outcome.verification_failed else None,
        "is_complete": True,
        "current_node": "interrupt_required",
        "current_step": state.current_step + 1,
        "tool_calls_used": ctx.ledger.calls_used,
        "workflow_steps": steps,
        "agent_runs": runs,
    }


async def run_fixed_pipeline(
    alert: Alert,
    thread_id: Optional[str] = None,
    verify: bool = True,
    resume: bool = False,
    on_event: Optional[Callable[[str, dict[str, Any]], None]] = None,
) -> InvestigationState:
    from src.agent.graph import run_graph

    return await run_graph(
        alert=alert,
        mode=ROLE,
        thread_id=thread_id or f"thr-{uuid.uuid4().hex[:12]}",
        resume=resume,
        deterministic_verifier=verify,
        emit=on_event,
    )
