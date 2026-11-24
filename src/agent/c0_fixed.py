"""
AuditGuard C0 - Fair Fixed Deterministic Workflow Baseline (`src/agent/c0_fixed.py`).

Topology: `START -> gather_evidence -> draft -> human_gate(interrupt) -> commit_disposition -> END`
Fair v3 baseline (`docs/AGENT_GUIDE.md` §4 Phase 2.5):
  * Wider fixed scan window (`time_window_days=14`, `max_hops=4`)
  * KYC + commercial registry checks (`get_kyc_profile` + `check_commercial_registry`) for `root`
    and up to `3` counterparties
  * Three-way fixed decision rule capable of outputting `escalate_str`, `close_benign`, and `request_info`
  * Zero replanning, zero LLM calls (`tokens_used=0`, `cost_usd=0`), identical `GuardedToolbox` & verifier
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from decimal import Decimal
from typing import Any, Optional

from src.agent.drafting import draft_and_verify, security_notes
from src.agent.gathering import build_case_regulatory_queries
from src.agent.nodes import RunContext
from src.agent.planning import sync_budget, tool_error_notes
from src.agent.telemetry import compute_network_flow_summary
from src.agent.tooling import GuardedToolbox, is_error
from src.core.adapters import flow_paths_from_result, graph_tx_payload, is_registered, kyc_summaries
from src.core.canonical import to_confidence
from src.db.database import utc_now_iso
from src.guardrails.guardrails import unwrap_untrusted_data
from src.models import (
    Alert,
    DispositionDecision,
    FundFlowPath,
    GraphParams,
    Hypothesis,
    HypothesisLabel,
    InvestigationState,
)

ROLE = "c0_fixed"
C0_FIXED_WINDOW_DAYS = 14
C0_FIXED_MAX_HOPS = 4
C0_MAX_COUNTERPARTIES = 3


def _err(result: dict[str, Any]) -> str:
    return str(result.get("error_code") or result.get("error"))


def _c0_graph_params(ctx: RunContext) -> GraphParams:
    gb = ctx.policy.graph_bounds
    return GraphParams(
        time_window_days=min(gb.time_window_days.max, max(gb.time_window_days.min, C0_FIXED_WINDOW_DAYS)),
        max_hops=min(gb.max_hops.max, max(gb.max_hops.min, C0_FIXED_MAX_HOPS)),
        amount_tolerance=gb.amount_tolerance.default,
        min_intermediaries=gb.min_intermediaries.default,
    )


def _select_c0_accounts(
    root: str, txs: list[dict[str, Any]], paths: list[FundFlowPath], network: list[str]
) -> list[str]:
    terminals = [p.nodes[-1] for p in paths if len(p.nodes) >= 2 and p.nodes[-1] != root]
    outbound = [
        str(t["receiver_account"])
        for t in txs
        if t.get("sender_account") == root and t.get("receiver_account") and t["receiver_account"] != root
    ]
    counterparties = list(dict.fromkeys([*terminals, *outbound, *(a for a in network if a != root)]))
    return [root, *counterparties[:C0_MAX_COUNTERPARTIES]]


async def _profile_c0_accounts(
    ctx: RunContext,
    box: GuardedToolbox,
    targets: list[str],
    registry: dict[str, Any],
    degraded: list[str],
) -> list[dict[str, Any]]:
    profiles: list[dict[str, Any]] = []
    max_calls = ctx.policy.budgets.max_tool_calls
    for acc in targets:
        # Reserve 2 slots: 1 for `search_regulations` + 1 exit slot for `draft_disposition_report`
        if ctx.ledger.calls_used + 2 > max_calls - 1:
            break
        kyc = await box.call("bank-records", "get_kyc_profile", {"account_id": acc})
        if is_error(kyc):
            degraded.append(f"KYC unavailable for {acc}: {_err(kyc)}")
            continue
        registry[str(kyc.get("evidence_id") or f"KYC-{acc}")] = kyc
        if ctx.ledger.calls_used + 2 <= max_calls - 1:
            reg = await box.call(
                "bank-records",
                "check_commercial_registry",
                {"entity_name": unwrap_untrusted_data(str(kyc.get("entity_name", acc))), "account_id": acc},
            )
            if is_error(reg):
                degraded.append(f"Commercial registry unavailable for {acc}: {_err(reg)}")
            elif reg.get("evidence_id"):
                registry[str(reg["evidence_id"])] = reg
                kyc["registry_check"] = reg
        profiles.append(kyc)
    return profiles


async def scan_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    t0 = time.perf_counter()
    box = ctx.box("primary")
    params = _c0_graph_params(ctx)
    registry: dict[str, Any] = dict(state.evidence_registry)
    degraded: list[str] = list(state.degraded_evidence)

    alert_ctx = await box.call("bank-records", "get_alert_context", {"alert_id": state.alert.alert_id})
    txs = [] if is_error(alert_ctx) else alert_ctx.get("transactions", [])
    root = state.alert.root_account if is_error(alert_ctx) else alert_ctx.get("root_account", state.alert.root_account)
    network = (
        list(state.alert.network_accounts)
        if is_error(alert_ctx)
        else list(alert_ctx.get("network_accounts", state.alert.network_accounts))
    )
    if is_error(alert_ctx):
        degraded.append(f"Alert context unavailable: {_err(alert_ctx)}")
    registry.update({t["tx_id"]: t for t in txs if t.get("tx_id")})

    graph = await box.call(
        "graph-engine",
        "find_candidate_fund_flows",
        {"root_account": root, "transactions": graph_tx_payload(txs), **params.model_dump()},
    )
    paths: list[FundFlowPath] = []
    calc_log = list(state.calc_log)
    if is_error(graph):
        degraded.append(f"Graph analysis unavailable: {_err(graph)}")
    else:
        paths = flow_paths_from_result(graph, limit=10)
        registry[graph["calc_id"]] = graph.get("graph_stats", {})
        registry.update({p.path_id: p.model_dump(mode="json") for p in paths})
        multi = [p for p in paths if p.hop_count >= 2]
        if multi and ctx.ledger.calls_used + 2 <= ctx.policy.budgets.max_tool_calls - 1:
            cons = await box.call(
                "graph-engine",
                "compute_flow_conservation",
                {"paths": [p.model_dump(mode="json") for p in multi[:10]], "amount_tolerance": str(params.amount_tolerance)},
            )
            if not is_error(cons):
                cons_key = f"{graph['calc_id']}-CONS"
                registry[cons_key] = cons
                calc_log.append({"calc_id": cons_key, **cons})

    targets = _select_c0_accounts(root, txs, paths, network)
    profiles = await _profile_c0_accounts(ctx, box, targets, registry, degraded)

    clauses: list[dict[str, Any]] = []
    if ctx.ledger.calls_used + 1 <= ctx.policy.budgets.max_tool_calls - 1:
        case_queries = build_case_regulatory_queries(state.alert, paths, profiles, degraded)
        reg = await box.call(
            "compliance-kb",
            "search_regulations",
            {"query": " ; ".join(case_queries[:2]), "top_k": 3, "decompose": True},
        )
        if is_error(reg):
            degraded.append(f"Regulatory retrieval unavailable: {_err(reg)}")
        else:
            clauses = [c for c in reg.get("clauses", []) if isinstance(c, dict) and c.get("clause_id")]
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
        "calc_log": calc_log,
        "degraded_evidence": degraded,
        "current_node": "gather_evidence",
        "current_step": state.current_step + 1,
        "tool_calls_used": ctx.ledger.calls_used,
        "total_tokens_used": 0,
        "estimated_cost_usd": Decimal("0"),
        "budget_remaining_usd": cap,
    }


def _c0_three_way_decision(
    state: InvestigationState, ctx: RunContext, params: GraphParams, degraded: list[str]
) -> tuple[DispositionDecision, float, str]:
    window = f"{params.time_window_days}d/{params.max_hops}-hop"
    critical_fail = (not state.transactions and bool(degraded)) or any(
        d.startswith(("Alert context unavailable:", "Graph analysis unavailable:", "Prompt-injection"))
        for d in degraded
    )
    if critical_fail:
        return (
            DispositionDecision.REQUEST_INFO,
            float(ctx.policy.scoring.c0_request_info_confidence),
            f"C0 Fair Baseline: incomplete or degraded evidence in fixed {window} scan.",
        )

    multi_hop = [p for p in state.fund_flow_paths if p.hop_count >= 2]
    root_kyc = state.kyc_profiles[0] if state.kyc_profiles else {}
    counterparties = state.kyc_profiles[1:]
    root_reg = is_registered(root_kyc)
    root_risk = str(root_kyc.get("risk_category", "")).lower()
    cp_all_low_reg = bool(counterparties) and all(
        is_registered(k) and str(k.get("risk_category", "")).lower() == "low" for k in counterparties
    )

    if multi_hop:
        if not degraded and root_reg and root_risk == "low" and cp_all_low_reg and not any(
            p.is_suspicious for p in multi_hop
        ):
            return (
                DispositionDecision.CLOSE_BENIGN,
                0.76,
                f"C0 Fair Baseline: {len(multi_hop)} path(s) in {window} scan corroborated by active registrations.",
            )
        return (
            DispositionDecision.ESCALATE_STR,
            float(ctx.policy.scoring.c0_escalate_confidence),
            f"C0 Fair Baseline: {len(multi_hop)} multi-hop path(s) detected in fixed {window} scan.",
        )

    if not degraded and state.kyc_profiles and root_reg and root_risk in ("low", "medium"):
        return (
            DispositionDecision.CLOSE_BENIGN,
            0.78,
            f"C0 Fair Baseline: 0 multi-hop paths in fixed {window} scan and active commercial registration verified.",
        )
    return (
        DispositionDecision.REQUEST_INFO,
        float(ctx.policy.scoring.c0_request_info_confidence),
        f"C0 Fair Baseline: 0 multi-hop paths in fixed {window} scan without verified commercial registration.",
    )


def _c0_telemetry(
    params: GraphParams, scan_ms: float, draft_ms: float, calls_used: int, rationale: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    steps = [
        {"step": 1, "name": "Alert Intake & Validation", "status": "completed"},
        {"step": 2, "name": "Fixed Sequence Setup (No Agent Plan)", "status": "completed"},
        {
            "step": 3,
            "name": f"Fixed Graph, KYC & Registry Scan ({params.time_window_days}d / {params.max_hops}-hop)",
            "status": "completed",
            "duration_ms": round(scan_ms, 1),
        },
        {"step": 4, "name": "Fixed 3-Way Rule Synthesis", "status": "completed"},
        {"step": 5, "name": "Verification (Deterministic)", "status": "completed", "duration_ms": round(draft_ms, 1)},
        {"step": 6, "name": "Human Approval", "status": "waiting_approval"},
        {"step": 7, "name": "Case Commit & Reporting", "status": "pending"},
    ]
    runs = [
        {
            "agent_id": "c0_pipeline",
            "agent_name": "Fair Fixed Deterministic Baseline (C0)",
            "task": "Fixed 14d/4-hop scan + root/counterparty KYC & registry + 3-way rule (no replanning, no LLM)",
            "status": "completed",
            "started_at": utc_now_iso(),
            "duration_ms": round(scan_ms + draft_ms, 1),
            "tool_calls": calls_used,
            "summary": rationale,
        }
    ]
    return steps, runs


def _c0_hypotheses(
    state: InvestigationState,
    disposition: DispositionDecision,
    confidence: float,
    citations: list[str],
    ev_ids: list[str],
) -> list[Hypothesis]:
    susp_conf = confidence if disposition == DispositionDecision.ESCALATE_STR else round(1.0 - confidence, 4)
    benign_conf = confidence if disposition == DispositionDecision.CLOSE_BENIGN else round(1.0 - susp_conf, 4)
    return [
        Hypothesis(
            label=HypothesisLabel.SUSPICIOUS,
            explanation="Fixed 14d/4-hop multi-hop scatter-gather topology assessment.",
            confidence=to_confidence(susp_conf),
            regulatory_citations=citations,
            evidence_ids=ev_ids,
        ),
        Hypothesis(
            label=HypothesisLabel.BENIGN,
            explanation="Fixed KYC and commercial registry corroboration check across root and counterparties.",
            confidence=to_confidence(benign_conf),
            regulatory_citations=citations,
            evidence_ids=ev_ids,
        ),
    ]


async def draft_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    t0 = time.perf_counter()
    box = ctx.box("primary")
    params = _c0_graph_params(ctx)
    degraded = sorted({*state.degraded_evidence, *security_notes(box), *tool_error_notes(ctx)})
    citations = [c["clause_id"] for c in state.regulatory_clauses if c.get("clause_id")]
    disposition, confidence, rationale = _c0_three_way_decision(state, ctx, params, degraded)
    if degraded:
        rationale += " Degraded evidence: " + "; ".join(degraded)
    rationale += " Missing evidence: Out-of-network beneficiary bank statements."

    summaries = kyc_summaries(state.kyc_profiles, limit=4)
    ev_ids = [
        eid
        for eid in [
            *(p.path_id for p in state.fund_flow_paths),
            *(str(k.get("evidence_id", "")) for k in state.kyc_profiles),
            *(str(t.get("tx_id", "")) for t in state.transactions[:2]),
        ]
        if eid and eid in state.evidence_registry
    ]
    refs = [*ev_ids[:2], *citations[:2]]
    if refs:
        rationale += f" [refs: {', '.join(refs)}]"
    hypotheses = _c0_hypotheses(state, disposition, confidence, citations, ev_ids)
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
        calc_log=state.calc_log,
        replan_count=0,
        base_rationale=rationale,
        degraded=degraded,
        use_strong_model=False,
        verify=ctx.deterministic_verifier,
        allow_llm=False,
    )
    draft_ms = (time.perf_counter() - t0) * 1000
    scan_ms = ctx.timings.get("scan_ms", 0.0)
    ws = outcome.worksheet
    flow_summary = compute_network_flow_summary(
        state.alert.root_account, state.transactions, state.fund_flow_paths, state.kyc_profiles
    )
    steps, runs = _c0_telemetry(params, scan_ms, draft_ms, ctx.ledger.calls_used, rationale)
    return {
        "worksheet": ws,
        "active_hypotheses": ws.hypotheses,
        "degraded_evidence": degraded,
        "flow_summary": flow_summary,
        "error": "verification_failed" if outcome.verification_failed else None,
        "is_complete": True,
        "current_node": "interrupt_required",
        "current_step": state.current_step + 1,
        "workflow_steps": steps,
        "agent_runs": runs,
        **sync_budget(ctx),
    }


async def run_fixed_pipeline(
    alert: Alert,
    thread_id: Optional[str] = None,
    verify: bool = True,
    budget_overrides: Optional[dict[str, Any]] = None,
    resume: bool = False,
    stop_after_node: Optional[str] = None,
    on_event: Optional[Callable[[str, dict[str, Any]], None]] = None,
) -> InvestigationState:
    from src.agent.graph import run_graph

    return await run_graph(
        alert=alert,
        mode=ROLE,
        thread_id=thread_id or f"thr-{uuid.uuid4().hex[:12]}",
        resume=resume,
        stop_after_node=stop_after_node,
        deterministic_verifier=verify,
        allow_llm=False,
        llm_mode="offline",
        budget_overrides=budget_overrides,
        emit=on_event,
    )
