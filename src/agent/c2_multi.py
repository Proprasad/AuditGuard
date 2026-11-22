"""
AuditGuard C2 Multi-Agent Team: Supervisor + 4 Specialists with strict per-specialist RBAC.

  flow_tracer          : exclusive owner of graph-engine + transaction reads
  benign_investigator  : KYC + commercial registry + counterparty history
  regulatory_analyst   : exclusive owner of compliance-kb
  reporter_critic      : deterministic verifier + gated case-actions drafting

All specialists share one per-run BudgetLedger (enforced in GuardedToolbox before every tool call).
"""
from __future__ import annotations

import asyncio
import time
from decimal import Decimal
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict

from src.agent.c1_single import decide_disposition, widened_params
from src.agent.drafting import draft_and_verify, security_notes
from src.agent.telemetry import compute_network_flow_summary
from src.agent.tooling import GuardedToolbox, is_error
from src.config import get_policy
from src.core.adapters import flow_paths_from_result, graph_tx_payload, kyc_summaries
from src.core.policy import BudgetLedger
from src.db.database import save_checkpoint, utc_now_iso
from src.guardrails.guardrails import unwrap_untrusted_data
from src.memory.store import memory_store
from src.models import (
    Alert,
    FundFlowPath,
    GraphParams,
    Hypothesis,
    HypothesisLabel,
    InvestigationPlan,
    InvestigationState,
)


class SpecialistHandOff(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str
    target_agent: Literal["flow_tracer", "benign_investigator", "regulatory_analyst", "reporter_critic"]
    objective: str
    allowed_tool_budget: int


class SpecialistFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str
    agent_name: str
    summary: str
    tool_calls: int
    evidence_ids_added: list[str]
    recommended_replan: Optional[dict[str, Any]] = None


async def flow_tracer(alert: Alert, params: GraphParams, box: GuardedToolbox, limit: int) -> dict[str, Any]:
    ctx = await box.call("bank-records", "get_alert_context", {"alert_id": alert.alert_id})
    if is_error(ctx):
        return {"agent": "flow_tracer", "error": ctx, "root_account": alert.root_account, "network_accounts": alert.network_accounts,
                "transactions": [], "graph_result": {}, "paths": [], "multi_hop_count": 0, "evidence_ids": [],
                "finding": f"Alert context unavailable ({ctx.get('error_code') or ctx.get('error')})"}
    txs = ctx.get("transactions", [])
    root = ctx.get("root_account", alert.root_account)
    graph = await box.call("graph-engine", "find_candidate_fund_flows",
                           {"root_account": root, "transactions": graph_tx_payload(txs), **params.model_dump()})
    error = graph if is_error(graph) else None
    paths = [] if error else flow_paths_from_result(graph, limit)
    multi_hop = [p for p in paths if p.hop_count >= 2]
    return {
        "agent": "flow_tracer", "error": error, "root_account": root,
        "network_accounts": ctx.get("network_accounts", alert.network_accounts), "transactions": txs,
        "graph_result": graph, "paths": paths, "multi_hop_count": len(multi_hop),
        "evidence_ids": [t["tx_id"] for t in txs if t.get("tx_id")] + [p.path_id for p in paths],
        "finding": (f"Graph analysis unavailable ({graph.get('error_code') or graph.get('error')})" if error
                    else f"Found {len(paths)} candidate paths ({len(multi_hop)} multi-hop)"),
    }


async def benign_investigator(alert: Alert, root: str, network: list[str], box: GuardedToolbox) -> dict[str, Any]:
    profiles: list[dict[str, Any]] = []
    registry_checks: list[dict[str, Any]] = []
    evidence_ids: list[str] = []
    degraded: list[str] = []
    for acc in [root, *list(network)[:3]]:
        kyc = await box.call("bank-records", "get_kyc_profile", {"account_id": acc})
        if is_error(kyc):
            degraded.append(f"KYC unavailable for {acc}: {kyc.get('error_code') or kyc.get('error')}")
            continue
        reg = await box.call("bank-records", "check_commercial_registry", {"entity_name": unwrap_untrusted_data(str(kyc.get("entity_name", acc))), "account_id": acc})
        if is_error(reg):
            degraded.append(f"Registry unavailable for {acc}: {reg.get('error_code') or reg.get('error')}")
            reg = {}
        profiles.append(kyc)
        registry_checks.append(reg)
        evidence_ids += [e for e in (kyc.get("evidence_id"), reg.get("evidence_id")) if e]

    root_kyc = profiles[0] if profiles else {}
    root_reg = registry_checks[0] if registry_checks else {}
    root_registered = bool(root_kyc.get("is_commercially_registered") or root_reg.get("is_registered"))
    recipient_regs = registry_checks[1:]
    merchants = bool(recipient_regs) and all(bool(r.get("is_registered")) for r in recipient_regs)
    risk = str(root_kyc.get("risk_category", "")).lower()

    if not profiles:
        confidence, finding = 0.35, "KYC evidence unavailable - cannot assess benign explanation"
    elif (root_registered or (merchants and risk == "low")) and risk != "high":
        confidence, finding = 0.86, "Benign corroborated: active commercial/NGO/chit registration and low risk profile"
    elif risk == "high":
        confidence, finding = 0.14, "Suspicious indicators: high-risk KYC profile without commercial registration"
    else:
        confidence, finding = 0.35, "Unverified entity: no active commercial registration found"
    return {"agent": "benign_investigator", "kyc_profiles": profiles, "registry_checks": registry_checks,
            "benign_confidence": confidence, "root_registered": root_registered, "evidence_ids": evidence_ids,
            "degraded": degraded, "finding": finding}


async def regulatory_analyst(alert: Alert, box: GuardedToolbox) -> dict[str, Any]:
    result = await box.call("compliance-kb", "search_regulations", {
        "query": "scatter gather staggered layering fee skimming and commercial registry benign verification",
        "top_k": 5, "decompose": True})
    if is_error(result):
        return {"agent": "regulatory_analyst", "clauses": [], "citations": [], "snippets": [], "evidence_ids": [],
                "degraded": [f"Regulatory retrieval unavailable: {result.get('error_code') or result.get('error')}"],
                "finding": "Regulatory retrieval unavailable"}
    clauses = result.get("clauses", [])
    citations = [c["clause_id"] for c in clauses]
    return {"agent": "regulatory_analyst", "clauses": clauses, "citations": citations, "evidence_ids": citations, "degraded": [],
            "snippets": [f"[{c['clause_id']}] {c['title']}: {c['text'][:160]}..." for c in clauses[:5]],
            "finding": f"Retrieved {len(citations)} regulatory clauses"}


def _hypotheses(paths: list[FundFlowPath], flow: dict[str, Any], benign: dict[str, Any], citations: list[str],
                susp_conf: float, benign_conf: float) -> list[Hypothesis]:
    multi_hop = [p for p in paths if p.hop_count >= 2]
    supp = [f"Path {p.path_id}: {p.hop_count} hops, outflow INR {p.total_outflow_inr} -> consolidated INR {p.total_consolidated_inr}" for p in multi_hop[:3]]
    ids = [p.path_id for p in paths]
    return [
        Hypothesis(label=HypothesisLabel.SUSPICIOUS, explanation=flow.get("finding", ""), confidence=susp_conf,
                   supporting_evidence=supp, regulatory_citations=citations[:3], evidence_ids=ids),
        Hypothesis(label=HypothesisLabel.BENIGN, explanation=benign.get("finding", ""), confidence=benign_conf,
                   supporting_evidence=[benign["finding"]] if benign["benign_confidence"] >= 0.5 else [],
                   contradicting_evidence=[benign["finding"]] if benign["benign_confidence"] < 0.5 else []),
    ]


async def reporter_critic(
    alert: Alert, flow: dict[str, Any], benign: dict[str, Any], reg: dict[str, Any], replan_count: int,
    box: GuardedToolbox, ledger: BudgetLedger, registry: dict[str, Any],
) -> dict[str, Any]:
    paths: list[FundFlowPath] = flow["paths"]
    multi_hop = [p for p in paths if p.hop_count >= 2]
    benign_conf = benign["benign_confidence"]
    degraded = sorted({*benign["degraded"], *reg["degraded"], *([flow["finding"]] if flow.get("error") else []), *security_notes(box)})
    citations = list(reg["citations"])

    if benign_conf >= 0.7:
        susp_conf, benign_final = 0.16, benign_conf
    elif multi_hop and benign_conf < 0.5:
        susp_conf, benign_final = 0.86, benign_conf
    else:
        susp_conf, benign_final = 0.45, benign_conf
    hypotheses = _hypotheses(paths, flow, benign, citations, susp_conf, benign_final)
    disposition, confidence = decide_disposition(hypotheses, degraded)
    summaries = kyc_summaries(benign["kyc_profiles"], limit=4)
    rationale = (
        f"C2 Multi-Agent Team: Flow Tracer reconstructed {len(paths)} path(s) ({len(multi_hop)} multi-hop, replans={replan_count}). "
        f"Benign Investigator confidence: {benign_conf:.0%}. Citations: {', '.join(citations[:3]) or 'none retrieved'}."
    )
    if degraded:
        rationale += " Degraded evidence: " + "; ".join(degraded)
    outcome = await draft_and_verify(
        box=box, ledger=ledger, alert=alert, agent_label="auditguard-c2", thread_id=box.thread_id, disposition=disposition,
        confidence=confidence, paths=paths, hypotheses=hypotheses, citations=citations, summaries=summaries,
        registry=registry, replan_count=replan_count, base_rationale=rationale, degraded=degraded, use_strong_model=True,
    )
    return {"agent": "reporter_critic", "worksheet": outcome.worksheet, "verification_failed": outcome.verification_failed,
            "degraded": degraded}


def _evidence_registry(flow: dict[str, Any], benign: dict[str, Any], reg: dict[str, Any]) -> dict[str, Any]:
    registry: dict[str, Any] = {t["tx_id"]: t for t in flow["transactions"] if t.get("tx_id")}
    registry.update({p.path_id: p.model_dump(mode="json") for p in flow["paths"]})
    calc_id = flow["graph_result"].get("calc_id") if flow["graph_result"] else None
    if calc_id:
        registry[calc_id] = flow["graph_result"].get("graph_stats", {})
    registry.update({k["evidence_id"]: k for k in benign["kyc_profiles"] if k.get("evidence_id")})
    registry.update({r["evidence_id"]: r for r in benign["registry_checks"] if r.get("evidence_id")})
    registry.update({c["clause_id"]: c for c in reg["clauses"] if c.get("clause_id")})
    return registry


def _agent_run(agent_id: str, name: str, task: str, ms: float, calls: int, summary: str) -> dict[str, Any]:
    return {"agent_id": agent_id, "agent_name": name, "task": task, "status": "completed", "started_at": utc_now_iso(),
            "duration_ms": ms, "tool_calls": calls, "summary": summary}


async def run_multi_agent(
    alert: Alert, thread_id: Optional[str] = None, reflexion_enabled: bool = False, memory_enabled: bool = True,
) -> InvestigationState:
    """C2 Supervisor coordinating 4 specialists under one shared BudgetLedger with bounded replanning."""
    policy = get_policy()
    ledger = policy.new_ledger()
    state = InvestigationState(thread_id=thread_id or f"thr-c2-{alert.alert_id.lower()}", alert=alert)
    params = GraphParams.policy_default()
    if reflexion_enabled and memory_enabled:
        lessons = memory_store.retrieve_top_lessons("scatter gather staggered", top_k=3)
        state.retrieved_lessons = [les.actionable_rule for les in lessons]
        if any("14-30" in les.actionable_rule for les in lessons):
            params = widened_params(policy, params)

    state.plan = InvestigationPlan(steps=[
        "1. [Supervisor -> Flow Tracer] Initial bounded scan",
        "2. [Supervisor -> Benign Investigator] Verify KYC + commercial registry",
        "3. [Supervisor -> Regulatory Analyst] Retrieve PMLA/RBI/FIU-IND clauses",
        "4. [Supervisor Replan] Expand bounds if consolidation leg missing",
        "5. [Supervisor -> Reporter & Critic] Deterministic verification & SHA-256 worksheet",
    ], graph_params=params)

    tid = state.thread_id
    tracer, investigator = GuardedToolbox("flow_tracer", ledger, tid), GuardedToolbox("benign_investigator", ledger, tid)
    analyst, reporter = GuardedToolbox("regulatory_analyst", ledger, tid), GuardedToolbox("reporter_critic", ledger, tid)

    t0 = time.perf_counter()
    flow = await flow_tracer(alert, params, tracer, limit=5)
    flow_ms = round((time.perf_counter() - t0) * 1000, 1)

    t1 = time.perf_counter()
    benign, reg = await asyncio.gather(
        benign_investigator(alert, flow["root_account"], flow["network_accounts"], investigator),
        regulatory_analyst(alert, analyst),
    )
    parallel_ms = round((time.perf_counter() - t1) * 1000, 1)

    if (flow["multi_hop_count"] == 0 and not flow.get("error") and not benign["root_registered"]
            and ledger.calls_used + 2 <= policy.budgets.max_tool_calls and ledger.try_replan().allowed):
        gb = policy.graph_bounds
        wide = GraphParams(time_window_days=gb.time_window_days.max, max_hops=gb.max_hops.max,
                           amount_tolerance=gb.amount_tolerance.max, min_intermediaries=params.min_intermediaries)
        t2 = time.perf_counter()
        flow = await flow_tracer(alert, wide, tracer, limit=5)
        flow_ms = round(flow_ms + (time.perf_counter() - t2) * 1000, 1)
        state.replan_count = 1
        state.plan = InvestigationPlan(steps=state.plan.steps, graph_params=wide, replan_count=1,
                                       replan_reason="Initial bounded scan found 0 consolidation legs for an unregistered seed account")

    registry = _evidence_registry(flow, benign, reg)
    t3 = time.perf_counter()
    report = await reporter_critic(alert, flow, benign, reg, state.replan_count, reporter, ledger, registry)
    critic_ms = round((time.perf_counter() - t3) * 1000, 1)

    state.transactions, state.fund_flow_paths = flow["transactions"], flow["paths"]
    state.kyc_profiles, state.regulatory_snippets = benign["kyc_profiles"], reg["snippets"]
    state.degraded_evidence = report["degraded"]
    state.error = "verification_failed" if report["verification_failed"] else None
    state.evidence_registry = registry
    state.flow_summary = compute_network_flow_summary(flow["root_account"], flow["transactions"], flow["paths"], benign["kyc_profiles"])
    state.worksheet = report["worksheet"]
    state.active_hypotheses = state.worksheet.hypotheses
    state.tool_calls_used = ledger.calls_used
    state.total_tokens_used = ledger.tokens_used
    state.estimated_cost_usd = ledger.cost_usd
    state.budget_remaining_usd = max(policy.budgets.max_cost_usd_per_case - ledger.cost_usd, Decimal("0"))
    state.workflow_steps = [
        {"step": 1, "name": "Alert Intake & Validation", "status": "completed"},
        {"step": 2, "name": "Investigation Planning", "status": "completed"},
        {"step": 3, "name": "Parallel Investigation", "status": "completed", "duration_ms": round(flow_ms + parallel_ms, 1)},
        {"step": 4, "name": "Evidence Synthesis", "status": "completed"},
        {"step": 5, "name": "Verification (Deterministic)", "status": "completed", "duration_ms": critic_ms},
        {"step": 6, "name": "Human Approval", "status": "waiting_approval"},
        {"step": 7, "name": "Case Commit & Reporting", "status": "pending"},
    ]
    tw, mh = state.plan.graph_params.time_window_days, state.plan.graph_params.max_hops
    state.agent_runs = [
        _agent_run("flow_tracer", "Flow Tracing Agent", f"Graph traversal ({tw}d, {mh} hops) & Decimal conservation", flow_ms, tracer.calls, flow["finding"]),
        _agent_run("benign_investigator", "Benign Context Agent", "Multi-bank KYC verification & GST/MCA/80G/Chit registry checks", parallel_ms, investigator.calls, benign["finding"]),
        _agent_run("regulatory_analyst", "Regulatory Research Agent", "Hybrid RAG (BM25 + Vector + RRF + Reranker) over Indian AML corpus", parallel_ms, analyst.calls, reg["finding"]),
        _agent_run("reporter_critic", "Reporting & Critique Agent", "Hypothesis reconciliation, deterministic verifier & SHA-256 worksheet draft", critic_ms, reporter.calls,
                   f"Drafted {state.worksheet.worksheet_id} ({state.worksheet.recommended_disposition.value})"),
    ]
    state.current_node = "interrupt_required"
    state.is_complete = True
    save_checkpoint(
        thread_id=state.thread_id, alert_id=alert.alert_id, mode="c2_multi", current_node="interrupt_required",
        status="interrupt_required", state_dict=state.model_dump(mode="json"),
        worksheet_id=state.worksheet.worksheet_id, payload_hash=state.worksheet.payload_hash,
    )
    return state
