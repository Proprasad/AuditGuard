"""
AuditGuard C2 — Multi-Agent Team
Architecture: Supervisor + 4 Specialist Agents with typed hand-offs and strict RBAC
  1. flow_tracer: Exclusive owner of graph-engine + transaction reads
  2. benign_investigator: KYC + commercial registry + counterparty history
  3. regulatory_analyst: Exclusive owner of compliance-kb
  4. reporter_critic: Deterministic verifier + gated case-actions drafting
"""
from __future__ import annotations

import asyncio
from typing import Any, Literal, Optional
from pydantic import BaseModel

from src.db.database import save_checkpoint, utc_now_iso
from src.guardrails.hooks import post_tool_hook, pre_tool_hook
from src.guardrails.verifier import verify_worksheet
from src.mcp_servers.client import call_mcp_tool
from src.memory.store import memory_store
from src.models import (
    Alert,
    DispositionDecision,
    DispositionWorksheet,
    FundFlowPath,
    Hypothesis,
    HypothesisLabel,
    InvestigationPlan,
    InvestigationState,
)


class SpecialistHandOff(BaseModel):
    task_id: str
    target_agent: Literal["flow_tracer", "benign_investigator", "regulatory_analyst", "reporter_critic"]
    objective: str
    allowed_tool_budget: int


class SpecialistFinding(BaseModel):
    task_id: str
    agent_name: str
    summary: str
    tool_calls: int
    evidence_ids_added: list[str]
    recommended_replan: Optional[dict[str, Any]] = None


async def _specialist_call(agent_role: str, server: str, tool: str, params: dict[str, Any]) -> tuple[dict[str, Any], int]:
    decision = pre_tool_hook(agent_role=agent_role, tool_name=tool, params=params)
    if not decision.allowed:
        return {"status": "error", "error_code": decision.error_code, "message": decision.message}, 0
    raw = await call_mcp_tool(server, tool, params)
    return post_tool_hook(tool, raw), 1


async def flow_tracer(alert: Alert, graph_params: dict[str, Any]) -> dict[str, Any]:
    calls = 0
    evidence_ids: list[str] = []

    alert_ctx, d1 = await _specialist_call("flow_tracer", "bank-records", "get_alert_context", {"alert_id": alert.alert_id})
    calls += d1
    transactions_raw = alert_ctx.get("transactions", [])
    root_account = alert_ctx.get("root_account", alert.root_account)
    for tx in transactions_raw:
        if tx.get("tx_id"):
            evidence_ids.append(tx["tx_id"])

    graph_result, d2 = await _specialist_call(
        "flow_tracer",
        "graph-engine",
        "find_candidate_fund_flows",
        {
            "root_account": root_account,
            "transactions": [
                {
                    "tx_id": tx.get("tx_id", f"TX{i}"),
                    "sender": tx.get("sender_account", tx.get("sender", root_account)),
                    "receiver": tx.get("receiver_account", tx.get("receiver", "")),
                    "amount_inr": tx.get("amount_inr", 0),
                    "timestamp": tx.get("timestamp", utc_now_iso()),
                    "memo": tx.get("memo"),
                }
                for i, tx in enumerate(transactions_raw)
            ],
            **graph_params,
        },
    )
    calls += d2

    paths = [
        FundFlowPath(
            path_id=p.get("path_id", ""),
            nodes=p.get("nodes", []),
            edge_tx_ids=p.get("edge_tx_ids", []),
            total_amount=p.get("total_amount", 0.0),
            total_outflow_inr=p.get("total_outflow_inr", "0.00"),
            total_consolidated_inr=p.get("total_consolidated_inr", "0.00"),
            net_difference_inr=p.get("net_difference_inr", "0.00"),
            retention_pct=p.get("retention_pct", "0.00"),
            hop_count=p.get("hop_count", 0),
            time_span_days=p.get("time_span_days", 0.0),
            amount_leaked_pct=p.get("amount_leaked_pct", 0.0),
        )
        for p in graph_result.get("paths", [])[:5]
    ]
    for p in paths:
        if p.path_id:
            evidence_ids.append(p.path_id)

    multi_hop = [p for p in paths if p.hop_count >= 2]
    return {
        "agent": "flow_tracer",
        "root_account": root_account,
        "network_accounts": alert_ctx.get("network_accounts", alert.network_accounts),
        "paths": paths,
        "multi_hop_count": len(multi_hop),
        "tool_calls": calls,
        "evidence_ids": evidence_ids,
        "finding": f"Found {len(paths)} candidate paths ({len(multi_hop)} multi-hop)",
    }


async def benign_investigator(alert: Alert, root_account: str, network_accounts: list[str]) -> dict[str, Any]:
    calls = 0
    kyc_profiles: list[dict[str, Any]] = []
    registry_checks: list[dict[str, Any]] = []
    evidence_ids: list[str] = []

    for acc in [root_account, *list(network_accounts)[:3]]:
        kyc, d1 = await _specialist_call("benign_investigator", "bank-records", "get_kyc_profile", {"account_id": acc})
        calls += d1
        kyc_profiles.append(kyc)
        if kyc.get("evidence_id"):
            evidence_ids.append(kyc["evidence_id"])

        reg, d2 = await _specialist_call(
            "benign_investigator",
            "bank-records",
            "check_commercial_registry",
            {"entity_name": kyc.get("entity_name", acc), "account_id": acc},
        )
        calls += d2
        registry_checks.append(reg)
        if reg.get("evidence_id"):
            evidence_ids.append(reg["evidence_id"])

    root_kyc = kyc_profiles[0] if kyc_profiles else {}
    root_reg = registry_checks[0] if registry_checks else {}
    root_registered = bool(root_kyc.get("is_commercially_registered") or root_reg.get("is_registered"))
    recipient_regs = registry_checks[1:]
    verified_merchants = bool(recipient_regs) and all(bool(r.get("is_registered")) for r in recipient_regs)

    root_risk = str(root_kyc.get("risk_category", "")).lower()
    high_risk = root_risk == "high"
    low_risk = root_risk == "low"

    if (root_registered or (verified_merchants and low_risk)) and not high_risk:
        benign_confidence = 0.86
        finding = "Benign corroborated: active commercial/NGO/chit registration and low risk profile"
    elif high_risk:
        benign_confidence = 0.14
        finding = "Suspicious indicators: high-risk KYC profile without commercial registration"
    else:
        benign_confidence = 0.35
        finding = "Unverified entity: no active commercial registration found"

    return {
        "agent": "benign_investigator",
        "kyc_profiles": kyc_profiles,
        "registry_checks": registry_checks,
        "benign_confidence": benign_confidence,
        "root_registered": root_registered,
        "tool_calls": calls,
        "evidence_ids": evidence_ids,
        "finding": finding,
    }


async def regulatory_analyst(alert: Alert) -> dict[str, Any]:
    result, calls = await _specialist_call(
        "regulatory_analyst",
        "compliance-kb",
        "search_regulations",
        {
            "query": "scatter gather staggered layering fee skimming and commercial registry benign verification",
            "top_k": 5,
            "decompose": True,
        },
    )
    clauses = result.get("clauses", [])
    citations = [c["clause_id"] for c in clauses] or ["REG-FIU-RF-014"]
    snippets = [f"[{c['clause_id']}] {c['title']}: {c['text'][:160]}..." for c in clauses[:5]]
    return {
        "agent": "regulatory_analyst",
        "citations": citations,
        "snippets": snippets,
        "tool_calls": calls,
        "evidence_ids": citations,
        "finding": f"Retrieved {len(citations)} regulatory clauses",
    }


async def reporter_critic(
    alert: Alert,
    flow_result: dict[str, Any],
    benign_result: dict[str, Any],
    reg_result: dict[str, Any],
    replan_count: int,
    total_calls_so_far: int,
) -> dict[str, Any]:
    paths = flow_result.get("paths", [])
    multi_hop = [p for p in paths if p.hop_count >= 2]
    benign_conf = benign_result.get("benign_confidence", 0.35)
    citations = reg_result.get("citations", ["REG-FIU-RF-014"])

    if benign_conf >= 0.7:
        disposition = DispositionDecision.CLOSE_BENIGN
        susp_conf, benign_final = 0.16, benign_conf
    elif multi_hop and benign_conf < 0.5:
        disposition = DispositionDecision.ESCALATE_STR
        susp_conf, benign_final = 0.86, benign_conf
    else:
        disposition = DispositionDecision.REQUEST_INFO
        susp_conf, benign_final = 0.45, benign_conf

    hypotheses = [
        Hypothesis(
            label=HypothesisLabel.SUSPICIOUS,
            explanation=flow_result.get("finding", ""),
            confidence=susp_conf,
            supporting_evidence=[
                f"Path {p.path_id}: {p.hop_count} hops, outflow INR {p.total_outflow_inr} -> consolidated INR {p.total_consolidated_inr}"
                for p in multi_hop[:3]
            ],
            regulatory_citations=citations[:3],
        ),
        Hypothesis(
            label=HypothesisLabel.BENIGN,
            explanation=benign_result.get("finding", ""),
            confidence=benign_final,
            supporting_evidence=[benign_result.get("finding", "")] if benign_conf >= 0.5 else [],
            contradicting_evidence=[benign_result.get("finding", "")] if benign_conf < 0.5 else [],
        ),
    ]

    kyc_summaries = [
        f"{k.get('account_id', '')}: {k.get('entity_type', '')}, risk={k.get('risk_category', '')}, registered={bool(k.get('is_commercially_registered'))}"
        for k in benign_result.get("kyc_profiles", [])[:4]
    ]
    rationale = (
        f"C2 Multi-Agent Team: Flow Tracer reconstructed {len(paths)} path(s) ({len(multi_hop)} multi-hop, replans={replan_count}). "
        f"Benign Investigator confidence: {benign_conf:.0%}. Citations: {', '.join(citations[:3])}."
    )

    draft_payload = {
        "alert_id": alert.alert_id,
        "recommended_disposition": disposition.value,
        "recommendation_rationale": rationale,
        "confidence_score": max(susp_conf, benign_final),
        "candidate_paths": [p.model_dump() for p in paths[:3]],
        "regulatory_citations": citations,
        "kyc_summaries": kyc_summaries,
    }
    vr = verify_worksheet(draft_payload)
    if not vr.passed:
        draft_payload["recommendation_rationale"] = f"[VERIFIER WARNING: {vr.errors}] " + rationale

    draft_res, d_call = await _specialist_call("reporter_critic", "case-actions", "draft_disposition_report", draft_payload)

    worksheet = DispositionWorksheet(
        worksheet_id=draft_res.get("worksheet_id", f"DWS-{alert.alert_id[-8:].upper()}"),
        alert_id=alert.alert_id,
        investigator_agent="auditguard-c2",
        candidate_paths=paths[:3],
        hypotheses=hypotheses,
        regulatory_citations=citations,
        kyc_summaries=kyc_summaries,
        recommended_disposition=disposition,
        recommendation_rationale=draft_payload["recommendation_rationale"],
        confidence_score=max(susp_conf, benign_final),
    )

    return {"agent": "reporter_critic", "worksheet": worksheet, "tool_calls": d_call}


async def run_multi_agent(
    alert: Alert,
    thread_id: Optional[str] = None,
    reflexion_enabled: bool = False,
    memory_enabled: bool = True,
) -> InvestigationState:
    """C2 Supervisor coordinating 4 specialists with shared 15-call budget and bounded replanning."""
    state = InvestigationState(thread_id=thread_id or f"thr-c2-{alert.alert_id.lower()}", alert=alert)
    params = {"time_window_days": 7, "max_hops": 3, "amount_tolerance": 0.10}

    if reflexion_enabled and memory_enabled:
        lessons = memory_store.retrieve_top_lessons("scatter gather staggered", top_k=3)
        state.retrieved_lessons = [l.actionable_rule for l in lessons]
        if any("14-30" in l.actionable_rule for l in lessons):
            params = {"time_window_days": 15, "max_hops": 4, "amount_tolerance": 0.15}

    state.plan = InvestigationPlan(
        steps=[
            "1. [Supervisor -> Flow Tracer] Initial bounded scan (7d, 3 hops, 10% tolerance)",
            "2. [Supervisor -> Benign Investigator] Verify KYC + commercial registry",
            "3. [Supervisor -> Regulatory Analyst] Retrieve PMLA/RBI/FIU-IND clauses",
            "4. [Supervisor Replan] Expand bounds if consolidation leg missing",
            "5. [Supervisor -> Reporter & Critic] Deterministic verification & SHA-256 worksheet",
        ],
        graph_params=params,
    )

    flow_result = await flow_tracer(alert, params)
    benign_result, reg_result = await asyncio.gather(
        benign_investigator(alert, flow_result["root_account"], flow_result["network_accounts"]),
        regulatory_analyst(alert),
    )
    total_calls = flow_result["tool_calls"] + benign_result["tool_calls"] + reg_result["tool_calls"]

    # Bounded replanning within global 15-call cap
    if flow_result["multi_hop_count"] == 0 and not benign_result["root_registered"] and total_calls + 2 <= 15:
        replan_params = {"time_window_days": 30, "max_hops": 5, "amount_tolerance": 0.20}
        flow_result_2 = await flow_tracer(alert, replan_params)
        total_calls += flow_result_2["tool_calls"]
        flow_result = flow_result_2
        state.replan_count = 1
        state.plan.graph_params = replan_params
        state.plan.replan_count = 1
        state.plan.replan_reason = "Expanded to 30d/5hop after initial 7d scan found 0 consolidation legs"

    report_result = await reporter_critic(alert, flow_result, benign_result, reg_result, state.replan_count, total_calls)
    total_calls += report_result["tool_calls"]

    state.fund_flow_paths = flow_result.get("paths", [])
    state.kyc_profiles = benign_result.get("kyc_profiles", [])
    state.regulatory_snippets = reg_result.get("snippets", [])
    state.worksheet = report_result["worksheet"]
    state.active_hypotheses = state.worksheet.hypotheses
    state.tool_calls_used = total_calls
    state.current_node = "interrupt_required"
    state.is_complete = True

    save_checkpoint(
        thread_id=state.thread_id,
        alert_id=state.alert.alert_id,
        mode="c2_multi",
        current_node="interrupt_required",
        status="interrupt_required",
        state_dict=state.model_dump(),
        worksheet_id=state.worksheet.worksheet_id,
        payload_hash=state.worksheet.payload_hash,
    )
    return state
