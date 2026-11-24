"""
Hypothesis scoring, closed-loop critique/replan, and fail-closed worksheet drafting nodes,
plus public re-exports of planning, gathering, and C2 specialist nodes.
"""

from __future__ import annotations

from decimal import Decimal
import time
from typing import Any, Literal, Optional

from src.agent import reasoning
from src.agent.drafting import draft_and_verify
from src.agent.gathering import gather_evidence_node
from src.agent.llm_client import LlmCallMeta
from src.agent.planning import (
    TOOL_CAPABILITIES,
    RunContext,
    all_security_notes,
    handoff_for,
    plan_node,
    sync_budget,
    tool_error_notes,
    upsert_finding,
    widened_params,
)
from src.agent.specialists import flow_tracer_node, parallel_specialists_node
from src.agent.telemetry import compute_network_flow_summary
from src.core.adapters import is_registered, kyc_summaries
from src.core.canonical import to_money
from src.core.policy import PolicyConfig
from src.core.scoring import EvidenceFeatures, decide, rubric_scores
from src.db.database import utc_now_iso
from src.models import (
    DispositionDecision,
    GraphParams,
    Hypothesis,
    HypothesisLabel,
    InvestigationPlan,
    InvestigationState,
    SpecialistFinding,
)

_LLM_NOTE_PREFIXES = (
    "LLM planning unavailable",
    "LLM critique unavailable",
    "LLM hypothesis scoring unavailable",
    "LLM cited evidence IDs",
    "LLM plan parameters rejected",
    "LLM critic proposed out-of-bounds",
)


def _income(kyc: dict[str, Any]) -> Decimal:
    raw = kyc.get("declared_annual_income_inr")
    return to_money(raw) if raw not in (None, "") else Decimal("0.00")


def _features(state: InvestigationState) -> tuple[EvidenceFeatures, list[str], list[str]]:
    multi_hop = [p for p in state.fund_flow_paths if p.hop_count >= 2]
    root_kyc = state.kyc_profiles[0] if state.kyc_profiles else {}
    root_reg = is_registered(root_kyc)
    recipients = state.kyc_profiles[1:]
    merchants_verified = bool(recipients) and all(is_registered(k) for k in recipients)
    risk = str(root_kyc.get("risk_category", "")).lower()
    income = _income(root_kyc)
    income_mismatch = income > 0 and state.alert.total_amount_inr > income

    susp: list[str] = []
    benign: list[str] = []
    if multi_hop:
        p0 = multi_hop[0]
        susp.append(
            f"{len(multi_hop)} multi-hop scatter-gather path(s) [{p0.path_id}]: outflow INR {p0.total_outflow_inr} -> "
            f"consolidated INR {p0.total_consolidated_inr} (retention {p0.retention_pct}%)"
        )
    if income_mismatch:
        susp.append(f"Alert INR {state.alert.total_amount_inr:,.2f} exceeds declared annual income INR {income:,.2f}")
    if risk == "high":
        susp.append("Seed account carries HIGH KYC risk rating")
    if root_reg:
        benign.append(
            f"Active commercial/NGO/chit registration verified "
            f"({root_kyc.get('registry_type') or root_kyc.get('entity_type')})"
        )
    verified_low = (not root_reg) and merchants_verified and risk == "low"
    if verified_low:
        benign.append("Low-risk customer settling directly with GST-verified commercial merchants")
    unregistered = bool(root_kyc) and not root_reg and not verified_low
    if unregistered:
        susp.append("No active GST/MCA/80G/Chit commercial registration found")
    feats = EvidenceFeatures(
        multi_hop_path=bool(multi_hop),
        flagged_path=any(p.is_suspicious for p in state.fund_flow_paths),
        income_mismatch=income_mismatch,
        high_kyc_risk=risk == "high",
        unregistered_root=unregistered,
        registered_root=root_reg,
        verified_merchants_low_risk=verified_low,
        low_kyc_risk=risk == "low",
    )
    return feats, susp, benign


async def hypothesis_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    feats, susp_ev, benign_ev = _features(state)
    citations = [c["clause_id"] for c in state.regulatory_clauses if c.get("clause_id")]
    path_ids = [p.path_id for p in state.fund_flow_paths]
    degraded = list(state.degraded_evidence)
    rubric = rubric_scores(feats, ctx.policy.scoring)

    susp_conf, benign_conf = rubric.suspicious, rubric.benign
    susp_expl = "Scatter-gather layering network across intermediaries"
    benign_expl = "Legitimate commercial, payroll, charitable, chit-fund, or merchant-settlement activity"
    susp_ids, benign_ids = list(path_ids), list(path_ids)
    mode = "rubric"

    scoring = None
    meta = LlmCallMeta(used_live_llm=False, model="offline")
    if ctx.allow_llm:
        scoring, meta = await reasoning.assess_hypotheses(
            state,
            ctx.policy,
            ctx.ledger,
            role="c2_supervisor" if ctx.strong else "c1_investigator",
            strong=ctx.strong,
        )
    if scoring is not None:
        s_ok, s_bad = reasoning.grounded(
            scoring.suspicious.supporting_evidence_ids + scoring.suspicious.contradicting_evidence_ids,
            state.evidence_registry,
        )
        b_ok, b_bad = reasoning.grounded(
            scoring.benign.supporting_evidence_ids + scoring.benign.contradicting_evidence_ids,
            state.evidence_registry,
        )
        if s_bad or b_bad:
            degraded.append(
                f"LLM cited evidence IDs not in the registry (dropped): {', '.join(sorted({*s_bad, *b_bad}))}"
            )
        susp_conf, benign_conf = scoring.suspicious.confidence, scoring.benign.confidence
        susp_expl = reasoning.safe_text(scoring.suspicious.explanation, susp_expl)
        benign_expl = reasoning.safe_text(scoring.benign.explanation, benign_expl)
        susp_ids, benign_ids, mode = s_ok or susp_ids, b_ok or benign_ids, "llm"
    elif meta.used_live_llm:
        degraded.append(f"LLM hypothesis scoring unavailable ({meta.error or 'budget'}); evidence-weighted rubric used")

    hypotheses = [
        Hypothesis(
            label=HypothesisLabel.SUSPICIOUS,
            explanation=susp_expl,
            supporting_evidence=susp_ev,
            contradicting_evidence=benign_ev,
            confidence=susp_conf,
            regulatory_citations=citations[:3],
            evidence_ids=susp_ids,
        ),
        Hypothesis(
            label=HypothesisLabel.BENIGN,
            explanation=benign_expl,
            supporting_evidence=benign_ev,
            contradicting_evidence=susp_ev,
            confidence=benign_conf,
            regulatory_citations=citations[:2],
            evidence_ids=benign_ids,
        ),
    ]
    return {
        "active_hypotheses": hypotheses,
        "degraded_evidence": degraded,
        "reasoning_mode": mode,
        "current_node": "form_hypotheses",
        "current_step": state.current_step + 1,
        **sync_budget(ctx),
    }


async def critique_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    multi_hop = [p for p in state.fund_flow_paths if p.hop_count >= 2]
    root_kyc = state.kyc_profiles[0] if state.kyc_profiles else {}
    benign_cleared = is_registered(root_kyc) and str(root_kyc.get("risk_category", "")).lower() == "low"
    critiques: list[str] = []
    proposed: Optional[GraphParams] = None
    refresh_kyc = False
    refresh_regs = False
    focus_accounts: list[str] = []
    reg_queries: list[str] = []
    clause_ids: list[str] = []

    if state.transactions and not multi_hop and not benign_cleared:
        gb = ctx.policy.graph_bounds
        critiques.append(
            "Outbound dispersal legs present without multi-hop consolidation in current window; reconfigure "
            f"time_window_days and max_hops within policy bounds "
            f"[{gb.time_window_days.min}..{gb.time_window_days.max}d, {gb.max_hops.min}..{gb.max_hops.max} hops]."
        )
    kyc_unavail = any("KYC unavailable" in d for d in state.degraded_evidence)
    if state.transactions and not state.kyc_profiles and not kyc_unavail:
        critiques.append("KYC profiles missing for active transaction network; refresh identity verification.")
        refresh_kyc = True
    if state.transactions and not state.regulatory_clauses and not any(
        "Regulatory retrieval unavailable" in d for d in state.degraded_evidence
    ):
        critiques.append("Regulatory clauses missing; refresh compliance KB retrieval.")
        refresh_regs = True

    verdict = None
    meta = LlmCallMeta(used_live_llm=False, model="offline")
    if ctx.allow_llm:
        verdict, meta = await reasoning.critique_evidence(
            state,
            ctx.policy,
            ctx.ledger,
            role="c2_supervisor" if ctx.strong else "c1_investigator",
            strong=ctx.strong,
        )
    degraded = list(state.degraded_evidence)
    if verdict is not None and verdict.contradiction_found:
        critiques.append(
            reasoning.safe_text(verdict.reason, "LLM critic reported a contradiction (text withheld by guardrail)")
        )
        refresh_kyc = refresh_kyc or verdict.refresh_kyc
        refresh_regs = refresh_regs or verdict.refresh_regulations
        focus_accounts = [reasoning.safe_text(a, "") for a in verdict.focus_accounts if a]
        reg_queries = [reasoning.safe_text(q, "") for q in verdict.regulatory_queries if q]
        clause_ids = [reasoning.safe_text(c, "") for c in verdict.clause_ids if c]
        if verdict.proposed_graph_params is not None:
            proposed, violations = verdict.proposed_graph_params.to_params(ctx.policy)
            if proposed is None:
                degraded.append(
                    f"LLM critic proposed out-of-bounds graph parameters "
                    f"({'; '.join(violations)}); bounded widening used"
                )
    elif verdict is None and meta.used_live_llm:
        degraded.append(f"LLM critique unavailable ({meta.error or 'budget'}); deterministic critique only")
    return {
        "critiques": critiques,
        "proposed_params": proposed,
        "proposed_focus_accounts": [a for a in focus_accounts if a],
        "proposed_regulatory_queries": [q for q in reg_queries if q],
        "proposed_clause_ids": [c for c in clause_ids if c],
        "refresh_kyc": refresh_kyc,
        "refresh_regulations": refresh_regs,
        "degraded_evidence": degraded,
        "current_node": "critique",
        "current_step": state.current_step + 1,
        **sync_budget(ctx),
    }


def should_replan(state: InvestigationState, ctx: RunContext) -> Literal["replan", "draft"]:
    if not (ctx.replanning_enabled and state.critiques and state.replan_count < ctx.policy.budgets.max_replans):
        return "draft"
    if ctx.ledger.calls_used + 2 > ctx.policy.budgets.max_tool_calls:
        return "draft"
    if state.refresh_kyc or state.refresh_regulations or state.proposed_focus_accounts or state.proposed_clause_ids:
        return "replan"
    params = state.plan.graph_params if state.plan else GraphParams.policy_default()
    gb = ctx.policy.graph_bounds
    if params.time_window_days >= gb.time_window_days.max and params.max_hops >= gb.max_hops.max:
        return "draft"
    return "replan"


async def replan_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    verdict = ctx.ledger.try_replan()
    if not verdict.allowed:
        return {
            "critiques": [],
            "proposed_params": None,
            "current_node": "replan",
            "current_step": state.current_step + 1,
            **sync_budget(ctx),
        }
    current = state.plan.graph_params if state.plan else GraphParams.policy_default()
    new_params = (
        state.proposed_params
        if state.proposed_params and state.proposed_params != current
        else widened_params(ctx.policy, current)
    )
    prev_plan = state.plan
    focus = list(dict.fromkeys([*(prev_plan.focus_accounts if prev_plan else []), *state.proposed_focus_accounts]))
    queries = list(
        dict.fromkeys([*(prev_plan.regulatory_queries if prev_plan else []), *state.proposed_regulatory_queries])
    )
    cids = list(dict.fromkeys([*(prev_plan.clause_ids if prev_plan else []), *state.proposed_clause_ids]))
    reason = " | ".join(state.critiques[-2:])
    new_plan = InvestigationPlan(
        steps=prev_plan.steps if prev_plan else [],
        graph_params=new_params,
        focus_accounts=focus,
        regulatory_queries=queries,
        clause_ids=cids,
        replan_count=state.replan_count + 1,
        replan_reason=reason,
    )
    return {
        "plan": new_plan,
        "replan_count": state.replan_count + 1,
        "critiques": [],
        "proposed_params": None,
        "proposed_focus_accounts": [],
        "proposed_regulatory_queries": [],
        "proposed_clause_ids": [],
        "current_node": "replan",
        "current_step": state.current_step + 1,
        **sync_budget(ctx),
    }


def _has_critical_gap(state: InvestigationState, degraded: list[str], has_security_flag: bool) -> bool:
    if has_security_flag:
        return True
    if not state.transactions and degraded:
        return True
    if any(d.startswith("Graph analysis unavailable:") for d in degraded):
        return True
    if not state.kyc_profiles and any(d.startswith("KYC unavailable for") for d in degraded):
        return True
    return False


def decide_disposition(
    hypotheses: list[Hypothesis],
    degraded: list[str],
    policy: PolicyConfig,
    *,
    critical_missing: bool = False,
) -> tuple[DispositionDecision, float]:
    susp = next((Decimal(str(h.confidence)) for h in hypotheses if h.label == HypothesisLabel.SUSPICIOUS), Decimal("0"))
    benign = next((Decimal(str(h.confidence)) for h in hypotheses if h.label == HypothesisLabel.BENIGN), Decimal("0"))
    evidence_degraded = [d for d in degraded if not d.startswith(_LLM_NOTE_PREFIXES)]
    value, confidence = decide(
        susp,
        benign,
        bool(evidence_degraded),
        policy.scoring,
        critical_missing=critical_missing,
    )
    return DispositionDecision(value), float(confidence)


def _c2_runs(
    state: InvestigationState, ctx: RunContext, now: str, flow_ms: float, ev_ms: float, critic_ms: float, summary: str
) -> list[dict[str, Any]]:
    tw, mh = (state.plan.graph_params.time_window_days, state.plan.graph_params.max_hops) if state.plan else (0, 0)
    multi = sum(1 for p in state.fund_flow_paths if p.hop_count >= 2)
    return [
        {
            "agent_id": "flow_tracer",
            "agent_name": "Flow Tracing Agent",
            "task": f"Graph traversal ({tw}d, {mh} hops) & Decimal conservation",
            "status": "completed",
            "started_at": now,
            "duration_ms": flow_ms,
            "tool_calls": ctx.box("flow_tracer").calls,
            "summary": f"Found {len(state.fund_flow_paths)} candidate paths ({multi} multi-hop)",
        },
        {
            "agent_id": "benign_investigator",
            "agent_name": "Benign Context Agent",
            "task": "Multi-bank KYC verification & GST/MCA/80G/Chit registry checks",
            "status": "completed",
            "started_at": now,
            "duration_ms": ev_ms,
            "tool_calls": ctx.box("benign_investigator").calls,
            "summary": f"Verified {len(state.kyc_profiles)} KYC/registry record(s)",
        },
        {
            "agent_id": "regulatory_analyst",
            "agent_name": "Regulatory Research Agent",
            "task": "Hybrid RAG (BM25 + Vector + RRF + Reranker) over Indian AML corpus",
            "status": "completed",
            "started_at": now,
            "duration_ms": ev_ms,
            "tool_calls": ctx.box("regulatory_analyst").calls,
            "summary": f"Retrieved {len(state.regulatory_clauses)} regulatory clauses",
        },
        {
            "agent_id": "reporter_critic",
            "agent_name": "Reporting & Critique Agent",
            "task": "Hypothesis reconciliation, deterministic verifier & SHA-256 worksheet draft",
            "status": "completed",
            "started_at": now,
            "duration_ms": round(critic_ms, 1),
            "tool_calls": ctx.box("reporter_critic").calls,
            "summary": summary,
        },
    ]


def _telemetry(state: InvestigationState, ctx: RunContext, worksheet_summary: str, critic_ms: float) -> dict[str, Any]:
    flow_ms, ev_ms = round(ctx.timings.get("flow_ms", 0.0), 1), round(ctx.timings.get("evidence_ms", 0.0), 1)
    steps = [
        {"step": 1, "name": "Alert Intake & Validation", "status": "completed"},
        {"step": 2, "name": "Investigation Planning", "status": "completed"},
        {
            "step": 3,
            "name": ("Parallel Investigation" if ctx.parallel else "ReAct Evidence Gathering")
            + (f" ({state.replan_count} Replan)" if state.replan_count and not ctx.parallel else ""),
            "status": "completed",
            "duration_ms": round(flow_ms + ev_ms, 1),
        },
        {"step": 4, "name": "Evidence Synthesis", "status": "completed"},
        {"step": 5, "name": "Verification (Deterministic)", "status": "completed", "duration_ms": round(critic_ms, 1)},
        {"step": 6, "name": "Human Approval", "status": "waiting_approval"},
        {"step": 7, "name": "Case Commit & Reporting", "status": "pending"},
    ]
    now = utc_now_iso()
    if ctx.parallel:
        runs = _c2_runs(state, ctx, now, flow_ms, ev_ms, critic_ms, worksheet_summary)
    else:
        runs = [
            {
                "agent_id": "c1_investigator",
                "agent_name": "C1 Single-Agent ReAct Investigator",
                "task": "Unified graph traversal, KYC/registry verification, RAG lookup & bounded replanning",
                "status": "completed",
                "started_at": now,
                "duration_ms": round(flow_ms + ev_ms + critic_ms, 1),
                "tool_calls": ctx.ledger.calls_used,
                "summary": worksheet_summary,
            }
        ]
    return {"workflow_steps": steps, "agent_runs": runs}


async def draft_worksheet_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    t0 = time.perf_counter()
    box = ctx.box("reporter_critic")
    if h_cr := handoff_for(state, "reporter_critic"):
        box.set_sub_budget(h_cr.allowed_tool_budget)

    degraded = sorted({*state.degraded_evidence, *all_security_notes(ctx), *tool_error_notes(ctx)})
    has_security_flag = any(b.security_events for b in ctx.boxes.values())
    critical_gap = _has_critical_gap(state, degraded, has_security_flag)
    disposition, confidence = decide_disposition(
        state.active_hypotheses, degraded, ctx.policy, critical_missing=critical_gap
    )
    citations = sorted({c for h in state.active_hypotheses for c in h.regulatory_citations})
    summaries = kyc_summaries(state.kyc_profiles, limit=5)
    rationale = (
        f"{ctx.label}: analyzed {len(state.fund_flow_paths)} candidate "
        f"path(s) across {state.replan_count + 1} bounded graph pass(es) "
        f"(replans={state.replan_count}, tool_calls={ctx.ledger.calls_used}) "
        f"and {len(state.kyc_profiles)} KYC/registry records "
        f"[reasoning={state.reasoning_mode}]. Recommended disposition: "
        f"{disposition.value} ({confidence:.0%} confidence) "
        f"pending mandatory human review."
    )
    if degraded:
        rationale += " Degraded evidence: " + "; ".join(degraded)
    outcome = await draft_and_verify(
        box=box,
        ledger=ctx.ledger,
        alert=state.alert,
        agent_label=ctx.label,
        thread_id=state.thread_id,
        disposition=disposition,
        confidence=confidence,
        paths=state.fund_flow_paths,
        hypotheses=state.active_hypotheses,
        citations=citations,
        summaries=summaries,
        registry=state.evidence_registry,
        replan_count=state.replan_count,
        base_rationale=rationale,
        degraded=degraded,
        use_strong_model=ctx.strong,
        narrative_role="c2_specialists" if ctx.mode == "c2_multi" else None,
        verify=ctx.deterministic_verifier,
        allow_llm=ctx.allow_llm,
    )
    critic_ms = (time.perf_counter() - t0) * 1000
    ws = outcome.worksheet
    findings = list(state.specialist_findings)
    if ctx.parallel:
        c_sum = f"Drafted {ws.worksheet_id} ({ws.recommended_disposition.value})"
        critic_f = SpecialistFinding(
            task_id="HO-CRITIC", agent_name="reporter_critic", summary=c_sum, tool_calls=box.calls
        )
        findings = upsert_finding(findings, critic_f)
    flow_summary = compute_network_flow_summary(
        state.alert.root_account, state.transactions, state.fund_flow_paths, state.kyc_profiles
    )
    summary_txt = ws.recommendation_rationale if ctx.mode != "c2_multi" else f"Drafted {ws.worksheet_id}"
    return {
        "worksheet": ws,
        "active_hypotheses": ws.hypotheses,
        "degraded_evidence": degraded,
        "flow_summary": flow_summary,
        "specialist_findings": findings,
        "error": "verification_failed" if outcome.verification_failed else None,
        "is_complete": True,
        "current_node": "interrupt_required",
        "current_step": state.current_step + 1,
        **sync_budget(ctx),
        **_telemetry(state, ctx, summary_txt, critic_ms),
    }


__all__ = [
    "TOOL_CAPABILITIES",
    "RunContext",
    "critique_node",
    "decide_disposition",
    "draft_worksheet_node",
    "flow_tracer_node",
    "gather_evidence_node",
    "hypothesis_node",
    "parallel_specialists_node",
    "plan_node",
    "replan_node",
    "should_replan",
    "widened_params",
]
