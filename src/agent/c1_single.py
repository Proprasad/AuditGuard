"""
AuditGuard C1 Single-Agent Investigator.

Node functions (plan -> gather_evidence -> form_hypotheses -> critique -> [replan] -> draft_and_verify) share a
`RunContext` (role-scoped GuardedToolbox + per-run BudgetLedger + PolicyConfig). Every tool call is RBAC-checked,
bounds-checked and budget-enforced by `GuardedToolbox`; all money flows through `Decimal`.
Durable node-level checkpoints enable exact mid-run crash recovery.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from math import ceil
from typing import Any, Literal, Optional

from src.agent.llm_client import synthesize_investigation_narrative
from src.agent.tooling import GuardedToolbox, is_error
from src.config import get_policy
from src.core.adapters import flow_paths_from_result, graph_tx_payload, is_registered, kyc_summaries
from src.core.canonical import to_money, to_ratio
from src.core.policy import BudgetLedger, PolicyConfig
from src.db.database import load_checkpoint, save_checkpoint, utc_now_iso
from src.guardrails.verifier import verify_worksheet
from src.memory.store import memory_store, trim_messages_with_summary
from src.models import (
    Alert,
    DispositionDecision,
    DispositionWorksheet,
    GraphParams,
    Hypothesis,
    HypothesisLabel,
    InvestigationPlan,
    InvestigationState,
)

ROLE = "c1_single"
HIGH_CONFIDENCE = 0.7


class SimulatedCrashInterrupt(RuntimeError):
    """Raised intentionally in Milestone T3 tests to simulate a mid-run server crash."""


@dataclass
class RunContext:
    toolbox: GuardedToolbox
    ledger: BudgetLedger
    policy: PolicyConfig


def new_context(role: str = ROLE) -> RunContext:
    policy = get_policy()
    ledger = policy.new_ledger()
    return RunContext(GuardedToolbox(role, ledger), ledger, policy)


def _as_state(raw: InvestigationState | dict[str, Any]) -> InvestigationState:
    if isinstance(raw, InvestigationState):
        return raw
    return InvestigationState(**{k: v for k, v in raw.items() if k in InvestigationState.model_fields})


def _sync_budget(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    cap = ctx.policy.budgets.max_cost_usd_per_case
    return {
        "tool_calls_used": ctx.ledger.calls_used,
        "total_tokens_used": ctx.ledger.tokens_used,
        "estimated_cost_usd": ctx.ledger.cost_usd,
        "budget_remaining_usd": max(Decimal("0"), cap - ctx.ledger.cost_usd),
    }


# ---------------------------------------------------------------------------
# State machine nodes
# ---------------------------------------------------------------------------
def widened_params(policy: PolicyConfig, current: GraphParams) -> GraphParams:
    """Widen graph parameters one bounded step towards the policy ceiling (exhausts in max_replans-1 steps)."""
    gb = policy.graph_bounds
    divisor = max(1, policy.budgets.max_replans - 1)

    def _step(rng_max: int, rng_default: int) -> int:
        return max(1, ceil((rng_max - rng_default) / divisor))

    return GraphParams(
        time_window_days=min(gb.time_window_days.max, current.time_window_days + _step(gb.time_window_days.max, gb.time_window_days.default)),
        max_hops=min(gb.max_hops.max, current.max_hops + _step(gb.max_hops.max, gb.max_hops.default)),
        amount_tolerance=min(gb.amount_tolerance.max, to_ratio(current.amount_tolerance + (gb.amount_tolerance.max - gb.amount_tolerance.default) / divisor)),
        min_intermediaries=current.min_intermediaries,
    )


async def plan_node(
    raw_state: InvestigationState | dict[str, Any], ctx: RunContext,
    reflexion_enabled: bool = False, memory_enabled: bool = True,
) -> dict[str, Any]:
    state = _as_state(raw_state)
    lessons: list[str] = []
    if reflexion_enabled and memory_enabled:
        top = memory_store.retrieve_top_lessons(f"{state.alert.rule_name} scatter gather", top_k=3)
        lessons = [f"[{les.lesson_id}] IF {les.trigger_precondition} THEN {les.actionable_rule}" for les in top]

    params = GraphParams.policy_default()
    if any("14-30" in lesson for lesson in lessons):
        params = widened_params(ctx.policy, params)

    plan = InvestigationPlan(
        steps=[
            "1. Retrieve alert context and seed transactions (bank-records)",
            "2. Run bounded graph scan via graph-engine (Decimal conservation)",
            "3. Verify KYC profiles & commercial registry for benign look-alikes",
            "4. Retrieve PMLA/RBI/FIU-IND regulatory clauses via compliance-kb",
            "5. Test competing suspicious vs. benign hypotheses & replan if contradicted",
            "6. Verify arithmetic/citations and draft SHA-256 disposition worksheet",
        ],
        graph_params=params,
    )
    msgs, summary = trim_messages_with_summary(
        [*state.messages, {"role": "assistant", "content": f"Created 6-step plan with params {params.model_dump(mode='json')}"}],
        state.rolling_summary,
        window_size=ctx.policy.memory.short_term_window_messages,
    )
    return {
        "plan": plan,
        "retrieved_lessons": lessons,
        "messages": msgs,
        "rolling_summary": summary,
        "current_node": "plan",
        "current_step": state.current_step + 1,
    }


async def _collect_identity_evidence(
    ctx: RunContext, state: InvestigationState, root: str, network: list[str], registry: dict[str, Any], degraded: list[str],
) -> list[dict[str, Any]]:
    profiles: list[dict[str, Any]] = list(state.kyc_profiles)
    if profiles:
        return profiles
    for acc in [root, *network[:3]]:
        kyc = await ctx.toolbox.call("bank-records", "get_kyc_profile", {"account_id": acc})
        if is_error(kyc):
            degraded.append(f"KYC unavailable for {acc}: {kyc.get('error_code') or kyc.get('error')}")
            continue
        registry[kyc.get("evidence_id", f"KYC-{acc}")] = kyc
        reg = await ctx.toolbox.call(
            "bank-records", "check_commercial_registry", {"entity_name": kyc.get("entity_name", acc), "account_id": acc}
        )
        if is_error(reg):
            degraded.append(f"Commercial registry unavailable for {acc}: {reg.get('error_code') or reg.get('error')}")
        elif reg.get("evidence_id"):
            registry[reg["evidence_id"]] = reg
            kyc["registry_check"] = reg
        profiles.append(kyc)
    return profiles


async def _collect_regulatory_evidence(ctx: RunContext, state: InvestigationState, registry: dict[str, Any], degraded: list[str]) -> list[str]:
    snippets = list(state.regulatory_snippets)
    if snippets:
        return snippets
    res = await ctx.toolbox.call(
        "compliance-kb", "search_regulations",
        {"query": "scatter gather staggered layering fee skimming and commercial registry benign verification", "top_k": 5, "decompose": True},
    )
    if is_error(res):
        degraded.append(f"Regulatory retrieval unavailable: {res.get('error_code') or res.get('error')}")
        return snippets
    for clause in res.get("clauses", []):
        registry[clause["clause_id"]] = clause
        snippets.append(f"[{clause['clause_id']}] {clause['title']}: {clause['text']}")
    return snippets


async def gather_evidence_node(raw_state: InvestigationState | dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    state = _as_state(raw_state)
    alert = state.alert
    registry = dict(state.evidence_registry)
    degraded = list(state.degraded_evidence)
    params = (state.plan.graph_params if state.plan else GraphParams.policy_default())

    alert_ctx = await ctx.toolbox.call("bank-records", "get_alert_context", {"alert_id": alert.alert_id})
    if is_error(alert_ctx):
        degraded.append(f"Alert context unavailable: {alert_ctx.get('error_code') or alert_ctx.get('error')}")
        return {
            "degraded_evidence": degraded, "current_node": "gather_evidence",
            "current_step": state.current_step + 1, **_sync_budget(state, ctx),
        }

    txs = alert_ctx.get("transactions", [])
    root = alert_ctx.get("root_account", alert.root_account)
    network = alert_ctx.get("network_accounts", alert.network_accounts)
    registry.update({t["tx_id"]: t for t in txs if t.get("tx_id")})

    graph_result = await ctx.toolbox.call(
        "graph-engine", "find_candidate_fund_flows",
        {"root_account": root, "transactions": graph_tx_payload(txs), **params.model_dump()},
    )
    paths = []
    if is_error(graph_result):
        degraded.append(f"Graph analysis unavailable: {graph_result.get('error_code') or graph_result.get('error')}")
    else:
        registry[graph_result["calc_id"]] = graph_result.get("graph_stats", {})
        paths = flow_paths_from_result(graph_result, limit=5)
        registry.update({p.path_id: p.model_dump(mode="json") for p in paths})

    profiles = await _collect_identity_evidence(ctx, state, root, list(network), registry, degraded)
    snippets = await _collect_regulatory_evidence(ctx, state, registry, degraded)

    msgs, summary = trim_messages_with_summary(
        [*state.messages, {"role": "tool", "content": f"Gathered {len(paths)} paths, {len(profiles)} KYC records"}],
        state.rolling_summary,
        window_size=ctx.policy.memory.short_term_window_messages,
    )
    return {
        "transactions": txs,
        "fund_flow_paths": paths,
        "kyc_profiles": profiles,
        "regulatory_snippets": snippets,
        "evidence_registry": registry,
        "degraded_evidence": degraded,
        "messages": msgs,
        "rolling_summary": summary,
        "current_node": "gather_evidence",
        "current_step": state.current_step + 1,
        **_sync_budget(state, ctx),
    }


def _income(kyc: dict[str, Any]) -> Decimal:
    raw = kyc.get("declared_annual_income_inr")
    return to_money(raw) if raw not in (None, "") else Decimal("0.00")


def _supporting_evidence(state: InvestigationState, multi_hop: list[Any], root_kyc: dict[str, Any], root_reg: bool) -> tuple[list[str], list[str]]:
    susp: list[str] = []
    benign: list[str] = []
    income = _income(root_kyc)
    if multi_hop:
        p0 = multi_hop[0]
        susp.append(
            f"{len(multi_hop)} multi-hop scatter-gather path(s) [{p0.path_id}]: outflow INR {p0.total_outflow_inr} -> "
            f"consolidated INR {p0.total_consolidated_inr} (retention {p0.retention_pct}%)"
        )
    if income > 0 and state.alert.total_amount_inr > income:
        susp.append(f"Alert INR {state.alert.total_amount_inr:,.2f} exceeds declared annual income INR {income:,.2f}")
    if str(root_kyc.get("risk_category", "")).lower() == "high":
        susp.append("Seed account carries HIGH KYC risk rating")
    if root_reg:
        benign.append(f"Active commercial/NGO/chit registration verified ({root_kyc.get('registry_type') or root_kyc.get('entity_type')})")
    return susp, benign


async def hypothesis_node(raw_state: InvestigationState | dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    state = _as_state(raw_state)
    multi_hop = [p for p in state.fund_flow_paths if p.hop_count >= 2]
    single_hop = [p for p in state.fund_flow_paths if p.hop_count == 1]
    root_kyc = state.kyc_profiles[0] if state.kyc_profiles else {}
    root_reg = is_registered(root_kyc)
    recipients = state.kyc_profiles[1:]
    merchants_verified = bool(recipients) and all(is_registered(k) for k in recipients)
    risk = str(root_kyc.get("risk_category", "")).lower()
    high_risk, low_risk = risk == "high", risk == "low"
    income = _income(root_kyc)
    income_mismatch = income > 0 and state.alert.total_amount_inr > income

    citations = [s[1: s.index("]")] for s in state.regulatory_snippets if s.startswith("[") and "]" in s]
    susp_ev, benign_ev = _supporting_evidence(state, multi_hop, root_kyc, root_reg)
    if not root_reg:
        if merchants_verified and low_risk:
            benign_ev.append("Low-risk customer settling directly with GST-verified commercial merchants")
        elif root_kyc:
            susp_ev.append("No active GST/MCA/80G/Chit commercial registration found")

    if (root_reg or (merchants_verified and low_risk)) and not high_risk:
        susp_conf, benign_conf = 0.18, 0.86
    elif multi_hop and (income_mismatch or high_risk or not root_reg):
        susp_conf, benign_conf = 0.86, 0.14
    elif single_hop and not multi_hop:
        susp_conf, benign_conf = 0.45, 0.35
    else:
        susp_conf, benign_conf = 0.40, 0.40

    evidence_ids = [p.path_id for p in state.fund_flow_paths]
    hypotheses = [
        Hypothesis(
            label=HypothesisLabel.SUSPICIOUS, explanation="Scatter-gather layering network across intermediaries",
            supporting_evidence=susp_ev, contradicting_evidence=benign_ev, confidence=susp_conf,
            regulatory_citations=citations[:3], evidence_ids=evidence_ids,
        ),
        Hypothesis(
            label=HypothesisLabel.BENIGN,
            explanation="Legitimate commercial, payroll, charitable, chit-fund, or merchant-settlement activity",
            supporting_evidence=benign_ev, contradicting_evidence=susp_ev, confidence=benign_conf,
            regulatory_citations=citations[:2], evidence_ids=evidence_ids,
        ),
    ]
    return {"active_hypotheses": hypotheses, "current_node": "form_hypotheses", "current_step": state.current_step + 1}


async def critique_node(raw_state: InvestigationState | dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    state = _as_state(raw_state)
    multi_hop = [p for p in state.fund_flow_paths if p.hop_count >= 2]
    root_kyc = state.kyc_profiles[0] if state.kyc_profiles else {}
    benign_cleared = is_registered(root_kyc) and str(root_kyc.get("risk_category", "")).lower() == "low"
    critiques: list[str] = []
    if state.transactions and not multi_hop and not benign_cleared:
        gb = ctx.policy.graph_bounds
        critiques.append(
            "Outbound dispersal legs present without multi-hop consolidation in current window; reconfigure "
            f"time_window_days and max_hops within policy bounds "
            f"[{gb.time_window_days.min}..{gb.time_window_days.max}d, {gb.max_hops.min}..{gb.max_hops.max} hops]."
        )
    return {"critiques": critiques, "current_node": "critique", "current_step": state.current_step + 1}


def should_replan(state: InvestigationState, ctx: RunContext, replanning_enabled: bool = True) -> Literal["replan", "draft"]:
    if not (replanning_enabled and state.critiques and state.replan_count < ctx.policy.budgets.max_replans):
        return "draft"
    params = state.plan.graph_params if state.plan else GraphParams.policy_default()
    gb = ctx.policy.graph_bounds
    if params.time_window_days >= gb.time_window_days.max and params.max_hops >= gb.max_hops.max:
        return "draft"
    return "replan"


async def replan_node(raw_state: InvestigationState | dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    state = _as_state(raw_state)
    verdict = ctx.ledger.try_replan()
    if not verdict.allowed:
        return {"critiques": [], "current_node": "replan", "current_step": state.current_step + 1}
    current = state.plan.graph_params if state.plan else GraphParams.policy_default()
    new_plan = InvestigationPlan(
        steps=state.plan.steps if state.plan else [],
        graph_params=widened_params(ctx.policy, current),
        replan_count=state.replan_count + 1,
        replan_reason=" | ".join(state.critiques[-2:]),
    )
    return {
        "plan": new_plan,
        "replan_count": state.replan_count + 1,
        "critiques": [],
        "current_node": "replan",
        "current_step": state.current_step + 1,
    }


def decide_disposition(hypotheses: list[Hypothesis], degraded: list[str]) -> tuple[DispositionDecision, float]:
    susp = next((h.confidence for h in hypotheses if h.label == HypothesisLabel.SUSPICIOUS), 0.0)
    benign = next((h.confidence for h in hypotheses if h.label == HypothesisLabel.BENIGN), 0.0)
    if degraded and susp < HIGH_CONFIDENCE and benign < HIGH_CONFIDENCE:
        return DispositionDecision.REQUEST_INFO, max(susp, benign, 0.45)
    if susp >= HIGH_CONFIDENCE:
        return DispositionDecision.ESCALATE_STR, susp
    if benign >= HIGH_CONFIDENCE:
        return DispositionDecision.CLOSE_BENIGN, benign
    return DispositionDecision.REQUEST_INFO, max(susp, benign, 0.45)


async def draft_worksheet_node(
    raw_state: InvestigationState | dict[str, Any], ctx: RunContext, deterministic_verifier: bool = True,
) -> dict[str, Any]:
    state = _as_state(raw_state)
    disposition, confidence = decide_disposition(state.active_hypotheses, state.degraded_evidence)
    citations = sorted({c for h in state.active_hypotheses for c in h.regulatory_citations})
    summaries = kyc_summaries(state.kyc_profiles, limit=5)
    rationale = (
        f"Analyzed {len(state.fund_flow_paths)} candidate path(s) across {state.replan_count + 1} bounded graph pass(es) "
        f"(replans={state.replan_count}, tool_calls={ctx.ledger.calls_used}) and {len(state.kyc_profiles)} KYC/registry records. "
        f"Recommended disposition: {disposition.value} ({confidence:.0%} confidence) pending mandatory human review."
    )
    if state.degraded_evidence:
        rationale += " Degraded evidence: " + "; ".join(state.degraded_evidence)

    llm_out = await synthesize_investigation_narrative(
        alert_id=state.alert.alert_id, disposition=disposition.value, confidence=confidence,
        paths_summary=[p.model_dump(mode="json") for p in state.fund_flow_paths[:3]], kyc_summaries=summaries,
        citations=citations, replan_count=state.replan_count, fallback_rationale=rationale,
        use_strong_model=False, ledger=ctx.ledger,
    )
    rationale = llm_out["rationale"]
    hypotheses = list(state.active_hypotheses)
    if llm_out["used_live_llm"]:
        for hyp in hypotheses:
            override = llm_out["suspicious_explanation"] if hyp.label == HypothesisLabel.SUSPICIOUS else llm_out["benign_explanation"]
            if override:
                hyp.explanation = override

    draft_payload = {
        "alert_id": state.alert.alert_id,
        "recommended_disposition": disposition.value,
        "recommendation_rationale": rationale,
        "confidence_score": confidence,
        "candidate_paths": [p.model_dump() for p in state.fund_flow_paths[:3]],
        "regulatory_citations": citations or ["REG-FIU-RF-014"],
        "kyc_summaries": summaries,
    }
    if deterministic_verifier:
        verification = verify_worksheet(draft_payload, evidence_registry=state.evidence_registry)
        if not verification.passed:
            rationale = f"[VERIFIER WARNING: {verification.errors}] " + rationale
            draft_payload["recommendation_rationale"] = rationale

    draft = await ctx.toolbox.call("case-actions", "draft_disposition_report", draft_payload)
    worksheet = DispositionWorksheet(
        worksheet_id=draft.get("worksheet_id", ""),
        alert_id=state.alert.alert_id,
        investigator_agent=f"auditguard-c1 ({llm_out['model']})",
        candidate_paths=state.fund_flow_paths[:3],
        hypotheses=hypotheses,
        regulatory_citations=draft_payload["regulatory_citations"],
        kyc_summaries=summaries,
        recommended_disposition=disposition,
        recommendation_rationale=rationale,
        confidence_score=confidence,
        payload_hash=draft.get("payload_hash", ""),
    )
    return {
        "worksheet": worksheet,
        "active_hypotheses": hypotheses,
        "is_complete": True,
        "current_node": "interrupt_required",
        "current_step": state.current_step + 1,
        **_sync_budget(state, ctx),
    }


# ---------------------------------------------------------------------------
# Durable checkpointed execution & crash resume
# ---------------------------------------------------------------------------
def _merge(state: InvestigationState, out: dict[str, Any]) -> InvestigationState:
    return _as_state({**{k: getattr(state, k) for k in InvestigationState.model_fields}, **out})


def _finalize_telemetry(state: InvestigationState) -> InvestigationState:
    from src.agent.telemetry import compute_network_flow_summary

    root = state.alert.root_account
    state.flow_summary = compute_network_flow_summary(root, state.transactions, state.fund_flow_paths, state.kyc_profiles)
    state.workflow_steps = [
        {"step": 1, "name": "Alert Intake & Validation", "status": "completed"},
        {"step": 2, "name": "Investigation Planning", "status": "completed"},
        {"step": 3, "name": "ReAct Evidence Gathering" + (f" ({state.replan_count} Replan)" if state.replan_count else ""), "status": "completed"},
        {"step": 4, "name": "Evidence Synthesis", "status": "completed"},
        {"step": 5, "name": "Verification (Deterministic)", "status": "completed"},
        {"step": 6, "name": "Human Approval", "status": "waiting_approval"},
        {"step": 7, "name": "Case Commit & Reporting", "status": "pending"},
    ]
    state.agent_runs = [{
        "agent_id": "c1_investigator", "agent_name": "C1 Single-Agent ReAct Investigator",
        "task": "Unified graph traversal, KYC/registry verification, RAG lookup & bounded replanning",
        "status": "completed", "started_at": utc_now_iso(), "tool_calls": state.tool_calls_used,
        "summary": state.worksheet.recommendation_rationale if state.worksheet else "",
    }]
    return state


async def run_investigation(
    alert: Alert,
    mode: str = "c1_single",
    thread_id: Optional[str] = None,
    resume: bool = False,
    stop_after_node: Optional[str] = None,
    replanning_enabled: bool = True,
    deterministic_verifier: bool = True,
    reflexion_enabled: bool = False,
    memory_enabled: bool = True,
) -> InvestigationState:
    """Execute C1 with durable node-by-node checkpointing; `resume=True` restarts from the saved node."""
    ctx = new_context()
    start_from = "start"
    if resume and thread_id and (saved := load_checkpoint(thread_id)) and saved.get("state"):
        state = _as_state(saved["state"])
        start_from = saved["current_node"]
        if state.is_complete and state.worksheet:
            return state
        ctx.ledger.preload(calls=state.tool_calls_used, cost_usd=state.estimated_cost_usd, replans=state.replan_count)
    else:
        state = InvestigationState(thread_id=thread_id or f"thr-{alert.alert_id.lower()}", alert=alert)

    def persist(st: InvestigationState, status: str = "running") -> None:
        save_checkpoint(
            thread_id=st.thread_id, alert_id=st.alert.alert_id, mode=mode, current_node=st.current_node, status=status,
            state_dict=st.model_dump(mode="json"), worksheet_id=st.worksheet.worksheet_id if st.worksheet else None,
            payload_hash=st.worksheet.payload_hash if st.worksheet else None,
        )

    def maybe_crash(node: str) -> None:
        if stop_after_node == node:
            raise SimulatedCrashInterrupt(f"Simulated crash after {node}")

    if start_from == "start":
        state = _merge(state, await plan_node(state, ctx, reflexion_enabled=reflexion_enabled, memory_enabled=memory_enabled))
        persist(state)
        maybe_crash("plan")

    while True:
        if start_from in ("start", "plan", "replan"):
            state = _merge(state, await gather_evidence_node(state, ctx))
            persist(state)
            start_from = "gather_evidence"
            maybe_crash("gather_evidence")
        if start_from == "gather_evidence":
            state = _merge(state, await hypothesis_node(state, ctx))
            persist(state)
            start_from = "form_hypotheses"
            maybe_crash("form_hypotheses")
        if start_from == "form_hypotheses":
            state = _merge(state, await critique_node(state, ctx))
            persist(state)
            start_from = "critique"
            maybe_crash("critique")
        if should_replan(state, ctx, replanning_enabled) == "replan":
            state = _merge(state, await replan_node(state, ctx))
            persist(state)
            start_from = "replan"
            maybe_crash("replan")
        else:
            break

    state = _merge(state, await draft_worksheet_node(state, ctx, deterministic_verifier=deterministic_verifier))
    state = _finalize_telemetry(state)
    persist(state, status="interrupt_required")
    return state
