"""
Shared LangGraph node implementations for C1 (single agent) and C2 (supervisor + RBAC specialists).

Nodes are plain async functions `(InvestigationState, RunContext) -> partial-state dict`; `src/agent/graph.py` wires
them
into a compiled `StateGraph` (conditional replan edge, durable checkpointer, `interrupt()` human gate).
Reasoning is LLM-driven when a live LLM is active (plan / competing hypotheses / critique) and otherwise uses the
evidence-weighted rubric from `config/models.yaml`; either way every claim is grounded in registry evidence IDs.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal
from math import ceil
from typing import Any, Literal, Optional

from src.agent import reasoning
from src.agent.drafting import draft_and_verify, security_notes
from src.agent.telemetry import compute_network_flow_summary
from src.agent.tooling import GuardedToolbox, is_error
from src.core.adapters import flow_paths_from_result, graph_tx_payload, is_registered, kyc_summaries
from src.core.canonical import to_money, to_ratio
from src.core.policy import BudgetLedger, PolicyConfig
from src.core.scoring import EvidenceFeatures, decide, rubric_scores
from src.db.database import utc_now_iso
from src.guardrails.guardrails import unwrap_untrusted_data
from src.memory.store import memory_store, trim_messages_with_summary
from src.models import (
    DispositionDecision,
    FundFlowPath,
    GraphParams,
    Hypothesis,
    HypothesisLabel,
    InvestigationPlan,
    InvestigationState,
    SpecialistFinding,
    SpecialistHandOff,
)
from src.typology_registry import typology_registry

TOOL_CAPABILITIES = [
    "bank-records: alert context, KYC profiles, commercial registry, counterparty history",
    "graph-engine: bounded fund-flow path search, Decimal conservation & replan run comparison",
    "compliance-kb: hybrid RAG over PMLA / RBI / FIU-IND clauses",
]


@dataclass
class RunContext:
    mode: str
    policy: PolicyConfig
    ledger: BudgetLedger
    boxes: dict[str, GuardedToolbox]
    label: str
    role: str
    strong: bool = False
    parallel: bool = False
    replanning_enabled: bool = True
    deterministic_verifier: bool = True
    reflexion_enabled: bool = False
    memory_enabled: bool = True
    emit: Optional[Callable[[str, dict[str, Any]], None]] = None
    timings: dict[str, float] = field(default_factory=dict)
    last_graph_output: Optional[dict[str, Any]] = None

    def box(self, name: str) -> GuardedToolbox:
        return self.boxes.get(name) or self.boxes["primary"]


def _sync_budget(ctx: RunContext) -> dict[str, Any]:
    cap = ctx.policy.budgets.max_cost_usd_per_case
    return {
        "tool_calls_used": ctx.ledger.calls_used,
        "total_tokens_used": ctx.ledger.tokens_used,
        "estimated_cost_usd": ctx.ledger.cost_usd,
        "budget_remaining_usd": max(Decimal("0"), cap - ctx.ledger.cost_usd),
    }


def _err(res: dict[str, Any]) -> str:
    return str(res.get("error_code") or res.get("error"))


def _all_security_notes(ctx: RunContext) -> list[str]:
    return sorted({n for b in ctx.boxes.values() for n in security_notes(b)})


# ---------------------------------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------------------------------
def widened_params(policy: PolicyConfig, current: GraphParams) -> GraphParams:
    """Widen graph parameters one bounded step towards the policy ceiling (exhausts in max_replans-1 steps)."""
    gb = policy.graph_bounds
    divisor = max(1, policy.budgets.max_replans - 1)

    def _step(rng_max: int, rng_default: int) -> int:
        return max(1, ceil((rng_max - rng_default) / divisor))

    return GraphParams(
        time_window_days=min(
            gb.time_window_days.max,
            current.time_window_days + _step(gb.time_window_days.max, gb.time_window_days.default),
        ),
        max_hops=min(gb.max_hops.max, current.max_hops + _step(gb.max_hops.max, gb.max_hops.default)),
        amount_tolerance=min(
            gb.amount_tolerance.max,
            to_ratio(current.amount_tolerance + (gb.amount_tolerance.max - gb.amount_tolerance.default) / divisor),
        ),
        min_intermediaries=current.min_intermediaries,
    )


def _c2_handoffs(budget: int) -> list[SpecialistHandOff]:
    return [
        SpecialistHandOff(
            task_id="HO-FLOW",
            target_agent="flow_tracer",
            objective="Bounded MultiDiGraph traversal & Decimal conservation",
            allowed_tool_budget=max(2, budget // 3),
        ),
        SpecialistHandOff(
            task_id="HO-BENIGN",
            target_agent="benign_investigator",
            objective="KYC & commercial registry verification across network",
            allowed_tool_budget=max(4, budget // 2),
        ),
        SpecialistHandOff(
            task_id="HO-REG",
            target_agent="regulatory_analyst",
            objective="Hybrid RAG PMLA/RBI/FIU-IND clause retrieval",
            allowed_tool_budget=2,
        ),
        SpecialistHandOff(
            task_id="HO-CRITIC",
            target_agent="reporter_critic",
            objective="Fail-closed verification & SHA-256 worksheet draft",
            allowed_tool_budget=2,
        ),
    ]


def _default_steps(ctx: RunContext, typology_name: str) -> list[str]:
    if ctx.mode == "c2_multi":
        return [
            f"1. [Supervisor -> Flow Tracer] Bounded graph scan for {typology_name}",
            "2. [Supervisor -> Benign Investigator] Verify KYC and commercial registry for benign look-alikes",
            "3. [Supervisor -> Regulatory Analyst] Retrieve PMLA/RBI/FIU-IND clauses",
            "4. [Supervisor] Weigh suspicious vs benign hypotheses; replan if evidence contradicts",
            "5. [Supervisor -> Reporter & Critic] Deterministic verification and SHA-256 worksheet draft",
        ]
    return [
        f"1. Retrieve alert context and seed transactions for {typology_name} (bank-records)",
        "2. Run bounded graph scan via graph-engine (Decimal conservation)",
        "3. Verify KYC profiles and commercial registry for benign look-alikes",
        "4. Retrieve PMLA/RBI/FIU-IND regulatory clauses via compliance-kb",
        "5. Test competing suspicious vs benign hypotheses and replan if contradicted",
        "6. Verify arithmetic/citations and draft the SHA-256 disposition worksheet",
    ]


async def plan_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    spec = typology_registry.get("scatter_gather")
    typology_name = spec.name if spec else "Scatter-Gather"
    lessons: list[str] = []
    if ctx.reflexion_enabled and ctx.memory_enabled:
        top = memory_store.retrieve_top_lessons(f"{state.alert.rule_name} scatter gather", top_k=3)
        lessons = [f"[{les.lesson_id}] IF {les.trigger_precondition} THEN {les.actionable_rule}" for les in top]
    seeded = state.model_copy(update={"retrieved_lessons": lessons})

    params = GraphParams(**spec.default_graph_params) if spec else GraphParams.policy_default()
    if any("14-30" in lesson for lesson in lessons):
        params = widened_params(ctx.policy, params)
    steps = _default_steps(ctx, typology_name)
    degraded: list[str] = []
    mode = "default"

    proposal, meta = await reasoning.propose_plan(
        seeded,
        ctx.policy,
        ctx.ledger,
        role="c2_supervisor" if ctx.strong else "c1_investigator",
        strong=ctx.strong,
        tools=TOOL_CAPABILITIES,
    )
    if proposal is not None:
        proposed, violations = proposal.graph_params.to_params(ctx.policy)
        if proposed is None:
            degraded.append(
                f"LLM plan parameters rejected by policy bounds ({'; '.join(violations)}); policy defaults used"
            )
        else:
            params, mode = proposed, "llm"
        steps = [reasoning.safe_text(s, f"{i + 1}. (step withheld by guardrail)") for i, s in enumerate(proposal.steps)]
    elif meta.used_live_llm:
        degraded.append(f"LLM planning unavailable ({meta.error or 'budget'}); default plan used")

    plan = InvestigationPlan(steps=steps, graph_params=params)
    handoffs = (
        [h.model_dump(mode="json") for h in _c2_handoffs(ctx.policy.budgets.max_tool_calls)] if ctx.parallel else []
    )
    msgs, summary = trim_messages_with_summary(
        [
            *state.messages,
            {"role": "assistant", "content": f"Plan ({mode}) with params {params.model_dump(mode='json')}"},
        ],
        state.rolling_summary,
        window_size=ctx.policy.memory.short_term_window_messages,
    )
    return {
        "plan": plan,
        "retrieved_lessons": lessons,
        "degraded_evidence": degraded,
        "specialist_handoffs": handoffs,
        "messages": msgs,
        "rolling_summary": summary,
        "current_node": "plan",
        "current_step": state.current_step + 1,
        **_sync_budget(ctx),
    }


# ---------------------------------------------------------------------------------------------------
# Evidence gathering
# ---------------------------------------------------------------------------------------------------
async def _identity(
    ctx: RunContext,
    state: InvestigationState,
    root: str,
    network: list[str],
    registry: dict[str, Any],
    degraded: list[str],
) -> list[dict[str, Any]]:
    if state.kyc_profiles:
        return list(state.kyc_profiles)
    box = ctx.box("benign_investigator")
    profiles: list[dict[str, Any]] = []
    for acc in [root, *network[:3]]:
        kyc = await box.call("bank-records", "get_kyc_profile", {"account_id": acc})
        if is_error(kyc):
            degraded.append(f"KYC unavailable for {acc}: {_err(kyc)}")
            continue
        registry[kyc.get("evidence_id", f"KYC-{acc}")] = kyc
        reg = await box.call(
            "bank-records",
            "check_commercial_registry",
            {"entity_name": unwrap_untrusted_data(str(kyc.get("entity_name", acc))), "account_id": acc},
        )
        if is_error(reg):
            degraded.append(f"Commercial registry unavailable for {acc}: {_err(reg)}")
        elif reg.get("evidence_id"):
            registry[reg["evidence_id"]] = reg
            kyc["registry_check"] = reg
        profiles.append(kyc)
    return profiles


async def _regulatory(
    ctx: RunContext, state: InvestigationState, registry: dict[str, Any], degraded: list[str]
) -> tuple[list[dict[str, Any]], list[str]]:
    if state.regulatory_clauses:
        return list(state.regulatory_clauses), list(state.regulatory_snippets)
    res = await ctx.box("regulatory_analyst").call(
        "compliance-kb",
        "search_regulations",
        {
            "query": "scatter gather staggered layering fee skimming and commercial registry benign verification",
            "top_k": 5,
            "decompose": True,
        },
    )
    if is_error(res):
        degraded.append(f"Regulatory retrieval unavailable: {_err(res)}")
        return [], []
    clauses = [c for c in res.get("clauses", []) if isinstance(c, dict) and c.get("clause_id")]
    snippets: list[str] = []
    for clause in clauses:
        registry[clause["clause_id"]] = clause
        snippets.append(f"[{clause['clause_id']}] {clause.get('title', '')}: {clause.get('text', '')}")
    return clauses, snippets


async def _enrich_graph_evidence(
    ctx: RunContext,
    flow_box: GuardedToolbox,
    graph_result: dict[str, Any],
    paths: list[FundFlowPath],
    params: GraphParams,
    registry: dict[str, Any],
) -> None:
    """Invoke conservation & replan-comparison MCP tools when multi-hop paths exist and budget permits."""
    multi = [p for p in paths if p.hop_count >= 2]
    max_calls = ctx.policy.budgets.max_tool_calls
    if multi and ctx.ledger.calls_used + 2 <= max_calls:
        cons = await flow_box.call(
            "graph-engine",
            "compute_flow_conservation",
            {
                "paths": [p.model_dump(mode="json") for p in multi[:3]],
                "amount_tolerance": str(params.amount_tolerance),
            },
        )
        if not is_error(cons):
            registry[f"{graph_result['calc_id']}-CONS"] = cons
    if multi and ctx.last_graph_output and ctx.ledger.calls_used + 2 <= max_calls:
        diff = await flow_box.call(
            "graph-engine", "compare_graph_runs", {"run_a": ctx.last_graph_output, "run_b": graph_result}
        )
        if not is_error(diff):
            registry[f"{graph_result['calc_id']}-DIFF"] = diff
    ctx.last_graph_output = graph_result


def _build_specialist_findings(
    ctx: RunContext, paths: list[FundFlowPath], profiles: list[dict[str, Any]], clauses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not ctx.parallel:
        return []
    multi = sum(1 for p in paths if p.hop_count >= 2)
    replan_hint = {"expand_window": True} if not multi else None
    items = [
        SpecialistFinding(
            task_id="HO-FLOW",
            agent_name="flow_tracer",
            summary=f"Reconstructed {len(paths)} path(s) ({multi} multi-hop)",
            tool_calls=ctx.box("flow_tracer").calls,
            evidence_ids_added=[p.path_id for p in paths],
            recommended_replan=replan_hint,
        ),
        SpecialistFinding(
            task_id="HO-BENIGN",
            agent_name="benign_investigator",
            summary=f"Verified {len(profiles)} KYC/registry record(s)",
            tool_calls=ctx.box("benign_investigator").calls,
            evidence_ids_added=[str(k.get("evidence_id", "")) for k in profiles if k.get("evidence_id")],
        ),
        SpecialistFinding(
            task_id="HO-REG",
            agent_name="regulatory_analyst",
            summary=f"Retrieved {len(clauses)} regulatory clause(s)",
            tool_calls=ctx.box("regulatory_analyst").calls,
            evidence_ids_added=[c["clause_id"] for c in clauses],
        ),
    ]
    return [f.model_dump(mode="json") for f in items]


async def gather_evidence_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    alert = state.alert
    registry = dict(state.evidence_registry)
    degraded = list(state.degraded_evidence)
    params = state.plan.graph_params if state.plan else GraphParams.policy_default()
    flow_box = ctx.box("flow_tracer")

    t0 = time.perf_counter()
    txs = state.transactions
    root, network = alert.root_account, list(alert.network_accounts)
    if not txs:
        alert_ctx = await flow_box.call("bank-records", "get_alert_context", {"alert_id": alert.alert_id})
        if is_error(alert_ctx):
            degraded = sorted({*degraded, f"Alert context unavailable: {_err(alert_ctx)}", *_all_security_notes(ctx)})
            return {
                "degraded_evidence": degraded,
                "current_node": "gather_evidence",
                "current_step": state.current_step + 1,
                **_sync_budget(ctx),
            }
        txs = alert_ctx.get("transactions", [])
        root = alert_ctx.get("root_account", root)
        network = list(alert_ctx.get("network_accounts", network))
        registry.update({t["tx_id"]: t for t in txs if t.get("tx_id")})

    graph_result = await flow_box.call(
        "graph-engine",
        "find_candidate_fund_flows",
        {"root_account": root, "transactions": graph_tx_payload(txs), **params.model_dump()},
    )
    paths: list[FundFlowPath] = []
    if is_error(graph_result):
        degraded.append(f"Graph analysis unavailable: {_err(graph_result)}")
    else:
        registry[graph_result["calc_id"]] = graph_result.get("graph_stats", {})
        paths = flow_paths_from_result(graph_result, limit=5)
        registry.update({p.path_id: p.model_dump(mode="json") for p in paths})
    ctx.timings["flow_ms"] = ctx.timings.get("flow_ms", 0.0) + (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    if ctx.parallel:
        profiles, (clauses, snippets) = await asyncio.gather(
            _identity(ctx, state, root, network, registry, degraded),
            _regulatory(ctx, state, registry, degraded),
        )
    else:
        profiles = await _identity(ctx, state, root, network, registry, degraded)
        clauses, snippets = await _regulatory(ctx, state, registry, degraded)
    if not is_error(graph_result):
        await _enrich_graph_evidence(ctx, flow_box, graph_result, paths, params, registry)
    ctx.timings["evidence_ms"] = ctx.timings.get("evidence_ms", 0.0) + (time.perf_counter() - t1) * 1000

    degraded = sorted({*degraded, *_all_security_notes(ctx)})
    msgs, summary = trim_messages_with_summary(
        [
            *state.messages,
            {"role": "tool", "content": f"Gathered {len(paths)} paths, {len(profiles)} KYC records"},
        ],
        state.rolling_summary,
        window_size=ctx.policy.memory.short_term_window_messages,
    )
    return {
        "transactions": txs,
        "fund_flow_paths": paths,
        "kyc_profiles": profiles,
        "regulatory_clauses": clauses,
        "regulatory_snippets": snippets,
        "evidence_registry": registry,
        "degraded_evidence": degraded,
        "specialist_findings": _build_specialist_findings(ctx, paths, profiles, clauses),
        "messages": msgs,
        "rolling_summary": summary,
        "current_node": "gather_evidence",
        "current_step": state.current_step + 1,
        **_sync_budget(ctx),
    }


# ---------------------------------------------------------------------------------------------------
# Competing hypotheses
# ---------------------------------------------------------------------------------------------------
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

    susp_conf, benign_conf = float(rubric.suspicious), float(rubric.benign)
    susp_expl = "Scatter-gather layering network across intermediaries"
    benign_expl = "Legitimate commercial, payroll, charitable, chit-fund, or merchant-settlement activity"
    susp_ids, benign_ids = list(path_ids), list(path_ids)
    mode = "rubric"

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
        **_sync_budget(ctx),
    }


# ---------------------------------------------------------------------------------------------------
# Critique + replan
# ---------------------------------------------------------------------------------------------------
async def critique_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    multi_hop = [p for p in state.fund_flow_paths if p.hop_count >= 2]
    root_kyc = state.kyc_profiles[0] if state.kyc_profiles else {}
    benign_cleared = is_registered(root_kyc) and str(root_kyc.get("risk_category", "")).lower() == "low"
    critiques: list[str] = []
    proposed: Optional[GraphParams] = None
    if state.transactions and not multi_hop and not benign_cleared:
        gb = ctx.policy.graph_bounds
        critiques.append(
            "Outbound dispersal legs present without multi-hop consolidation in current window; reconfigure "
            f"time_window_days and max_hops within policy bounds "
            f"[{gb.time_window_days.min}..{gb.time_window_days.max}d, {gb.max_hops.min}..{gb.max_hops.max} hops]."
        )
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
        "degraded_evidence": degraded,
        "current_node": "critique",
        "current_step": state.current_step + 1,
        **_sync_budget(ctx),
    }


def should_replan(state: InvestigationState, ctx: RunContext) -> Literal["replan", "draft"]:
    if not (ctx.replanning_enabled and state.critiques and state.replan_count < ctx.policy.budgets.max_replans):
        return "draft"
    if ctx.ledger.calls_used + 2 > ctx.policy.budgets.max_tool_calls:
        return "draft"
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
            **_sync_budget(ctx),
        }
    current = state.plan.graph_params if state.plan else GraphParams.policy_default()
    new_params = (
        state.proposed_params
        if state.proposed_params and state.proposed_params != current
        else widened_params(ctx.policy, current)
    )
    reason = " | ".join(state.critiques[-2:])
    new_plan = InvestigationPlan(
        steps=state.plan.steps if state.plan else [],
        graph_params=new_params,
        replan_count=state.replan_count + 1,
        replan_reason=reason,
    )
    return {
        "plan": new_plan,
        "replan_count": state.replan_count + 1,
        "critiques": [],
        "proposed_params": None,
        "current_node": "replan",
        "current_step": state.current_step + 1,
        **_sync_budget(ctx),
    }


# ---------------------------------------------------------------------------------------------------
# Draft + verify (fail-closed) and telemetry
# ---------------------------------------------------------------------------------------------------
def decide_disposition(
    hypotheses: list[Hypothesis], degraded: list[str], policy: PolicyConfig
) -> tuple[DispositionDecision, float]:
    susp = next((h.confidence for h in hypotheses if h.label == HypothesisLabel.SUSPICIOUS), 0.0)
    benign = next((h.confidence for h in hypotheses if h.label == HypothesisLabel.BENIGN), 0.0)
    value, confidence = decide(susp, benign, bool(degraded), policy.scoring)
    return DispositionDecision(value), confidence


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
        {
            "step": 5,
            "name": "Verification (Deterministic)",
            "status": "completed",
            "duration_ms": round(critic_ms, 1),
        },
        {"step": 6, "name": "Human Approval", "status": "waiting_approval"},
        {"step": 7, "name": "Case Commit & Reporting", "status": "pending"},
    ]
    now = utc_now_iso()
    if ctx.parallel:
        tw, mh = (state.plan.graph_params.time_window_days, state.plan.graph_params.max_hops) if state.plan else (0, 0)
        runs = [
            {
                "agent_id": "flow_tracer",
                "agent_name": "Flow Tracing Agent",
                "task": f"Graph traversal ({tw}d, {mh} hops) & Decimal conservation",
                "status": "completed",
                "started_at": now,
                "duration_ms": flow_ms,
                "tool_calls": ctx.box("flow_tracer").calls,
                "summary": (
                    f"Found {len(state.fund_flow_paths)} candidate paths "
                    f"({sum(1 for p in state.fund_flow_paths if p.hop_count >= 2)} multi-hop)"
                ),
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
                "summary": worksheet_summary,
            },
        ]
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
    degraded = sorted({*state.degraded_evidence, *_all_security_notes(ctx)})
    # Any prompt-injection detection on untrusted tool data forces request_info for human inspection
    has_security_flag = any(b.security_events for b in ctx.boxes.values())
    if has_security_flag or (not state.transactions and degraded):
        disposition = DispositionDecision.REQUEST_INFO
        confidence = float(ctx.policy.scoring.request_info_floor)
    else:
        disposition, confidence = decide_disposition(state.active_hypotheses, degraded, ctx.policy)
    citations = sorted({c for h in state.active_hypotheses for c in h.regulatory_citations})
    summaries = kyc_summaries(state.kyc_profiles, limit=5)
    box = ctx.box("reporter_critic")
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
        verify=ctx.deterministic_verifier,
    )
    critic_ms = (time.perf_counter() - t0) * 1000
    ws = outcome.worksheet
    findings = list(state.specialist_findings)
    if ctx.parallel:
        findings.append(
            SpecialistFinding(
                task_id="HO-CRITIC",
                agent_name="reporter_critic",
                summary=f"Drafted {ws.worksheet_id} ({ws.recommended_disposition.value})",
                tool_calls=box.calls,
                evidence_ids_added=[ws.worksheet_id],
            ).model_dump(mode="json")
        )
    flow_summary = compute_network_flow_summary(
        state.alert.root_account, state.transactions, state.fund_flow_paths, state.kyc_profiles
    )
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
        **_sync_budget(ctx),
        **_telemetry(
            state,
            ctx,
            ws.recommendation_rationale
            if ctx.mode != "c2_multi"
            else f"Drafted {ws.worksheet_id} ({ws.recommended_disposition.value})",
            critic_ms,
        ),
    }
