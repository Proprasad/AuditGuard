"""
Shared execution context, budget synchronization, playbook rule parsing, and `plan_node` for C1/C2.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal
from math import ceil
import os
import re
from typing import Any, Optional

from src.agent import reasoning
from src.agent.drafting import security_notes
from src.agent.llm_client import LlmCallMeta, get_model_for_role
from src.agent.tooling import GuardedToolbox
from src.core.canonical import to_ratio
from src.core.policy import BudgetLedger, PolicyConfig
from src.memory.store import memory_store, trim_messages_with_summary
from src.models import GraphParams, InvestigationPlan, InvestigationState, SpecialistFinding, SpecialistHandOff
from src.typology_registry import typology_registry

TOOL_CAPABILITIES = [
    "bank-records: alert context, account transactions, KYC profiles, commercial registry, counterparty history",
    "graph-engine: bounded fund-flow path search, Decimal conservation & replan run comparison",
    "compliance-kb: hybrid RAG search & exact clause lookup over PMLA / RBI / FIU-IND clauses",
]
_LESSON_PARAM_RE = re.compile(r"\b(time_window_days|max_hops|amount_tolerance)\b", re.IGNORECASE)


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
    configurable_graph: bool = True
    replanning_enabled: bool = True
    deterministic_verifier: bool = True
    allow_calc: bool = True
    allow_registry: bool = True
    allow_rag: bool = True
    defenses_enabled: bool = True
    reflexion_enabled: bool = False
    memory_enabled: bool = True
    allow_llm: bool = True
    llm_client: Optional[Any] = None
    llm_mode: Optional[str] = None
    run_id: Optional[str] = None
    cassette_path: Optional[str] = None
    model_override: Optional[str] = None
    strong_model_override: Optional[str] = None
    seed: Optional[int] = None
    emit: Optional[Callable[[str, dict[str, Any]], None]] = None
    timings: dict[str, float] = field(default_factory=dict)
    last_graph_output: Optional[dict[str, Any]] = None

    def box(self, name: str) -> GuardedToolbox:
        return self.boxes.get(name) or self.boxes["primary"]


def resolve_model_for_role(ctx: RunContext, role: str, *, strong: bool = False) -> str:
    """Resolve model slug: explicit override -> runtime DB flag (non-replay) -> policy default."""
    explicit = ctx.strong_model_override if (strong or role == "c2_supervisor") else ctx.model_override
    if explicit:
        return explicit
    raw_mode = (ctx.llm_mode or os.getenv("LLM_MODE") or "").strip().lower()
    if raw_mode != "replay":
        runtime_model = get_model_for_role(role, strong=strong)
        if ctx.policy.is_allowed_model(runtime_model):
            return runtime_model
    return ctx.policy.model_for(role).model_id


def all_tool_errors(ctx: RunContext) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for box in ctx.boxes.values():
        for err in box.tool_errors:
            key = (
                str(err.get("server", "")),
                str(err.get("tool", "")),
                str(err.get("error_code", "")),
                str(err.get("message", "")),
            )
            seen[key] = err
    return list(seen.values())


def tool_error_notes(ctx: RunContext) -> list[str]:
    return [
        f"Tool error [{e['server']}.{e['tool']}]: {e['error_code']}"
        for e in all_tool_errors(ctx)
    ]


def sync_budget(ctx: RunContext) -> dict[str, Any]:
    cap = ctx.policy.budgets.max_cost_usd_per_case
    errs = all_tool_errors(ctx)
    return {
        "tool_calls_used": ctx.ledger.calls_used,
        "tool_error_count": len(errs),
        "tool_errors": errs,
        "critique_retries_used": ctx.ledger.critique_retries_used,
        "total_tokens_used": ctx.ledger.tokens_used,
        "estimated_cost_usd": ctx.ledger.cost_usd,
        "budget_remaining_usd": max(Decimal("0"), cap - ctx.ledger.cost_usd),
    }


def err_code(res: dict[str, Any]) -> str:
    return str(res.get("error_code") or res.get("error"))


def all_security_notes(ctx: RunContext) -> list[str]:
    return sorted({n for b in ctx.boxes.values() for n in security_notes(b)})


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


def apply_playbook_lessons(policy: PolicyConfig, params: GraphParams, lessons: list[str]) -> GraphParams:
    """Apply approved Reflexion parameter directives without hardcoded substring magic."""
    if any(_LESSON_PARAM_RE.search(lesson) for lesson in lessons):
        return widened_params(policy, params)
    return params


def c2_handoffs(budget: int) -> list[SpecialistHandOff]:
    return [
        SpecialistHandOff(
            task_id="HO-FLOW",
            target_agent="flow_tracer",
            objective="Bounded MultiDiGraph traversal & Decimal conservation",
            allowed_tool_budget=max(2, (budget * 2) // 5),
        ),
        SpecialistHandOff(
            task_id="HO-BENIGN",
            target_agent="benign_investigator",
            objective="KYC, commercial registry & counterparty verification across network",
            allowed_tool_budget=max(2, (budget * 3) // 5),
        ),
        SpecialistHandOff(
            task_id="HO-REG",
            target_agent="regulatory_analyst",
            objective="Hybrid RAG PMLA/RBI/FIU-IND clause retrieval",
            allowed_tool_budget=max(1, budget // 5),
        ),
        SpecialistHandOff(
            task_id="HO-CRITIC",
            target_agent="reporter_critic",
            objective="Fail-closed verification & SHA-256 worksheet draft",
            allowed_tool_budget=2,
        ),
    ]


def handoff_for(state: InvestigationState, target: str) -> Optional[SpecialistHandOff]:
    for raw in state.specialist_handoffs:
        if isinstance(raw, dict) and raw.get("target_agent") == target:
            return SpecialistHandOff.model_validate(raw)
    return None


def upsert_finding(existing: list[dict[str, Any]], item: SpecialistFinding) -> list[dict[str, Any]]:
    by_task = {f["task_id"]: f for f in existing if isinstance(f, dict) and f.get("task_id")}
    by_task[item.task_id] = item.model_dump(mode="json")
    return list(by_task.values())


def _default_steps(ctx: RunContext, typology_name: str) -> list[str]:
    if ctx.mode == "c2_multi":
        return [
            f"1. [Supervisor -> Flow Tracer] Bounded graph scan for {typology_name}",
            "2. [Supervisor -> Benign Investigator] Verify KYC, registry & counterparty history",
            "3. [Supervisor -> Regulatory Analyst] Retrieve PMLA/RBI/FIU-IND clauses",
            "4. [Supervisor] Weigh suspicious vs benign hypotheses; replan if evidence contradicts",
            "5. [Supervisor -> Reporter & Critic] Deterministic verification and SHA-256 worksheet draft",
        ]
    return [
        f"1. Retrieve alert context and seed transactions for {typology_name} (bank-records)",
        "2. Run bounded graph scan via graph-engine (Decimal conservation)",
        "3. Verify KYC profiles, commercial registry & counterparty context",
        "4. Retrieve PMLA/RBI/FIU-IND regulatory clauses via compliance-kb",
        "5. Test competing suspicious vs benign hypotheses and replan if contradicted",
        "6. Verify arithmetic/citations and draft the SHA-256 disposition worksheet",
    ]


async def plan_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    spec = typology_registry.get("scatter_gather")
    typology_name = spec.name if spec else "Scatter-Gather"
    lessons: list[str] = []
    if ctx.reflexion_enabled and ctx.memory_enabled:
        top = await asyncio.to_thread(memory_store.retrieve_top_lessons, f"{state.alert.rule_name} scatter gather", 3)
        lessons = [f"[{les.lesson_id}] IF {les.trigger_precondition} THEN {les.actionable_rule}" for les in top]
    seeded = state.model_copy(update={"retrieved_lessons": lessons})

    base_params = GraphParams(**spec.default_graph_params) if spec else GraphParams.policy_default()
    params = apply_playbook_lessons(ctx.policy, base_params, lessons)
    steps = _default_steps(ctx, typology_name)
    focus_accounts: list[str] = []
    reg_queries: list[str] = []
    clause_ids: list[str] = []
    degraded: list[str] = []
    mode = "default"

    proposal = None
    meta = LlmCallMeta(used_live_llm=False, model="offline")
    if ctx.allow_llm:
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
        focus_accounts = [reasoning.safe_text(a, "") for a in proposal.focus_accounts if a]
        reg_queries = [reasoning.safe_text(q, "") for q in proposal.regulatory_queries if q]
        clause_ids = [reasoning.safe_text(c, "") for c in proposal.clause_ids if c]
    elif meta.used_live_llm:
        degraded.append(f"LLM planning unavailable ({meta.error or 'budget'}); default plan used")

    if not ctx.configurable_graph:
        params = GraphParams.policy_default()
        mode = "fixed_detector"

    plan = InvestigationPlan(
        steps=steps,
        graph_params=params,
        focus_accounts=[a for a in focus_accounts if a],
        regulatory_queries=[q for q in reg_queries if q],
        clause_ids=[c for c in clause_ids if c],
    )
    handoffs = (
        [h.model_dump(mode="json") for h in c2_handoffs(ctx.policy.budgets.max_tool_calls)] if ctx.parallel else []
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
        **sync_budget(ctx),
    }
