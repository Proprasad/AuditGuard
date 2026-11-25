"""
C2 Supervisor Dynamic Routing & Budget Allocation (`src/agent/c2_routing.py`).

Validates supervisor-proposed specialist plans while enforcing:
  * Mandatory coverage across all 4 specialist responsibilities (`flow_tracer`,
    `benign_investigator`, `regulatory_analyst`, `reporter_critic`).
  * Per-specialist RBAC `permitted_tools` derived strictly from `AGENT_TOOL_ALLOWLIST`.
  * Global `BudgetLedger` safety reserving capacity for mandatory critique & verification.
"""

from __future__ import annotations

from typing import Any, cast

from src.agent.planning import c2_handoffs
from src.core.investigation_contracts import SpecialistRole, SupervisorRoutingPlan
from src.guardrails.hooks import AGENT_TOOL_ALLOWLIST
from src.models import SpecialistHandOff

MANDATORY_ROLES: tuple[SpecialistRole, ...] = (
    "flow_tracer",
    "benign_investigator",
    "regulatory_analyst",
    "reporter_critic",
)
_DEFAULT_EXPECTED: dict[str, list[str]] = {
    "flow_tracer": ["reconstructed_paths", "flow_conservation", "graph_stats"],
    "benign_investigator": ["kyc_profiles", "commercial_registry", "counterparty_history"],
    "regulatory_analyst": ["verified_regulatory_clauses", "applicability_mapping"],
    "reporter_critic": ["independent_critique", "verified_disposition_worksheet"],
}
_DEFAULT_DEPS: dict[str, list[str]] = {
    "flow_tracer": [],
    "benign_investigator": ["flow_tracer"],
    "regulatory_analyst": ["flow_tracer"],
    "reporter_critic": ["flow_tracer", "benign_investigator", "regulatory_analyst"],
}


def _allocate_budgets(
    by_role: dict[str, SpecialistHandOff], max_calls: int, reserved_critic: int, *, is_replay: bool
) -> dict[str, int]:
    if is_replay:
        return {role: max(1, min(by_role[role].allowed_tool_budget, max_calls - 1)) for role in MANDATORY_ROLES}
    invest_pool = max(3, max_calls - reserved_critic)
    inv_roles: tuple[SpecialistRole, ...] = ("flow_tracer", "benign_investigator", "regulatory_analyst")
    raw_total = sum(max(1, by_role[r].allowed_tool_budget) for r in inv_roles)
    clamped: dict[str, int] = {}
    remaining = invest_pool
    for idx, role in enumerate(inv_roles):
        req = max(1, by_role[role].allowed_tool_budget)
        if raw_total <= invest_pool:
            alloc = req
        else:
            slots_left = len(inv_roles) - idx - 1
            scaled = max(1, (req * invest_pool) // raw_total)
            alloc = max(1, min(scaled, remaining - slots_left))
        clamped[role] = alloc
        remaining = max(0, remaining - alloc)
    critic_req = by_role["reporter_critic"].allowed_tool_budget
    clamped["reporter_critic"] = max(2, min(critic_req, reserved_critic))
    return clamped


def _resolve_execution_order(raw_order: Any) -> list[list[SpecialistRole]]:
    default_order: list[list[SpecialistRole]] = [
        ["flow_tracer"],
        ["benign_investigator", "regulatory_analyst"],
        ["reporter_critic"],
    ]
    if not isinstance(raw_order, list) or not raw_order:
        return default_order
    stages: list[list[SpecialistRole]] = []
    seen: set[str] = set()
    for stage in raw_order:
        items = stage if isinstance(stage, list) else [stage]
        valid = [cast(SpecialistRole, r) for r in items if r in MANDATORY_ROLES and r not in seen]
        if valid:
            stages.append(valid)
            seen.update(valid)
    for missing in (r for r in MANDATORY_ROLES if r not in seen):
        if missing == "reporter_critic":
            stages.append([missing])
        else:
            stages.insert(max(0, len(stages) - 1), [missing])
    return stages or default_order


def build_routing_plan(
    raw_plan: dict[str, Any] | None,
    handoffs_list: list[SpecialistHandOff],
    max_calls: int,
    *,
    is_replay: bool = False,
) -> tuple[SupervisorRoutingPlan, dict[str, SpecialistHandOff]]:
    """Build validated `SupervisorRoutingPlan` & budget-safe `SpecialistHandOff`s."""
    reserved_critic = max(2, min(3, max_calls // 5))
    base_by_role = {h.target_agent: h for h in c2_handoffs(max_calls)}
    raw_rationale = dict((raw_plan or {}).get("selection_rationale") or {})
    raw_deps = dict((raw_plan or {}).get("dependencies") or {})

    by_role: dict[str, SpecialistHandOff] = {h.target_agent: h for h in handoffs_list if h.target_agent in base_by_role}
    for role in MANDATORY_ROLES:
        if role not in by_role:
            rat = str(raw_rationale.get(role) or f"Mandatory coverage invariant enforced for {role}")
            by_role[role] = base_by_role[role].model_copy(update={"selection_rationale": rat})

    budgets = _allocate_budgets(by_role, max_calls, reserved_critic, is_replay=is_replay)
    enriched: dict[str, SpecialistHandOff] = {}
    rationale_map: dict[str, str] = {}
    deps_map: dict[str, list[str]] = {}

    for role in MANDATORY_ROLES:
        ho = by_role[role]
        deps = [str(d) for d in (ho.dependencies or raw_deps.get(role) or _DEFAULT_DEPS[role])]
        rat = ho.selection_rationale or str(raw_rationale.get(role) or f"Assigned {role} for {ho.objective[:80]}")
        rationale_map[role] = rat
        deps_map[role] = deps
        enriched[role] = ho.model_copy(
            update={
                "allowed_tool_budget": budgets[role],
                "selection_rationale": rat,
                "dependencies": deps,
                "permitted_tools": sorted(AGENT_TOOL_ALLOWLIST.get(role, set())),
                "expected_outputs": ho.expected_outputs or _DEFAULT_EXPECTED[role],
                "completion_condition": ho.completion_condition or f"Evidence-grounded summary with {role} outputs",
                "replan_triggers": ho.replan_triggers
                or (["no_multi_hop_paths_in_initial_window"] if role == "flow_tracer" else []),
                "parallel_group": ho.parallel_group
                or ("stage_2_parallel" if role in ("benign_investigator", "regulatory_analyst") else role),
            }
        )

    plan = SupervisorRoutingPlan(
        selected_specialists=list(MANDATORY_ROLES),
        execution_order=_resolve_execution_order((raw_plan or {}).get("execution_order")),
        selection_rationale=rationale_map,
        dependencies=deps_map,
        completion_conditions=[str(x) for x in ((raw_plan or {}).get("completion_conditions") or []) if x]
        or [
            "Suspicious fund-flow topology reconstructed with Decimal conservation",
            "Benign commercial/payroll/charity explanations evaluated with KYC and registry checks",
            "Applicable PMLA/RBI/FIU-IND regulatory clauses retrieved",
            "Independent critique and Verifier v2 passed before human_gate",
        ],
        replan_conditions=[str(x) for x in ((raw_plan or {}).get("replan_conditions") or []) if x]
        or [
            "Outbound transfers found with zero multi-hop consolidation in initial window",
            "Contradictory KYC/registry evidence requires wider graph verification",
        ],
        reserved_critic_budget=reserved_critic,
        mandatory_coverage_verified=set(MANDATORY_ROLES) <= set(enriched.keys()),
    )
    return plan, enriched
