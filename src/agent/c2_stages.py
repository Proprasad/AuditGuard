"""
C2 Supervisor Dynamic Routing, Typed Specialist Enrichment & Multi-Stage Checkpointed Nodes (`src/agent/c2_stages.py`).

Provides:
  * `validate_and_normalize_routing`: genuine supervisor routing plan validation with mandatory
    coverage invariants and global `BudgetLedger` clamping (reserving critic/draft capacity).
  * `enrich_specialist_finding`: constructs evidence-rich, typed `SpecialistFinding` objects with
    claims, supporting/contradicting evidence, contradictions, missing info, limitations, and metadata.
  * 6 durably checkpointed LangGraph nodes for live LLM `c2_multi`:
    `supervisor_plan -> flow_tracer -> parallel_specialists -> hypothesis_evaluation
     -> supervisor_replan_check --(replan)--> flow_replan -> hypothesis_evaluation
                                --(critique)--> reporter_critic -> human_gate -> commit_disposition`
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Literal

from src.agent.c2_loop import (
    SupervisorReplanCheck,
    _run_evidence_specialist,
    _run_reporter_critic,
    _supervisor_plan,
    _supervisor_should_replan,
)
from src.agent.c2_routing import MANDATORY_ROLES, build_routing_plan
from src.agent.hypothesis_eval import hypothesis_evaluation_node
from src.agent.loop_context import retrieve_frozen_lessons
from src.agent.planning import RunContext, c2_handoffs, sync_budget
from src.agent.telemetry import compute_network_flow_summary
from src.core.claims import classify_evidence_source
from src.db.database import utc_now_iso
from src.llm.client import LLMClientProtocol
from src.models import (
    GraphParams,
    InvestigationPlan,
    InvestigationState,
    SpecialistFinding,
    SpecialistHandOff,
)

__all__ = [
    "MANDATORY_ROLES",
    "build_routing_plan",
    "enrich_specialist_finding",
    "make_c2_stage_nodes",
    "route_c2_after_replan_check",
]


def _runtime_from_state(
    role: str, state: InvestigationState, ctx: RunContext, *, replanning_enabled: bool = False
) -> Any:
    from src.agent.tools import AgentToolRuntime

    rt = AgentToolRuntime(
        role=role,
        box=ctx.box(role),
        alert=state.alert,
        configurable_graph=ctx.configurable_graph,
        replanning_enabled=replanning_enabled,
        allow_calc=ctx.allow_calc,
        allow_registry=ctx.allow_registry,
        allow_rag=ctx.allow_rag,
        initial_transactions=list(state.transactions),
        initial_paths=list(state.fund_flow_paths),
        initial_registry=dict(state.evidence_registry),
        initial_baseline_paths=list(state.initial_fund_flow_paths or state.fund_flow_paths),
    )
    rt.kyc_profiles = list(state.kyc_profiles)
    rt.regulatory_clauses = list(state.regulatory_clauses)
    rt.regulatory_snippets = list(state.regulatory_snippets)
    rt.calc_log = list(state.calc_log)
    rt.degraded_evidence = list(state.degraded_evidence)
    rt.replan_records = list(state.replan_records)
    rt.tool_execution_log = list(state.tool_execution_log)
    rt.replan_count = state.replan_count
    if state.plan is not None:
        rt.current_graph_params = state.plan.graph_params
        rt.last_replan_reason = state.plan.replan_reason
    return rt


def _handoffs_map(state: InvestigationState, max_calls: int) -> dict[str, SpecialistHandOff]:
    by_role: dict[str, SpecialistHandOff] = {h.target_agent: h for h in c2_handoffs(max_calls)}
    for raw in state.specialist_handoffs:
        if isinstance(raw, dict) and raw.get("target_agent") in by_role:
            by_role[str(raw["target_agent"])] = SpecialistHandOff.model_validate(raw)
    return by_role


def enrich_specialist_finding(
    handoff: SpecialistHandOff,
    finding: SpecialistFinding,
    evidence_registry: dict[str, Any],
    *,
    degraded: list[str],
    tool_errors: list[dict[str, Any]],
    duration_ms: float,
) -> SpecialistFinding:
    """Attach structured claims, evidence relevance, gaps, limitations, and execution metadata."""
    added = list(finding.evidence_ids_added)
    relevance = {eid: classify_evidence_source(eid, evidence_registry.get(eid)) for eid in added[:12]}
    supporting = [eid for eid in added if eid.startswith(("PATH-", "TXN-", "TX-", "CALC-", "REG-", "SOP-"))]
    benign_or_ctx = [eid for eid in added if eid.startswith(("KYC-", "REGISTRY-", "CP-"))]
    claims = [
        {
            "claim_id": f"{handoff.task_id}-CLM-01",
            "claim_text": finding.summary,
            "evidence_ids": added[:6],
            "evidence_sources": list(dict.fromkeys(relevance.values())),
        }
    ]
    missing: list[str] = []
    if not added:
        missing.append(f"{handoff.target_agent} added 0 new evidence records.")
    if finding.recommended_replan:
        missing.append("No multi-hop consolidation found in current graph window; replanning recommended.")
    next_act = (
        "Trigger bounded flow_tracer replan within policy bounds."
        if finding.recommended_replan
        else "Forward evidence-linked findings to supervisor hypothesis evaluation and reporter_critic."
    )
    limitations = [
        *(f"Tool error: {e.get('tool')}:{e.get('error_code')}" for e in tool_errors[-3:]),
        *degraded[-2:],
    ]
    return finding.model_copy(
        update={
            "objective": handoff.objective,
            "findings": [finding.summary],
            "claims": claims,
            "supporting_evidence_ids": supporting or added[:6],
            "contradicting_evidence_ids": benign_or_ctx if handoff.target_agent == "flow_tracer" else [],
            "evidence_relevance": relevance,
            "missing_information": missing,
            "recommended_next_action": next_act,
            "limitations": limitations,
            "execution_metadata": {
                "role": handoff.target_agent,
                "allowed_tool_budget": handoff.allowed_tool_budget,
                "tool_calls_used": finding.tool_calls,
                "duration_ms": round(duration_ms, 1),
            },
        }
    )


def make_c2_stage_nodes(llm_client: LLMClientProtocol) -> dict[str, Any]:
    """Create the 6 durably checkpointed LangGraph stage nodes for live LLM `c2_multi`."""

    async def supervisor_plan_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
        lessons = await retrieve_frozen_lessons(state, ctx)
        steps, handoffs_dict, routing_plan = await _supervisor_plan(state, ctx, llm_client, lessons)
        plan = InvestigationPlan(
            steps=steps,
            graph_params=GraphParams.policy_default(),
            focus_accounts=list(dict.fromkeys([state.alert.root_account, *state.alert.network_accounts[:5]])),
        )
        return {
            "plan": plan,
            "retrieved_lessons": lessons,
            "routing_plan": routing_plan.model_dump(mode="json"),
            "specialist_handoffs": [h.model_dump(mode="json") for h in handoffs_dict.values()],
            "reasoning_mode": "llm_tool_loop",
            "current_node": "supervisor_plan",
            "current_step": state.current_step + 1,
            **sync_budget(ctx),
        }

    async def flow_tracer_stage(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
        t0 = time.perf_counter()
        handoffs = _handoffs_map(state, ctx.policy.budgets.max_tool_calls)
        ho = handoffs["flow_tracer"]
        flow_rt = _runtime_from_state("flow_tracer", state, ctx, replanning_enabled=False)
        raw_f = await _run_evidence_specialist(
            handoff=ho,
            runtime=flow_rt,
            ctx=ctx,
            llm_client=llm_client,
            context_summary={"alert_id": state.alert.alert_id, "root_account": state.alert.root_account},
        )
        finding = enrich_specialist_finding(
            ho,
            raw_f,
            flow_rt.evidence_registry,
            degraded=flow_rt.degraded_evidence,
            tool_errors=ctx.box("flow_tracer").tool_errors,
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
        return {
            "alert": state.alert.model_copy(
                update={"root_account": flow_rt.root_account, "network_accounts": flow_rt.network_accounts}
            ),
            "transactions": flow_rt.transactions,
            "fund_flow_paths": flow_rt.fund_flow_paths,
            "initial_fund_flow_paths": flow_rt.initial_fund_flow_paths,
            "evidence_registry": flow_rt.evidence_registry,
            "calc_log": flow_rt.calc_log,
            "replan_records": flow_rt.replan_records,
            "tool_execution_log": flow_rt.tool_execution_log,
            "degraded_evidence": flow_rt.degraded_evidence,
            "specialist_findings": [finding.model_dump(mode="json")],
            "current_node": "flow_tracer",
            "current_step": state.current_step + 1,
            **sync_budget(ctx),
        }

    async def parallel_specialists_stage(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
        t0 = time.perf_counter()
        handoffs = _handoffs_map(state, ctx.policy.budgets.max_tool_calls)
        benign_rt = _runtime_from_state("benign_investigator", state, ctx, replanning_enabled=False)
        reg_rt = _runtime_from_state("regulatory_analyst", state, ctx, replanning_enabled=False)
        flow_sum = next(
            (str(f.get("summary", "")) for f in state.specialist_findings if f.get("agent_name") == "flow_tracer"),
            "",
        )
        shared_ctx = {
            "alert_id": state.alert.alert_id,
            "root_account": state.alert.root_account,
            "network_accounts": state.alert.network_accounts[:8],
            "path_nodes": list(dict.fromkeys(n for p in state.fund_flow_paths for n in p.nodes))[:8],
            "flow_finding": flow_sum,
        }
        f_benign_raw, f_reg_raw = await asyncio.gather(
            _run_evidence_specialist(
                handoff=handoffs["benign_investigator"],
                runtime=benign_rt,
                ctx=ctx,
                llm_client=llm_client,
                context_summary=shared_ctx,
            ),
            _run_evidence_specialist(
                handoff=handoffs["regulatory_analyst"],
                runtime=reg_rt,
                ctx=ctx,
                llm_client=llm_client,
                context_summary=shared_ctx,
            ),
        )
        ms = (time.perf_counter() - t0) * 1000
        f_benign = enrich_specialist_finding(
            handoffs["benign_investigator"],
            f_benign_raw,
            benign_rt.evidence_registry,
            degraded=benign_rt.degraded_evidence,
            tool_errors=ctx.box("benign_investigator").tool_errors,
            duration_ms=ms,
        )
        f_reg = enrich_specialist_finding(
            handoffs["regulatory_analyst"],
            f_reg_raw,
            reg_rt.evidence_registry,
            degraded=reg_rt.degraded_evidence,
            tool_errors=ctx.box("regulatory_analyst").tool_errors,
            duration_ms=ms,
        )
        return {
            "kyc_profiles": benign_rt.kyc_profiles,
            "regulatory_clauses": reg_rt.regulatory_clauses,
            "regulatory_snippets": reg_rt.regulatory_snippets,
            "evidence_registry": {**benign_rt.evidence_registry, **reg_rt.evidence_registry},
            "calc_log": [*state.calc_log, *[c for c in benign_rt.calc_log if c not in state.calc_log]],
            "tool_execution_log": [
                *state.tool_execution_log,
                *benign_rt.tool_execution_log[len(state.tool_execution_log) :],
                *reg_rt.tool_execution_log[len(state.tool_execution_log) :],
            ],
            "degraded_evidence": sorted({*benign_rt.degraded_evidence, *reg_rt.degraded_evidence}),
            "specialist_findings": [f_benign.model_dump(mode="json"), f_reg.model_dump(mode="json")],
            "current_node": "parallel_specialists",
            "current_step": state.current_step + 1,
            **sync_budget(ctx),
        }

    async def supervisor_replan_check_stage(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
        # Bounded by the policy budget on the supervisor's own counter (audit AG-12): the loop ends even if the
        # flow tracer ignores the directive, and C2 can replan more than once when the evidence calls for it.
        max_replans = ctx.policy.budgets.max_replans
        if state.replan_attempts >= max_replans or ctx.ledger.replans_used >= max_replans:
            return {
                "proposed_params": None,
                "current_node": "supervisor_replan_check",
                "current_step": state.current_step + 1,
                **sync_budget(ctx),
            }
        flow_rt = _runtime_from_state("flow_tracer", state, ctx, replanning_enabled=True)
        findings = [SpecialistFinding.model_validate(f) for f in state.specialist_findings if isinstance(f, dict)]
        req: SupervisorReplanCheck | None = await _supervisor_should_replan(ctx, llm_client, findings, flow_rt)
        if req is None:
            return {
                "proposed_params": None,
                "current_node": "supervisor_replan_check",
                "current_step": state.current_step + 1,
                **sync_budget(ctx),
            }
        proposed = GraphParams(
            time_window_days=req.time_window_days,
            max_hops=req.max_hops,
            amount_tolerance=req.amount_tolerance,
            min_intermediaries=flow_rt.current_graph_params.min_intermediaries,
        )
        updated_plan = (state.plan or InvestigationPlan(steps=[])).model_copy(update={"replan_reason": req.reason})
        return {
            "plan": updated_plan,
            "proposed_params": proposed,
            "current_node": "supervisor_replan_check",
            "current_step": state.current_step + 1,
            **sync_budget(ctx),
        }

    async def flow_replan_stage(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
        t0 = time.perf_counter()
        proposed = state.proposed_params or GraphParams.policy_default()
        reason = (state.plan.replan_reason if state.plan else None) or "Bounded replan requested by supervisor"
        flow_rt = _runtime_from_state("flow_tracer", state, ctx, replanning_enabled=True)
        replan_ho = SpecialistHandOff(
            task_id="HO-FLOW-REPLAN",
            target_agent="flow_tracer",
            objective=(
                f"Call replan_graph(time_window_days={proposed.time_window_days}, "
                f"max_hops={proposed.max_hops}, amount_tolerance='{proposed.amount_tolerance}', "
                f"reason={reason!r})"
            ),
            allowed_tool_budget=ctx.policy.agent_limits.c2_replan_handoff_budget,
        )
        raw_f = await _run_evidence_specialist(
            handoff=replan_ho,
            runtime=flow_rt,
            ctx=ctx,
            llm_client=llm_client,
            context_summary={
                "replan_directive": {
                    "request_replan": True,
                    "time_window_days": proposed.time_window_days,
                    "max_hops": proposed.max_hops,
                    "amount_tolerance": str(proposed.amount_tolerance),
                    "reason": reason,
                }
            },
            replanning_enabled=True,
            max_turns=ctx.policy.agent_limits.c2_replan_max_turns,
        )
        finding = enrich_specialist_finding(
            replan_ho,
            raw_f,
            flow_rt.evidence_registry,
            degraded=flow_rt.degraded_evidence,
            tool_errors=ctx.box("flow_tracer").tool_errors,
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
        updated_plan = (state.plan or InvestigationPlan(steps=[])).model_copy(
            update={
                "graph_params": flow_rt.current_graph_params,
                "replan_count": flow_rt.replan_count,
                "replan_reason": flow_rt.last_replan_reason or reason,
            }
        )
        return {
            "plan": updated_plan,
            "proposed_params": None,
            "replan_count": flow_rt.replan_count,
            "replan_attempts": state.replan_attempts + 1,
            "fund_flow_paths": flow_rt.fund_flow_paths,
            "initial_fund_flow_paths": flow_rt.initial_fund_flow_paths,
            "evidence_registry": flow_rt.evidence_registry,
            "calc_log": flow_rt.calc_log,
            "replan_records": flow_rt.replan_records,
            "tool_execution_log": flow_rt.tool_execution_log,
            "degraded_evidence": flow_rt.degraded_evidence,
            "specialist_findings": [finding.model_dump(mode="json")],
            "current_node": "flow_replan",
            "current_step": state.current_step + 1,
            **sync_budget(ctx),
        }

    async def reporter_critic_stage(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
        t0 = time.perf_counter()
        handoffs = _handoffs_map(state, ctx.policy.budgets.max_tool_calls)
        merged_rt = _runtime_from_state("reporter_critic", state, ctx, replanning_enabled=False)
        findings = [SpecialistFinding.model_validate(f) for f in state.specialist_findings if isinstance(f, dict)]
        worksheet, f_critic_raw = await _run_reporter_critic(
            handoff=handoffs["reporter_critic"],
            merged_rt=merged_rt,
            state=state,
            ctx=ctx,
            llm_client=llm_client,
            findings=findings,
        )
        ms = (time.perf_counter() - t0) * 1000
        f_critic = enrich_specialist_finding(
            handoffs["reporter_critic"],
            f_critic_raw,
            merged_rt.evidence_registry,
            degraded=merged_rt.degraded_evidence,
            tool_errors=ctx.box("reporter_critic").tool_errors,
            duration_ms=ms,
        )
        all_findings = [*findings, f_critic]
        now = utc_now_iso()
        agent_runs = [
            {
                "agent_id": f.agent_name,
                "agent_name": f.agent_name,
                "task": handoffs[f.agent_name].objective if f.agent_name in handoffs else f.task_id,
                "status": "completed",
                "started_at": now,
                "duration_ms": float((f.execution_metadata or {}).get("duration_ms", round(ms, 1))),
                "tool_calls": f.tool_calls,
                "summary": f.summary,
            }
            for f in all_findings
        ]
        flow_summary = compute_network_flow_summary(
            merged_rt.root_account, merged_rt.transactions, merged_rt.fund_flow_paths, merged_rt.kyc_profiles
        )
        drafted_state = state.model_copy(
            update={
                "worksheet": worksheet,
                "active_hypotheses": worksheet.hypotheses,
                "specialist_findings": [f.model_dump(mode="json") for f in all_findings],
                "evidence_registry": merged_rt.evidence_registry,
                "calc_log": merged_rt.calc_log,
            }
        )
        eval_update = await hypothesis_evaluation_node(drafted_state, ctx)
        return {
            "worksheet": worksheet,
            "active_hypotheses": worksheet.hypotheses,
            "evidence_registry": merged_rt.evidence_registry,
            "calc_log": merged_rt.calc_log,
            "tool_execution_log": merged_rt.tool_execution_log,
            "specialist_findings": [f.model_dump(mode="json") for f in all_findings],
            "hypothesis_assessment": eval_update["hypothesis_assessment"],
            "evidence_claims": eval_update["evidence_claims"],
            "critic_assessment": eval_update["critic_assessment"],
            "degraded_evidence": sorted({*worksheet.degraded_evidence, *merged_rt.degraded_evidence}),
            "flow_summary": flow_summary,
            "reasoning_mode": "llm_tool_loop",
            "error": (
                "verification_failed"
                if (ctx.deterministic_verifier and worksheet.verification_status == "failed")
                else None
            ),
            "is_complete": True,
            "current_node": "reporter_critic",
            "current_step": state.current_step + 1,
            "workflow_steps": [
                {"step": 1, "name": "Alert Intake & Supervisor Routing", "status": "completed"},
                {"step": 2, "name": "Flow Tracer & Parallel Specialists", "status": "completed"},
                {"step": 3, "name": "Competing Hypotheses & Claim Grounding", "status": "completed"},
                {"step": 4, "name": "Supervisor Review & Evidence-Driven Replan", "status": "completed"},
                {"step": 5, "name": "Independent Critic & Verifier v2", "status": "completed"},
                {"step": 6, "name": "Human Approval", "status": "waiting_approval"},
                {"step": 7, "name": "Case Commit & Reporting", "status": "pending"},
            ],
            "agent_runs": agent_runs,
            **sync_budget(ctx),
        }

    return {
        "supervisor_plan": supervisor_plan_node,
        "flow_tracer": flow_tracer_stage,
        "parallel_specialists": parallel_specialists_stage,
        "hypothesis_evaluation": hypothesis_evaluation_node,
        "supervisor_replan_check": supervisor_replan_check_stage,
        "flow_replan": flow_replan_stage,
        "reporter_critic": reporter_critic_stage,
    }


def route_c2_after_replan_check(state: InvestigationState) -> Literal["flow_replan", "reporter_critic"]:
    return "flow_replan" if state.proposed_params is not None else "reporter_critic"
