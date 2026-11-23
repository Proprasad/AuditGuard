"""
Dedicated C2 RBAC specialist nodes (`flow_tracer_node`, `parallel_specialists_node`) with enforced
per-handoff `SpecialistHandOff.allowed_tool_budget` sub-budgets and durable checkpointing.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from src.agent.gathering import enrich_graph_evidence, fetch_flow_evidence, gather_identity, gather_regulatory
from src.agent.planning import RunContext, all_security_notes, handoff_for, sync_budget, upsert_finding
from src.agent.tooling import is_error
from src.memory.store import trim_messages_with_summary
from src.models import GraphParams, InvestigationState, SpecialistFinding


async def flow_tracer_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    """Dedicated C2 `flow_tracer` specialist node (durably checkpointed before parallel context specialists)."""
    flow_box = ctx.box("flow_tracer")
    if handoff := handoff_for(state, "flow_tracer"):
        flow_box.set_sub_budget(handoff.allowed_tool_budget)

    registry = dict(state.evidence_registry)
    degraded = list(state.degraded_evidence)
    params = state.plan.graph_params if state.plan else GraphParams.policy_default()

    t0 = time.perf_counter()
    root, network, txs, paths, graph_result = await fetch_flow_evidence(state, ctx, flow_box, registry, degraded)
    if graph_result is None:
        ctx.timings["flow_ms"] = ctx.timings.get("flow_ms", 0.0) + (time.perf_counter() - t0) * 1000
        return {
            "degraded_evidence": sorted({*degraded, *all_security_notes(ctx)}),
            "current_node": "flow_tracer",
            "current_step": state.current_step + 1,
            **sync_budget(ctx),
        }
    if not is_error(graph_result):
        await enrich_graph_evidence(ctx, flow_box, graph_result, paths, params, registry)
    ctx.timings["flow_ms"] = ctx.timings.get("flow_ms", 0.0) + (time.perf_counter() - t0) * 1000

    multi = sum(1 for p in paths if p.hop_count >= 2)
    finding = SpecialistFinding(
        task_id="HO-FLOW",
        agent_name="flow_tracer",
        summary=f"Reconstructed {len(paths)} path(s) ({multi} multi-hop)",
        tool_calls=flow_box.calls,
        evidence_ids_added=[p.path_id for p in paths],
        recommended_replan={"expand_window": True} if not multi else None,
    )
    updated_alert = state.alert.model_copy(update={"root_account": root, "network_accounts": network})
    return {
        "alert": updated_alert,
        "transactions": txs,
        "fund_flow_paths": paths,
        "evidence_registry": registry,
        "degraded_evidence": sorted({*degraded, *all_security_notes(ctx)}),
        "specialist_findings": upsert_finding(state.specialist_findings, finding),
        "current_node": "flow_tracer",
        "current_step": state.current_step + 1,
        **sync_budget(ctx),
    }


async def parallel_specialists_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    """Dedicated C2 parallel dispatch for `benign_investigator` and `regulatory_analyst` (durably checkpointed)."""
    if h_ben := handoff_for(state, "benign_investigator"):
        ctx.box("benign_investigator").set_sub_budget(h_ben.allowed_tool_budget)
    if h_reg := handoff_for(state, "regulatory_analyst"):
        ctx.box("regulatory_analyst").set_sub_budget(h_reg.allowed_tool_budget)

    registry = dict(state.evidence_registry)
    degraded = list(state.degraded_evidence)
    root = state.alert.root_account
    network = list(state.alert.network_accounts)

    t1 = time.perf_counter()
    profiles, (clauses, snippets) = await asyncio.gather(
        gather_identity(ctx, state, root, network, state.fund_flow_paths, registry, degraded),
        gather_regulatory(ctx, state, registry, degraded),
    )
    ctx.timings["evidence_ms"] = ctx.timings.get("evidence_ms", 0.0) + (time.perf_counter() - t1) * 1000

    findings = upsert_finding(
        state.specialist_findings,
        SpecialistFinding(
            task_id="HO-BENIGN",
            agent_name="benign_investigator",
            summary=f"Verified {len(profiles)} KYC/registry record(s)",
            tool_calls=ctx.box("benign_investigator").calls,
            evidence_ids_added=[str(k.get("evidence_id", "")) for k in profiles if k.get("evidence_id")],
        ),
    )
    findings = upsert_finding(
        findings,
        SpecialistFinding(
            task_id="HO-REG",
            agent_name="regulatory_analyst",
            summary=f"Retrieved {len(clauses)} regulatory clause(s)",
            tool_calls=ctx.box("regulatory_analyst").calls,
            evidence_ids_added=[c["clause_id"] for c in clauses],
        ),
    )
    msg_txt = f"Specialists gathered {len(state.fund_flow_paths)} paths, {len(profiles)} KYC"
    msgs, summary = trim_messages_with_summary(
        [*state.messages, {"role": "tool", "content": msg_txt}],
        state.rolling_summary,
        window_size=ctx.policy.memory.short_term_window_messages,
    )
    return {
        "kyc_profiles": profiles,
        "regulatory_clauses": clauses,
        "regulatory_snippets": snippets,
        "evidence_registry": registry,
        "degraded_evidence": sorted({*degraded, *all_security_notes(ctx)}),
        "specialist_findings": findings,
        "refresh_kyc": False,
        "refresh_regulations": False,
        "messages": msgs,
        "rolling_summary": summary,
        "current_node": "parallel_specialists",
        "current_step": state.current_step + 1,
        **sync_budget(ctx),
    }
