"""
AuditGuard v3 C2 Multi-Agent Supervisor + 4 RBAC Specialist LLMs (`src/agent/c2_loop.py`).

Architecture:
  1. Supervisor LLM (`c2_supervisor`) emits typed `SpecialistHandOff`s with per-specialist slices of
     the shared `15` calls / `$0.15` `BudgetLedger`.
  2. `flow_tracer` LLM runs initial graph & transaction reconstruction within its RBAC allow-list.
  3. `benign_investigator` and `regulatory_analyst` LLMs fan out **in parallel** (`asyncio.gather`).
  4. Supervisor LLM inspects the `SpecialistFinding`s and may request at most ONE bounded replan
     from `flow_tracer`.
  5. `reporter_critic` LLM drafts via `finish(...)`, runs `verify_worksheet`, and may execute ONE
     correction round before fail-closed fallback.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
import json
import re
import time
from typing import Any, Optional

from pydantic import Field, ValidationError

from src.agent.loop import (
    execute_tool_turn_batch,
    persist_forced_finish,
    retrieve_frozen_lessons,
    tool_message,
)
from src.agent.planning import RunContext, c2_handoffs, sync_budget
from src.agent.prompts import render_c2_supervisor_prompt, render_specialist_prompt
from src.agent.telemetry import compute_network_flow_summary
from src.agent.tooling import is_error
from src.agent.tools import AgentToolRuntime, build_openai_tools
from src.core.canonical import Ratio
from src.db.database import utc_now_iso
from src.llm.client import LLMClientProtocol
from src.models import (
    DispositionWorksheet,
    InvestigationPlan,
    InvestigationState,
    SpecialistFinding,
    SpecialistHandOff,
    StrictModel,
)

SPECIALIST_MAX_TURNS = 4
CRITIC_MAX_TURNS = 4


class SupervisorPlanOutput(StrictModel):
    steps: list[str] = Field(min_length=1)
    handoffs: list[SpecialistHandOff] = Field(min_length=1)


class SupervisorReplanCheck(StrictModel):
    request_replan: bool = False
    time_window_days: int = 18
    max_hops: int = 4
    amount_tolerance: Ratio = Decimal("0.1500")
    reason: str = ""


def _parse_json_obj(raw: str) -> Optional[dict[str, Any]]:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=re.IGNORECASE | re.DOTALL).strip()
    m = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not m:
        return None
    try:
        parsed = json.loads(m.group(0))
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _normalize_handoffs(handoffs: list[SpecialistHandOff], max_calls: int) -> dict[str, SpecialistHandOff]:
    by_role: dict[str, SpecialistHandOff] = {h.target_agent: h for h in c2_handoffs(max_calls)}
    for h in handoffs:
        if h.target_agent in by_role:
            capped = max(1, min(h.allowed_tool_budget, max_calls - 1))
            by_role[h.target_agent] = h.model_copy(update={"allowed_tool_budget": capped})
    return by_role


async def _supervisor_plan(
    state: InvestigationState,
    ctx: RunContext,
    llm_client: LLMClientProtocol,
    lessons: list[str],
) -> tuple[list[str], dict[str, SpecialistHandOff]]:
    max_calls = ctx.policy.budgets.max_tool_calls
    fallback_handoffs = _normalize_handoffs([], max_calls)
    fallback_steps = [f"[{h.target_agent}] {h.objective}" for h in fallback_handoffs.values()]
    if not ctx.ledger.check_llm_allowed().allowed:
        return fallback_steps, fallback_handoffs

    spec = ctx.policy.model_for("c2_supervisor")
    model_id = ctx.strong_model_override or spec.model_id
    user_prompt = (
        f"Plan investigation for Alert `{state.alert.alert_id}` (root=`{state.alert.root_account}`, "
        f"amount=`INR {state.alert.total_amount_inr}`, rule=`{state.alert.rule_name}`).\n"
        "Return JSON: "
        '{"steps": ["..."], "handoffs": ['
        '{"task_id":"HO-FLOW","target_agent":"flow_tracer","objective":"...","allowed_tool_budget":4},'
        '{"task_id":"HO-BENIGN","target_agent":"benign_investigator","objective":"...","allowed_tool_budget":5},'
        '{"task_id":"HO-REG","target_agent":"regulatory_analyst","objective":"...","allowed_tool_budget":2},'
        '{"task_id":"HO-CRITIC","target_agent":"reporter_critic","objective":"...","allowed_tool_budget":2}]}'
    )
    resp = await llm_client.chat(
        [
            {"role": "system", "content": render_c2_supervisor_prompt(ctx.policy, lessons)},
            {"role": "user", "content": user_prompt},
        ],
        model=model_id,
        temperature=spec.temperature,
        max_tokens=spec.max_tokens,
        seed=ctx.seed,
    )
    ctx.ledger.record_llm_usage(resp.usage.prompt_tokens, resp.usage.completion_tokens, resp.cost_usd)
    parsed_dict = _parse_json_obj(resp.text)
    if parsed_dict is not None:
        try:
            validated = SupervisorPlanOutput.model_validate(parsed_dict)
            return validated.steps, _normalize_handoffs(validated.handoffs, max_calls)
        except ValidationError:
            pass
    return fallback_steps, fallback_handoffs


async def _run_evidence_specialist(
    *,
    handoff: SpecialistHandOff,
    runtime: AgentToolRuntime,
    ctx: RunContext,
    llm_client: LLMClientProtocol,
    context_summary: dict[str, Any],
    replanning_enabled: bool = False,
    max_turns: int = SPECIALIST_MAX_TURNS,
) -> SpecialistFinding:
    role = handoff.target_agent
    runtime.box.set_sub_budget(runtime.box.calls + handoff.allowed_tool_budget)
    calls_before = runtime.box.calls
    keys_before = set(runtime.evidence_registry.keys())
    spec = ctx.policy.model_for("c2_specialists")
    model_id = ctx.model_override or spec.model_id
    tools = build_openai_tools(role, include_finish=False, replanning_enabled=replanning_enabled)
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": render_specialist_prompt(role, handoff.objective, handoff.allowed_tool_budget, context_summary),
        },
        {"role": "user", "content": f"Execute hand-off `{handoff.task_id}` now using your allowed tools."},
    ]
    summary_text = ""
    for _ in range(max_turns):
        if not ctx.ledger.check_llm_allowed().allowed:
            break
        resp = await llm_client.chat(
            messages,
            tools=tools,
            model=model_id,
            temperature=spec.temperature,
            max_tokens=spec.max_tokens,
            seed=ctx.seed,
        )
        ctx.ledger.record_llm_usage(resp.usage.prompt_tokens, resp.usage.completion_tokens, resp.cost_usd)
        messages.append(resp.to_assistant_message())
        if resp.text.strip():
            summary_text = resp.text.strip()
        if not resp.tool_calls:
            break
        stop_specialist = False
        for tc in resp.tool_calls:
            res = await runtime.execute(tc.name, tc.arguments)
            messages.append(tool_message(tc, res))
            if is_error(res) and res.get("error_code") in ("BUDGET_EXCEEDED", "SPECIALIST_BUDGET_EXCEEDED"):
                stop_specialist = True
        if stop_specialist:
            break

    added = sorted(set(runtime.evidence_registry.keys()) - keys_before)
    multi = sum(1 for p in runtime.fund_flow_paths if p.hop_count >= 2)
    rec_replan = {"expand_window": True} if (role == "flow_tracer" and not multi and runtime.transactions) else None
    return SpecialistFinding(
        task_id=handoff.task_id,
        agent_name=role,
        summary=(summary_text or f"{role} completed ({len(added)} evidence item(s) added)")[:300],
        tool_calls=runtime.box.calls - calls_before,
        evidence_ids_added=added,
        recommended_replan=rec_replan,
    )


async def _supervisor_should_replan(
    ctx: RunContext,
    llm_client: LLMClientProtocol,
    findings: list[SpecialistFinding],
    flow_rt: AgentToolRuntime,
) -> Optional[SupervisorReplanCheck]:
    if not (
        ctx.replanning_enabled
        and ctx.policy.budgets.max_replans >= 1
        and flow_rt.transactions
        and ctx.ledger.calls_used + 2 <= ctx.policy.budgets.max_tool_calls
        and ctx.ledger.check_llm_allowed().allowed
    ):
        return None
    spec = ctx.policy.model_for("c2_supervisor")
    model_id = ctx.strong_model_override or spec.model_id
    gb = ctx.policy.graph_bounds
    prompt = (
        f"Specialist findings:\n{json.dumps([f.model_dump(mode='json') for f in findings], indent=2)}\n"
        f"Paths reconstructed so far: {len(flow_rt.fund_flow_paths)} "
        f"(multi-hop={sum(1 for p in flow_rt.fund_flow_paths if p.hop_count >= 2)}).\n"
        f"Bounds: time_window_days=[{gb.time_window_days.min}..{gb.time_window_days.max}], "
        f"max_hops=[{gb.max_hops.min}..{gb.max_hops.max}], "
        f"amount_tolerance=[{gb.amount_tolerance.min}..{gb.amount_tolerance.max}].\n"
        'Return JSON: {"request_replan": true|false, "time_window_days": 18, '
        '"max_hops": 4, "amount_tolerance": "0.15", "reason": "..."}'
    )
    resp = await llm_client.chat(
        [
            {"role": "system", "content": render_c2_supervisor_prompt(ctx.policy)},
            {"role": "user", "content": prompt},
        ],
        model=model_id,
        temperature=spec.temperature,
        max_tokens=512,
        seed=ctx.seed,
    )
    ctx.ledger.record_llm_usage(resp.usage.prompt_tokens, resp.usage.completion_tokens, resp.cost_usd)
    raw = _parse_json_obj(resp.text)
    if raw is not None:
        try:
            verdict = SupervisorReplanCheck.model_validate(raw)
            return verdict if verdict.request_replan else None
        except ValidationError:
            return None
    return None


def _critic_initial_messages(
    handoff: SpecialistHandOff,
    merged_rt: AgentToolRuntime,
    state: InvestigationState,
    findings: list[SpecialistFinding],
) -> list[dict[str, Any]]:
    ev_preview = {
        "alert_id": state.alert.alert_id,
        "alert_amount_inr": str(state.alert.total_amount_inr),
        "specialist_findings": [f.model_dump(mode="json") for f in findings],
        "candidate_paths": [p.model_dump(mode="json") for p in merged_rt.fund_flow_paths[:3]],
        "kyc_profiles": merged_rt.kyc_profiles[:5],
        "regulatory_clauses": [
            {"clause_id": c["clause_id"], "title": c.get("title", "")} for c in merged_rt.regulatory_clauses[:5]
        ],
        "known_evidence_ids": sorted(merged_rt.evidence_registry.keys())[:60],
    }
    sys_prompt = render_specialist_prompt(
        "reporter_critic", handoff.objective, handoff.allowed_tool_budget, ev_preview
    )
    return [
        {"role": "system", "content": sys_prompt},
        {
            "role": "user",
            "content": (
                "Synthesize the specialist findings, use `calc` if any figure is needed, and invoke `finish` "
                "with both `suspicious_hypothesis` and `benign_hypothesis`, exact `evidence_ids` from "
                "`known_evidence_ids`, `regulatory_citations`, and a non-empty `missing_evidence` list."
            ),
        },
    ]


async def _run_reporter_critic(
    *,
    handoff: SpecialistHandOff,
    merged_rt: AgentToolRuntime,
    state: InvestigationState,
    ctx: RunContext,
    llm_client: LLMClientProtocol,
    findings: list[SpecialistFinding],
) -> tuple[DispositionWorksheet, SpecialistFinding]:
    merged_rt.box.set_sub_budget(merged_rt.box.calls + max(2, handoff.allowed_tool_budget))
    calls_before = merged_rt.box.calls
    spec = ctx.policy.model_for("c2_specialists")
    model_id = ctx.model_override or spec.model_id
    tools = build_openai_tools("reporter_critic", include_finish=True, replanning_enabled=False)
    messages = _critic_initial_messages(handoff, merged_rt, state, findings)

    repair_used = False
    forced_reason = "reporter_critic finished turns without valid finish"
    last_model = model_id
    worksheet: Optional[DispositionWorksheet] = None

    for turn in range(CRITIC_MAX_TURNS):
        if not ctx.ledger.check_llm_allowed().allowed:
            forced_reason = "cost budget exhausted before reporter_critic finish"
            break
        resp = await llm_client.chat(
            messages,
            tools=tools,
            model=model_id,
            temperature=spec.temperature,
            max_tokens=spec.max_tokens,
            seed=ctx.seed,
        )
        last_model = resp.model or model_id
        ctx.ledger.record_llm_usage(resp.usage.prompt_tokens, resp.usage.completion_tokens, resp.cost_usd)
        messages.append(resp.to_assistant_message())
        if not resp.tool_calls:
            if turn + 1 < CRITIC_MAX_TURNS:
                messages.append({"role": "user", "content": "Call the `finish` tool now to submit the worksheet."})
                continue
            break
        ws, repair_used, abort, batch_reason = await execute_tool_turn_batch(
            tool_calls=resp.tool_calls,
            messages=messages,
            runtime=merged_rt,
            ctx=ctx,
            state=state,
            model_name=last_model,
            repair_used=repair_used,
            turns_left=(turn + 1 < CRITIC_MAX_TURNS),
        )
        if batch_reason:
            forced_reason = batch_reason
        if ws is not None:
            worksheet = ws
            break
        if abort:
            break

    if worksheet is None:
        worksheet = await persist_forced_finish(
            runtime=merged_rt,
            ctx=ctx,
            alert=state.alert,
            thread_id=state.thread_id,
            model_name=last_model,
            reason=forced_reason,
        )
    finding = SpecialistFinding(
        task_id=handoff.task_id,
        agent_name="reporter_critic",
        summary=f"Drafted {worksheet.worksheet_id} ({worksheet.recommended_disposition.value})",
        tool_calls=merged_rt.box.calls - calls_before,
        evidence_ids_added=[worksheet.worksheet_id],
    )
    return worksheet, finding


def _merge_specialist_runtimes(
    flow_rt: AgentToolRuntime,
    benign_rt: AgentToolRuntime,
    reg_rt: AgentToolRuntime,
    ctx: RunContext,
) -> AgentToolRuntime:
    merged = AgentToolRuntime(
        role="reporter_critic",
        box=ctx.box("reporter_critic"),
        alert=flow_rt.alert,
        replanning_enabled=False,
        initial_transactions=flow_rt.transactions,
        initial_paths=flow_rt.fund_flow_paths,
        initial_registry={
            **flow_rt.evidence_registry,
            **benign_rt.evidence_registry,
            **reg_rt.evidence_registry,
        },
    )
    merged.root_account = flow_rt.root_account
    merged.network_accounts = list(flow_rt.network_accounts)
    merged.kyc_profiles = list(benign_rt.kyc_profiles)
    merged.regulatory_clauses = list(reg_rt.regulatory_clauses)
    merged.regulatory_snippets = list(reg_rt.regulatory_snippets)
    merged.calc_log = [*flow_rt.calc_log, *benign_rt.calc_log]
    merged.degraded_evidence = sorted(
        {*flow_rt.degraded_evidence, *benign_rt.degraded_evidence, *reg_rt.degraded_evidence}
    )
    merged.graph_runs = list(flow_rt.graph_runs)
    merged.replan_count = flow_rt.replan_count
    merged.last_replan_reason = flow_rt.last_replan_reason
    merged.current_graph_params = flow_rt.current_graph_params
    return merged


async def _maybe_replan_flow(
    ctx: RunContext,
    llm_client: LLMClientProtocol,
    findings: list[SpecialistFinding],
    flow_rt: AgentToolRuntime,
) -> None:
    replan_req = await _supervisor_should_replan(ctx, llm_client, findings, flow_rt)
    if replan_req is None:
        return
    flow_rt.replanning_enabled = True
    replan_ho = SpecialistHandOff(
        task_id="HO-FLOW-REPLAN",
        target_agent="flow_tracer",
        objective=(
            f"Call replan_graph(time_window_days={replan_req.time_window_days}, "
            f"max_hops={replan_req.max_hops}, amount_tolerance='{replan_req.amount_tolerance}', "
            f"reason={replan_req.reason!r})"
        ),
        allowed_tool_budget=2,
    )
    findings[0] = await _run_evidence_specialist(
        handoff=replan_ho,
        runtime=flow_rt,
        ctx=ctx,
        llm_client=llm_client,
        context_summary={"replan_directive": replan_req.model_dump(mode="json")},
        replanning_enabled=True,
        max_turns=2,
    )


async def _gather_c2_specialists(
    state: InvestigationState,
    ctx: RunContext,
    llm_client: LLMClientProtocol,
    handoffs: dict[str, SpecialistHandOff],
) -> tuple[AgentToolRuntime, list[SpecialistFinding]]:
    flow_rt = AgentToolRuntime(
        role="flow_tracer",
        box=ctx.box("flow_tracer"),
        alert=state.alert,
        replanning_enabled=False,
        initial_registry=state.evidence_registry,
    )
    f_flow = await _run_evidence_specialist(
        handoff=handoffs["flow_tracer"],
        runtime=flow_rt,
        ctx=ctx,
        llm_client=llm_client,
        context_summary={"alert_id": state.alert.alert_id, "root_account": state.alert.root_account},
    )
    benign_rt = AgentToolRuntime(
        role="benign_investigator",
        box=ctx.box("benign_investigator"),
        alert=state.alert,
        replanning_enabled=False,
        initial_transactions=flow_rt.transactions,
        initial_paths=flow_rt.fund_flow_paths,
    )
    reg_rt = AgentToolRuntime(
        role="regulatory_analyst",
        box=ctx.box("regulatory_analyst"),
        alert=state.alert,
        replanning_enabled=False,
    )
    shared_ctx = {
        "alert_id": state.alert.alert_id,
        "root_account": flow_rt.root_account,
        "network_accounts": flow_rt.network_accounts[:8],
        "path_nodes": list(dict.fromkeys(n for p in flow_rt.fund_flow_paths for n in p.nodes))[:8],
        "flow_finding": f_flow.summary,
    }
    f_benign, f_reg = await asyncio.gather(
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
    findings = [f_flow, f_benign, f_reg]
    await _maybe_replan_flow(ctx, llm_client, findings, flow_rt)
    return _merge_specialist_runtimes(flow_rt, benign_rt, reg_rt, ctx), findings


def _c2_state_update(
    state: InvestigationState,
    ctx: RunContext,
    merged_rt: AgentToolRuntime,
    steps: list[str],
    lessons: list[str],
    handoffs: dict[str, SpecialistHandOff],
    findings: list[SpecialistFinding],
    worksheet: DispositionWorksheet,
    elapsed_ms: float,
) -> dict[str, Any]:
    now = utc_now_iso()
    agent_runs = [
        {
            "agent_id": f.agent_name,
            "agent_name": f.agent_name,
            "task": handoffs[f.agent_name].objective if f.agent_name in handoffs else f.task_id,
            "status": "completed",
            "started_at": now,
            "duration_ms": round(elapsed_ms / 4, 1),
            "tool_calls": f.tool_calls,
            "summary": f.summary,
        }
        for f in findings
    ]
    plan = InvestigationPlan(
        steps=steps,
        graph_params=merged_rt.current_graph_params,
        focus_accounts=list(dict.fromkeys([merged_rt.root_account, *merged_rt.network_accounts[:5]])),
        clause_ids=[c["clause_id"] for c in merged_rt.regulatory_clauses if c.get("clause_id")],
        replan_count=merged_rt.replan_count,
        replan_reason=merged_rt.last_replan_reason,
    )
    flow_summary = compute_network_flow_summary(
        merged_rt.root_account, merged_rt.transactions, merged_rt.fund_flow_paths, merged_rt.kyc_profiles
    )
    return {
        "alert": state.alert.model_copy(
            update={"root_account": merged_rt.root_account, "network_accounts": merged_rt.network_accounts}
        ),
        "plan": plan,
        "replan_count": merged_rt.replan_count,
        "transactions": merged_rt.transactions,
        "fund_flow_paths": merged_rt.fund_flow_paths,
        "kyc_profiles": merged_rt.kyc_profiles,
        "regulatory_clauses": merged_rt.regulatory_clauses,
        "regulatory_snippets": merged_rt.regulatory_snippets,
        "evidence_registry": merged_rt.evidence_registry,
        "calc_log": merged_rt.calc_log,
        "retrieved_lessons": lessons,
        "specialist_handoffs": [h.model_dump(mode="json") for h in handoffs.values()],
        "specialist_findings": [f.model_dump(mode="json") for f in findings],
        "degraded_evidence": sorted({*worksheet.degraded_evidence, *merged_rt.degraded_evidence}),
        "active_hypotheses": worksheet.hypotheses,
        "worksheet": worksheet,
        "flow_summary": flow_summary,
        "reasoning_mode": "llm_tool_loop",
        "error": "verification_failed" if worksheet.verification_status == "failed" else None,
        "is_complete": True,
        "current_node": "interrupt_required",
        "current_step": state.current_step + 1,
        "workflow_steps": [
            {"step": 1, "name": "Alert Intake & Validation", "status": "completed"},
            {"step": 2, "name": "Supervisor Typed Hand-Offs", "status": "completed"},
            {"step": 3, "name": "Parallel Specialist Execution", "status": "completed"},
            {"step": 4, "name": "Supervisor Review & Replan Check", "status": "completed"},
            {"step": 5, "name": "Reporter Critic & Deterministic Verifier", "status": "completed"},
            {"step": 6, "name": "Human Approval", "status": "waiting_approval"},
            {"step": 7, "name": "Case Commit & Reporting", "status": "pending"},
        ],
        "agent_runs": agent_runs,
        **sync_budget(ctx),
    }


async def run_c2_agent_team(
    state: InvestigationState,
    ctx: RunContext,
    llm_client: LLMClientProtocol,
) -> dict[str, Any]:
    """Execute Supervisor + 4 RBAC Specialist LLMs with parallel fan-out and bounded replanning."""
    t0 = time.perf_counter()
    lessons = await retrieve_frozen_lessons(state, ctx)
    steps, handoffs = await _supervisor_plan(state, ctx, llm_client, lessons)
    merged_rt, findings = await _gather_c2_specialists(state, ctx, llm_client, handoffs)
    worksheet, f_critic = await _run_reporter_critic(
        handoff=handoffs["reporter_critic"],
        merged_rt=merged_rt,
        state=state,
        ctx=ctx,
        llm_client=llm_client,
        findings=findings,
    )
    findings.append(f_critic)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    return _c2_state_update(
        state, ctx, merged_rt, steps, lessons, handoffs, findings, worksheet, elapsed_ms
    )
