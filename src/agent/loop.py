"""
AuditGuard v3 C1 Single-Agent ReAct / OpenAI Tool-Calling Loop (`src/agent/loop.py`).

Enforces:
  * System prompt loaded & versioned from `config/prompts/c1_investigator.yaml` (+ frozen Reflexion lessons)
  * Hard caps: `max_tool_calls` (15), `max_replans` (3), `max_cost_usd` ($0.15), `max_turns` (12)
  * Real token & `Decimal` USD cost tracking in `BudgetLedger` on every `llm_client.chat(...)` turn
  * Structured `finish(...)` validated with Pydantic + `verify_worksheet`, with ONE repair retry on error
  * Forced `INSUFFICIENT_DATA` (`request_info`) finish if turns or budgets exhaust before verified `finish`
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Optional

from src.agent.planning import RunContext, all_security_notes, resolve_model_for_role, sync_budget, tool_error_notes
from src.agent.prompts import render_alert_user_message, render_c1_system_prompt
from src.agent.telemetry import compute_network_flow_summary
from src.agent.tooling import is_error
from src.agent.tools import (
    AgentToolRuntime,
    FinishInvestigationInput,
    build_hypotheses_from_finish,
    build_openai_tools,
    format_rationale_with_missing,
)
from src.core.adapters import kyc_summaries
from src.core.canonical import dec_str, to_confidence
from src.core.verifier import verify_worksheet
from src.db.database import utc_now_iso
from src.llm.client import LLMClientProtocol
from src.llm.schemas import ChatResponse, ToolCallRequest
from src.memory.store import memory_store, trim_messages_with_summary
from src.models import (
    Alert,
    DispositionDecision,
    DispositionWorksheet,
    Hypothesis,
    HypothesisLabel,
    InvestigationState,
)

DEFAULT_MAX_TURNS = 12


def _candidate_draft_payload(
    *,
    runtime: AgentToolRuntime,
    alert: Alert,
    thread_id: str,
    disposition: DispositionDecision,
    rationale: str,
    confidence: float,
    hypotheses: list[Hypothesis],
    citations: list[str],
    degraded: list[str],
    missing_evidence: Optional[list[str]] = None,
    status: str = "passed",
    discrepancies: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "thread_id": thread_id,
        "recommended_disposition": disposition.value,
        "recommendation_rationale": rationale,
        "confidence_score": dec_str(to_confidence(confidence)),
        "candidate_paths": [p.model_dump(mode="json") for p in runtime.fund_flow_paths[:3]],
        "regulatory_citations": citations,
        "kyc_summaries": kyc_summaries(runtime.kyc_profiles, limit=5),
        "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
        "degraded_evidence": degraded,
        "missing_evidence": list(missing_evidence or []),
        "alert_amount_inr": dec_str(alert.total_amount_inr),
        "verification_status": status,
        "verification_discrepancies": discrepancies or [],
    }


def _resolve_citations(sub: FinishInvestigationInput, runtime: AgentToolRuntime) -> list[str]:
    explicit = list(
        dict.fromkeys(
            [
                *sub.regulatory_citations,
                *sub.suspicious_hypothesis.regulatory_citations,
                *sub.benign_hypothesis.regulatory_citations,
            ]
        )
    )
    if explicit:
        return explicit
    return [str(c["clause_id"]) for c in runtime.regulatory_clauses if c.get("clause_id")][:3]


def validate_finish_candidate(
    runtime: AgentToolRuntime,
    sub: FinishInvestigationInput,
    alert: Alert,
    thread_id: str,
    degraded: list[str],
    *,
    verify: bool = True,
) -> tuple[bool, list[str], dict[str, Any], list[Hypothesis], list[str], list[dict[str, Any]]]:
    """
    Run Verifier v2 (`verify_worksheet` with `calc_log`) on every finish candidate.
    Even when `verify=False` (E4 `no_verifier`), checks execute and discrepancies are returned;
    the caller decides whether to gate/repair (`verify=True`) or pass through (`verify=False`).
    """
    _ = verify  # gate enforcement happens in `handle_finish_attempt` / `persist_verified_worksheet`
    disp, conf, rationale = format_rationale_with_missing(sub)
    hyps = build_hypotheses_from_finish(sub)
    citations = _resolve_citations(sub, runtime)
    errors: list[str] = []

    non_clause_ids = [k for k in runtime.evidence_registry if not str(k).startswith(("REG-", "SOP-"))]
    if non_clause_ids and not (hyps[0].evidence_ids or hyps[1].evidence_ids):
        errors.append("MISSING_HYPOTHESIS_EVIDENCE_IDS: hypotheses must cite at least one gathered evidence ID")

    payload = _candidate_draft_payload(
        runtime=runtime,
        alert=alert,
        thread_id=thread_id,
        disposition=disp,
        rationale=rationale,
        confidence=conf,
        hypotheses=hyps,
        citations=citations,
        degraded=degraded,
        missing_evidence=list(sub.missing_evidence),
    )
    vr = verify_worksheet(payload, runtime.evidence_registry, calc_log=runtime.calc_log)
    discrepancies = [d.model_dump() for d in vr.discrepancies]
    if not vr.passed:
        errors.extend(vr.errors)
    return (len(errors) == 0), errors, payload, hyps, citations, discrepancies


async def persist_verified_worksheet(
    *,
    runtime: AgentToolRuntime,
    alert: Alert,
    thread_id: str,
    agent_label: str,
    model_name: str,
    payload: dict[str, Any],
    hypotheses: list[Hypothesis],
    citations: list[str],
    missing_evidence: list[str],
    verify: bool,
) -> DispositionWorksheet:
    """Persist worksheet via `case-actions.draft_disposition_report` (`enforce_verifier_gate=verify`)."""
    call_payload = {
        **payload,
        "evidence_registry": dict(runtime.evidence_registry),
        "calc_log": list(runtime.calc_log),
        "enforce_verifier_gate": verify,
    }
    draft = await runtime.box.call("case-actions", "draft_disposition_report", call_payload)
    if is_error(draft):
        raise RuntimeError(f"draft_disposition_report failed: {draft.get('error_code') or draft.get('message')}")
    stored = dict(draft.get("content") or {})
    return DispositionWorksheet(
        worksheet_id=str(draft["worksheet_id"]),
        alert_id=alert.alert_id,
        drafted_at=str(stored.get("drafted_at") or draft.get("created_at") or ""),
        investigator_agent=f"{agent_label} ({model_name})",
        candidate_paths=runtime.fund_flow_paths[:3],
        hypotheses=hypotheses,
        regulatory_citations=citations,
        kyc_summaries=kyc_summaries(runtime.kyc_profiles, limit=5),
        degraded_evidence=list(payload["degraded_evidence"]),
        missing_evidence=missing_evidence,
        alert_amount_inr=str(payload["alert_amount_inr"]),
        verification_status=str(stored.get("verification_status", payload["verification_status"])),
        verification_discrepancies=list(
            stored.get("verification_discrepancies", payload["verification_discrepancies"])
        ),
        recommended_disposition=DispositionDecision(
            str(stored.get("recommended_disposition", payload["recommended_disposition"]))
        ),
        recommendation_rationale=str(stored.get("recommendation_rationale", payload["recommendation_rationale"])),
        confidence_score=payload["confidence_score"],
        payload_hash=str(draft["payload_hash"]),
    )


async def persist_forced_finish(
    *,
    runtime: AgentToolRuntime,
    ctx: RunContext,
    alert: Alert,
    thread_id: str,
    model_name: str,
    reason: str,
) -> DispositionWorksheet:
    """Fail-closed forced `INSUFFICIENT_DATA` (`request_info`) worksheet when budget/turns/repair exhaust."""
    degraded = sorted(
        {
            *runtime.degraded_evidence,
            *all_security_notes(ctx),
            *tool_error_notes(ctx),
            f"Forced finish (INSUFFICIENT_DATA): {reason}",
        }
    )
    citations = [str(c["clause_id"]) for c in runtime.regulatory_clauses if c.get("clause_id")][:3]
    path_ids = [p.path_id for p in runtime.fund_flow_paths[:3]]
    kyc_ids = [str(k.get("evidence_id")) for k in runtime.kyc_profiles if k.get("evidence_id")][:3]
    ev_ids = [eid for eid in [*path_ids, *kyc_ids] if eid in runtime.evidence_registry]
    missing = [f"Investigation halted prior to verified completion ({reason}); manual analyst review required."]
    rationale = (
        f"INSUFFICIENT_DATA (request_info): forced finish triggered ({reason}). "
        f"Grounded evidence records collected: {len(runtime.evidence_registry)}. "
        f"Missing evidence: {missing[0]}"
    )
    hyps = [
        Hypothesis(
            label=HypothesisLabel.SUSPICIOUS,
            explanation="Potential layering/structuring activity remains unresolved pending full verification.",
            confidence=to_confidence("0.50"),
            regulatory_citations=citations,
            evidence_ids=ev_ids,
        ),
        Hypothesis(
            label=HypothesisLabel.BENIGN,
            explanation="Potential commercial or personal explanation remains uncorroborated due to incomplete run.",
            confidence=to_confidence("0.50"),
            regulatory_citations=citations,
            evidence_ids=ev_ids,
        ),
    ]
    payload = _candidate_draft_payload(
        runtime=runtime,
        alert=alert,
        thread_id=thread_id,
        disposition=DispositionDecision.REQUEST_INFO,
        rationale=rationale,
        confidence=0.40,
        hypotheses=hyps,
        citations=citations,
        degraded=degraded,
        missing_evidence=missing,
    )
    return await persist_verified_worksheet(
        runtime=runtime,
        alert=alert,
        thread_id=thread_id,
        agent_label=ctx.label,
        model_name=model_name,
        payload=payload,
        hypotheses=hyps,
        citations=citations,
        missing_evidence=missing,
        verify=ctx.deterministic_verifier,
    )


async def retrieve_frozen_lessons(state: InvestigationState, ctx: RunContext) -> list[str]:
    if not (ctx.reflexion_enabled and ctx.memory_enabled):
        return []
    top = await asyncio.to_thread(memory_store.retrieve_top_lessons, f"{state.alert.rule_name} scatter gather", 3)
    return [f"[{les.lesson_id}] IF {les.trigger_precondition} THEN {les.actionable_rule}" for les in top]


def tool_message(tc: ToolCallRequest, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "role": "tool",
        "tool_call_id": tc.id,
        "name": tc.name,
        "content": json.dumps(result, sort_keys=True, default=str),
    }


def _c1_loop_telemetry(
    runtime: AgentToolRuntime, ctx: RunContext, ws: DispositionWorksheet, elapsed_ms: float
) -> dict[str, Any]:
    steps = [
        {"step": 1, "name": "Alert Intake & Validation", "status": "completed"},
        {"step": 2, "name": "6-Slot System Prompt & Tool Schema Init", "status": "completed"},
        {
            "step": 3,
            "name": f"LLM ReAct Tool Loop ({runtime.replan_count} Replan)",
            "status": "completed",
            "duration_ms": round(elapsed_ms, 1),
        },
        {"step": 4, "name": "Competing Hypotheses Synthesis", "status": "completed"},
        {"step": 5, "name": "Deterministic Verification", "status": "completed"},
        {"step": 6, "name": "Human Approval", "status": "waiting_approval"},
        {"step": 7, "name": "Case Commit & Reporting", "status": "pending"},
    ]
    runs = [
        {
            "agent_id": "c1_investigator",
            "agent_name": "C1 Single-Agent LLM Investigator",
            "task": "OpenAI tool-calling loop with Decimal calc, bounded replanning & verifier",
            "status": "completed",
            "started_at": utc_now_iso(),
            "duration_ms": round(elapsed_ms, 1),
            "tool_calls": ctx.ledger.calls_used,
            "summary": ws.recommendation_rationale[:240],
        }
    ]
    return {"workflow_steps": steps, "agent_runs": runs}


async def handle_finish_attempt(
    *,
    tc: ToolCallRequest,
    tool_res: dict[str, Any],
    runtime: AgentToolRuntime,
    ctx: RunContext,
    state: InvestigationState,
    model_name: str,
    repair_used: bool,
    turns_left: bool,
) -> tuple[Optional[DispositionWorksheet], Optional[dict[str, Any]], bool, str]:
    """Process a `finish` tool call; returns `(worksheet, repair_tool_msg, repair_used, fail_reason)`."""
    can_retry = (not repair_used) and turns_left and ctx.ledger.check_llm_allowed().allowed
    if is_error(tool_res) or runtime.finish_submission is None:
        err_detail = str(tool_res.get("message") or "finish schema validation failed")
        if can_retry and ctx.ledger.try_critique_retry().allowed:
            val_feedback: dict[str, Any] = {
                "status": "error",
                "error_code": "FINISH_VALIDATION_ERROR",
                "detail": err_detail,
                "instruction": "Fix the schema validation error above and call `finish` once more.",
            }
            return None, tool_message(tc, val_feedback), True, ""
        return None, None, repair_used, f"finish validation failed: {err_detail[:120]}"

    degraded = sorted({*runtime.degraded_evidence, *all_security_notes(ctx), *tool_error_notes(ctx)})
    sub = runtime.finish_submission
    ok, v_errors, payload, hyps, citations, discrepancies = validate_finish_candidate(
        runtime, sub, state.alert, state.thread_id, degraded, verify=ctx.deterministic_verifier
    )
    if ok or not ctx.deterministic_verifier:
        if not ok:
            payload["verification_status"] = "failed"
            payload["verification_discrepancies"] = discrepancies
        ws = await persist_verified_worksheet(
            runtime=runtime,
            alert=state.alert,
            thread_id=state.thread_id,
            agent_label=ctx.label,
            model_name=model_name,
            payload=payload,
            hypotheses=hyps,
            citations=citations,
            missing_evidence=list(sub.missing_evidence),
            verify=ctx.deterministic_verifier,
        )
        return ws, None, repair_used, ""

    runtime.finish_submission = None
    if can_retry and ctx.ledger.try_critique_retry().allowed:
        ver_feedback: dict[str, Any] = {
            "status": "error",
            "error_code": "VERIFICATION_FAILED",
            "errors": v_errors,
            "known_evidence_ids": sorted(runtime.evidence_registry.keys())[:50],
            "instruction": (
                "Repair every verification error above: quote ONLY exact INR numbers from tool results, "
                "cite ONLY IDs in known_evidence_ids, include retrieved regulatory_citations, remove any "
                "guilt claims, and call `finish` again."
            ),
        }
        return None, tool_message(tc, ver_feedback), True, ""
    return None, None, repair_used, f"verifier rejected finish after repair: {'; '.join(v_errors)[:140]}"


async def execute_tool_turn_batch(
    *,
    tool_calls: list[ToolCallRequest],
    messages: list[dict[str, Any]],
    runtime: AgentToolRuntime,
    ctx: RunContext,
    state: InvestigationState,
    model_name: str,
    repair_used: bool,
    turns_left: bool,
) -> tuple[Optional[DispositionWorksheet], bool, bool, str]:
    """Run all tool calls in one assistant turn; returns `(worksheet, repair_used, abort, reason)`."""
    reason = ""
    for tc in tool_calls:
        res = await runtime.execute(tc.name, tc.arguments)
        if tc.name == "finish":
            ws, repair_msg, repair_used, fail_reason = await handle_finish_attempt(
                tc=tc,
                tool_res=res,
                runtime=runtime,
                ctx=ctx,
                state=state,
                model_name=model_name,
                repair_used=repair_used,
                turns_left=turns_left,
            )
            if ws is not None:
                return ws, repair_used, False, ""
            if repair_msg is not None:
                messages.append(repair_msg)
                continue
            return None, repair_used, True, fail_reason

        messages.append(tool_message(tc, res))
        if is_error(res) and res.get("error_code") == "BUDGET_EXCEEDED":
            reason = str(res.get("message") or "tool call budget exhausted")
    return None, repair_used, False, reason


def _select_turn_tools(
    turn: int, max_turns: int, tools_schema: list[dict[str, Any]], messages: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if turn == max_turns - 1 and max_turns >= 4 and tools_schema:
        messages.append(
            {
                "role": "user",
                "content": (
                    f"Budget notice: final turn ({turn + 1}/{max_turns}). Do not call further read tools; "
                    "invoke `finish` now using only the verified evidence and INR figures already gathered."
                ),
            }
        )
        return [t for t in tools_schema if t.get("function", {}).get("name") == "finish"] or tools_schema
    return tools_schema


async def _drive_tool_loop(
    *,
    messages: list[dict[str, Any]],
    tools_schema: list[dict[str, Any]],
    runtime: AgentToolRuntime,
    ctx: RunContext,
    state: InvestigationState,
    llm_client: LLMClientProtocol,
    model_id: str,
    max_turns: int,
) -> DispositionWorksheet:
    spec = ctx.policy.model_for("c1_investigator")
    repair_used = False
    forced_reason = f"max_turns ({max_turns}) reached without finish"
    last_model = model_id

    for turn in range(max_turns):
        budget_ok = ctx.ledger.check_llm_allowed()
        if not budget_ok.allowed:
            forced_reason = budget_ok.message
            break
        active_tools = _select_turn_tools(turn, max_turns, tools_schema, messages)
        resp: ChatResponse = await llm_client.chat(
            messages,
            tools=active_tools,
            model=model_id,
            temperature=spec.temperature,
            max_tokens=spec.max_tokens,
            seed=ctx.seed,
        )
        last_model = resp.model or model_id
        ctx.ledger.record_llm_usage(resp.usage.prompt_tokens, resp.usage.completion_tokens, resp.cost_usd)
        messages.append(resp.to_assistant_message())

        if not resp.tool_calls:
            if turn + 1 < max_turns and ctx.ledger.check_llm_allowed().allowed:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Conclude by invoking the `finish` tool with `recommended_disposition`, "
                            "`suspicious_hypothesis`, `benign_hypothesis`, `missing_evidence`, and "
                            "`regulatory_citations`."
                        ),
                    }
                )
                continue
            forced_reason = "assistant stopped without calling finish"
            break

        ws, repair_used, abort, batch_reason = await execute_tool_turn_batch(
            tool_calls=resp.tool_calls,
            messages=messages,
            runtime=runtime,
            ctx=ctx,
            state=state,
            model_name=last_model,
            repair_used=repair_used,
            turns_left=(turn + 1 < max_turns),
        )
        if batch_reason:
            forced_reason = batch_reason
        if ws is not None:
            return ws
        if abort:
            forced_reason = batch_reason or forced_reason
            break

    return await persist_forced_finish(
        runtime=runtime,
        ctx=ctx,
        alert=state.alert,
        thread_id=state.thread_id,
        model_name=last_model,
        reason=forced_reason,
    )


def _c1_state_update(
    state: InvestigationState,
    ctx: RunContext,
    runtime: AgentToolRuntime,
    messages: list[dict[str, Any]],
    lessons: list[str],
    worksheet: DispositionWorksheet,
    elapsed_ms: float,
) -> dict[str, Any]:
    degraded = sorted({*worksheet.degraded_evidence, *runtime.degraded_evidence, *all_security_notes(ctx)})
    updated_alert = state.alert.model_copy(
        update={"root_account": runtime.root_account, "network_accounts": runtime.network_accounts}
    )
    flow_summary = compute_network_flow_summary(
        runtime.root_account, runtime.transactions, runtime.fund_flow_paths, runtime.kyc_profiles
    )
    trimmed_msgs, rolling = trim_messages_with_summary(
        messages, state.rolling_summary, window_size=ctx.policy.memory.short_term_window_messages
    )
    return {
        "alert": updated_alert,
        "plan": runtime.plan_snapshot(),
        "replan_count": runtime.replan_count,
        "transactions": runtime.transactions,
        "fund_flow_paths": runtime.fund_flow_paths,
        "initial_fund_flow_paths": runtime.initial_fund_flow_paths,
        "kyc_profiles": runtime.kyc_profiles,
        "regulatory_clauses": runtime.regulatory_clauses,
        "regulatory_snippets": runtime.regulatory_snippets,
        "evidence_registry": runtime.evidence_registry,
        "calc_log": runtime.calc_log,
        "replan_records": runtime.replan_records,
        "tool_execution_log": runtime.tool_execution_log,
        "react_steps_completed": sum(1 for m in messages if m.get("role") == "assistant"),
        "retrieved_lessons": lessons,
        "degraded_evidence": degraded,
        "active_hypotheses": worksheet.hypotheses,
        "worksheet": worksheet,
        "flow_summary": flow_summary,
        "reasoning_mode": "llm_tool_loop",
        "messages": trimmed_msgs,
        "rolling_summary": rolling,
        "error": (
            "verification_failed"
            if (ctx.deterministic_verifier and worksheet.verification_status == "failed")
            else None
        ),
        "is_complete": True,
        "current_node": "agent_loop",
        "current_step": state.current_step + 1,
        **sync_budget(ctx),
        **_c1_loop_telemetry(runtime, ctx, worksheet, elapsed_ms),
    }


async def run_c1_agent_loop(
    state: InvestigationState,
    ctx: RunContext,
    llm_client: LLMClientProtocol,
    *,
    max_turns: int = DEFAULT_MAX_TURNS,
) -> dict[str, Any]:
    """Execute the genuine C1 LLM ReAct / tool-calling loop and return LangGraph state update."""
    t0 = time.perf_counter()
    lessons = await retrieve_frozen_lessons(state, ctx)
    model_id = await asyncio.to_thread(resolve_model_for_role, ctx, "c1_investigator")
    runtime = AgentToolRuntime(
        role="c1_single",
        box=ctx.box("primary"),
        alert=state.alert,
        configurable_graph=ctx.configurable_graph,
        replanning_enabled=ctx.replanning_enabled,
        allow_calc=ctx.allow_calc,
        allow_registry=ctx.allow_registry,
        allow_rag=ctx.allow_rag,
        initial_registry=state.evidence_registry,
    )
    tools_schema = build_openai_tools(
        "c1_single",
        include_finish=True,
        replanning_enabled=ctx.replanning_enabled,
        allow_calc=ctx.allow_calc,
        allow_registry=ctx.allow_registry,
        allow_rag=ctx.allow_rag,
    )
    sys_txt = render_c1_system_prompt(ctx.policy, lessons=lessons, replanning_enabled=ctx.replanning_enabled)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": sys_txt},
        {"role": "user", "content": render_alert_user_message(state.alert)},
    ]
    ws = await _drive_tool_loop(
        messages=messages, tools_schema=tools_schema, runtime=runtime, ctx=ctx,
        state=state, llm_client=llm_client, model_id=model_id, max_turns=max_turns,
    )
    return _c1_state_update(state, ctx, runtime, messages, lessons, ws, (time.perf_counter() - t0) * 1000)
