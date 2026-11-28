"""Investigation execution + durable event log. Streams are READ-ONLY subscribers of `investigation_events`."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import logging
import time
from typing import Any
import uuid

from src.api.metrics import CITATIONS_VERIFIED, INVESTIGATION_DURATION, INVESTIGATIONS_TOTAL, TOOL_CALLS_TOTAL
from src.core.canonical import dec_str
from src.db import case_repo
from src.db.database import append_audit_log, append_event, save_checkpoint
from src.models import Alert, InvestigationState
from src.observability.loki_shipper import emit_loki_log

logger = logging.getLogger("auditguard.runner")
TERMINAL_EVENTS = {"interrupt_required", "verification_failed", "completed", "error"}
_TASKS: set[asyncio.Task[Any]] = set()


def emit(thread_id: str, alert_id: str, mode: str, event: str, data: dict[str, Any]) -> None:
    append_event(thread_id, event, data)
    emit_loki_log(
        stream_type="agent_flow",
        event=event,
        message=f"[{mode.upper()} | {alert_id}] {event}: {data.get('message', '')}",
        level="ERROR" if event == "error" else "INFO",
        extra={
            "thread_id": thread_id,
            "alert_id": alert_id,
            "mode": mode,
            "category": data.get("category", ""),
        },
    )


async def execute_mode(
    alert: Alert, mode: str, thread_id: str, resume: bool = False, on_event: Any = None
) -> InvestigationState:
    if mode == "c0_fixed":
        from src.agent.c0_fixed import run_fixed_pipeline

        return await run_fixed_pipeline(alert, thread_id=thread_id, resume=resume, on_event=on_event)
    if mode == "rule_engine":
        from src.agent.rule_engine import run_rule_engine

        return await run_rule_engine(alert, thread_id=thread_id, resume=resume, on_event=on_event)
    if mode == "c2_multi":
        from src.agent.c2_multi import run_multi_agent

        return await run_multi_agent(alert, thread_id=thread_id, resume=resume, on_event=on_event)
    from src.agent.c1_single import run_investigation

    return await run_investigation(alert, mode=mode, thread_id=thread_id, resume=resume, on_event=on_event)


def register_thread(alert: Alert, mode: str, owner: str) -> str:
    thread_id = f"thr-{uuid.uuid4().hex[:12]}"
    save_checkpoint(
        thread_id=thread_id,
        alert_id=alert.alert_id,
        mode=mode,
        current_node="registered",
        status="running",
        state_dict={"alert": alert.model_dump(mode="json"), "thread_id": thread_id},
    )
    # Maker-checker anchor: the requester is recorded once in the append-only audit log (never in mutable state).
    append_audit_log(
        thread_id, case_repo.REQUESTED_EVENT, owner, {"alert_id": alert.alert_id, "mode": mode}
    )
    emit(
        thread_id,
        alert.alert_id,
        mode,
        "started",
        {
            "category": "intake",
            "thread_id": thread_id,
            "alert_id": alert.alert_id,
            "mode": mode,
            "message": f"Registered {mode.upper()} investigation for {alert.alert_id}",
        },
    )
    return thread_id


def _node_events(node: str, inv: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    plan = inv.get("plan") or {}
    if node in ("plan", "supervisor_plan"):
        steps = plan.get("steps", [])
        return [
            (
                "plan_updated",
                {
                    "category": "planning",
                    "steps": steps,
                    "graph_params": plan.get("graph_params"),
                    "replan_count": inv.get("replan_count", 0),
                    "message": f"Plan with {len(steps)} steps",
                },
            )
        ]
    if node in ("gather_evidence", "flow_tracer", "parallel_specialists"):
        return [
            (
                "tool_called",
                {
                    "category": "mcp_tool",
                    "node": node,
                    "tool_calls_used": inv.get("tool_calls_used", 0),
                    "paths_found": len(inv.get("fund_flow_paths", [])),
                    "kyc_checked": len(inv.get("kyc_profiles", [])),
                    "citations_found": len(inv.get("regulatory_snippets", [])),
                    "message": f"[{node}] Executed {inv.get('tool_calls_used', 0)} guarded MCP calls",
                },
            )
        ]
    if node in ("form_hypotheses", "supervisor_hypotheses", "hypothesis_evaluation"):
        hyps = [{"label": h["label"], "confidence": h["confidence"]} for h in inv.get("active_hypotheses", [])]
        ha = inv.get("hypothesis_assessment") or {}
        return [
            (
                "hypotheses_scored",
                {
                    "category": "reasoning",
                    "reasoning_mode": inv.get("reasoning_mode"),
                    "hypotheses": hyps,
                    "overall_outcome": ha.get("overall_outcome"),
                    "message": f"Evaluated competing hypotheses ({inv.get('reasoning_mode')})",
                },
            )
        ]
    if node in ("replan", "supervisor_replan", "flow_replan"):
        return [
            (
                "replan_triggered",
                {
                    "category": "replan",
                    "replan_count": inv.get("replan_count", 0),
                    "reason": plan.get("replan_reason"),
                    "new_params": plan.get("graph_params"),
                    "message": f"Replan #{inv.get('replan_count', 0)}",
                },
            )
        ]
    if node in ("draft", "reporter_critic", "agent_loop", "c2_agent_team"):
        return _draft_completion_events(node, inv)
    return []


def _llm_loop_summary_events(node: str, inv: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    plan = inv.get("plan") or {}
    steps = plan.get("steps", [])
    events: list[tuple[str, dict[str, Any]]] = [
        (
            "plan_updated",
            {
                "category": "planning",
                "steps": steps,
                "graph_params": plan.get("graph_params"),
                "replan_count": inv.get("replan_count", 0),
                "message": f"Plan with {len(steps)} steps",
            },
        ),
        (
            "tool_called",
            {
                "category": "mcp_tool",
                "node": node,
                "tool_calls_used": inv.get("tool_calls_used", 0),
                "paths_found": len(inv.get("fund_flow_paths", [])),
                "kyc_checked": len(inv.get("kyc_profiles", [])),
                "citations_found": len(inv.get("regulatory_snippets", [])),
                "message": f"[{node}] Executed {inv.get('tool_calls_used', 0)} guarded tool calls",
            },
        ),
    ]
    if inv.get("replan_count", 0) > 0:
        events.append(
            (
                "replan_triggered",
                {
                    "category": "replan",
                    "replan_count": inv.get("replan_count", 0),
                    "reason": plan.get("replan_reason"),
                    "new_params": plan.get("graph_params"),
                    "message": f"Replan #{inv.get('replan_count', 0)}",
                },
            )
        )
    hyps = [{"label": h["label"], "confidence": h["confidence"]} for h in inv.get("active_hypotheses", [])]
    events.append(
        (
            "hypotheses_scored",
            {
                "category": "reasoning",
                "reasoning_mode": inv.get("reasoning_mode"),
                "hypotheses": hyps,
                "message": f"Scored competing hypotheses ({inv.get('reasoning_mode')})",
            },
        )
    )
    return events


def _draft_completion_events(node: str, inv: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    events = _llm_loop_summary_events(node, inv) if node in ("agent_loop", "c2_agent_team") else []
    events.extend(
        ("agent_updated", {"category": "agent", "agent": a, "message": f"{a['agent_name']}: {a['summary']}"})
        for a in inv.get("agent_runs", [])
    )
    failed = inv.get("error") == "verification_failed"
    events.append(
        (
            "verification_completed",
            {
                "category": "verifier",
                "status": "failed" if failed else "passed",
                "message": "Deterministic verification " + ("FAILED (fail-closed)" if failed else "passed"),
            },
        )
    )
    return events


def live_callback(thread_id: str, alert: Alert, mode: str) -> Callable[[str, dict[str, Any]], None]:
    """Translate LangGraph node completions into durable SSE events as they happen (not after the run)."""

    def on_node(node: str, inv: dict[str, Any]) -> None:
        for ev_name, payload in _node_events(node, inv):
            emit(thread_id, alert.alert_id, mode, ev_name, payload)

    return on_node


def _record_thread_error(thread_id: str, alert: Alert, mode: str, correlation: str) -> None:
    save_checkpoint(
        thread_id=thread_id,
        alert_id=alert.alert_id,
        mode=mode,
        current_node="error",
        status="error",
        state_dict={"alert": alert.model_dump(mode="json"), "thread_id": thread_id, "correlation_id": correlation},
    )
    emit(
        thread_id,
        alert.alert_id,
        mode,
        "error",
        {
            "category": "error",
            "correlation_id": correlation,
            "message": f"Investigation failed (correlation_id={correlation})",
        },
    )


def _finalize_thread_db(thread_id: str, alert: Alert, mode: str, state: InvestigationState, duration: float) -> str:
    worksheet = state.worksheet
    if worksheet is None:
        raise RuntimeError("investigation finished without a worksheet")
    failed = state.error == "verification_failed"
    status = "verification_failed" if failed else "interrupt_required"
    stored = case_repo.get_worksheet(worksheet.worksheet_id)
    payload_hash = stored["current_hash"] if stored else worksheet.payload_hash
    state_dump = state.model_dump(mode="json")
    save_checkpoint(
        thread_id=thread_id,
        alert_id=alert.alert_id,
        mode=mode,
        current_node=status,
        status=status,
        state_dict=state_dump,
        worksheet_id=worksheet.worksheet_id,
        payload_hash=payload_hash,
    )
    CITATIONS_VERIFIED.labels(status="failed" if failed else "passed").inc(len(worksheet.regulatory_citations))
    INVESTIGATIONS_TOTAL.labels(mode=mode, disposition=worksheet.recommended_disposition.value).inc()

    terminal = {
        "category": "human_gate",
        "thread_id": thread_id,
        "worksheet_id": worksheet.worksheet_id,
        "payload_hash": payload_hash,
        "recommended_disposition": worksheet.recommended_disposition.value,
        "confidence_score": dec_str(worksheet.confidence_score),
        "rationale": worksheet.recommendation_rationale,
        "replan_count": state.replan_count,
        "tool_calls_used": state.tool_calls_used,
        "tool_errors": state.tool_error_count,
        "duration_seconds": round(duration, 3),
        "worksheet": worksheet.model_dump(mode="json"),
        "state": state_dump,
        "approved_hash": None if failed else payload_hash,
        "approval_token": None,
        "message": (
            "Verification FAILED (fail-closed): edit the rationale until it verifies; commit is blocked."
            if failed
            else "Human approval required - review evidence and Approve, Edit, or Reject."
        ),
    }
    emit(thread_id, alert.alert_id, mode, status, terminal)
    return status


async def run_thread(thread_id: str, alert: Alert, mode: str, resume: bool = False) -> str:
    """Execute (or resume) a thread, persist its result + events and issue the single-use approval token."""
    started = time.perf_counter()
    try:
        state = await execute_mode(
            alert, mode, thread_id, resume=resume, on_event=live_callback(thread_id, alert, mode)
        )
        if state.worksheet is None:
            raise RuntimeError("investigation finished without a worksheet")
    except Exception:  # noqa: BLE001 - background boundary: log with a correlation id, never leak internals
        correlation = uuid.uuid4().hex[:12]
        logger.exception("investigation failed thread=%s correlation_id=%s", thread_id, correlation)
        await asyncio.to_thread(_record_thread_error, thread_id, alert, mode, correlation)
        return "error"

    duration = time.perf_counter() - started
    INVESTIGATION_DURATION.labels(mode=mode).observe(duration)
    TOOL_CALLS_TOTAL.labels(mode=mode).inc(state.tool_calls_used)
    return await asyncio.to_thread(_finalize_thread_db, thread_id, alert, mode, state, duration)


def start_background(thread_id: str, alert: Alert, mode: str) -> None:
    task = asyncio.create_task(run_thread(thread_id, alert, mode))
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
