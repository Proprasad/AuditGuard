"""Investigation execution + durable event log. Streams are READ-ONLY subscribers of `investigation_events`."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

from src.api.metrics import CITATIONS_VERIFIED, INVESTIGATION_DURATION, INVESTIGATIONS_TOTAL, TOOL_CALLS_TOTAL
from src.db import case_repo
from src.db.database import append_event, save_checkpoint
from src.models import Alert, InvestigationState
from src.observability.loki_shipper import emit_loki_log

logger = logging.getLogger("auditguard.runner")
TERMINAL_EVENTS = {"interrupt_required", "verification_failed", "completed", "error"}
_TASKS: set[asyncio.Task[Any]] = set()


def emit(thread_id: str, alert_id: str, mode: str, event: str, data: dict[str, Any]) -> None:
    append_event(thread_id, event, data)
    emit_loki_log(
        stream_type="agent_flow", event=event, message=f"[{mode.upper()} | {alert_id}] {event}: {data.get('message', '')}",
        level="ERROR" if event == "error" else "INFO",
        extra={"thread_id": thread_id, "alert_id": alert_id, "mode": mode, "category": data.get("category", "")},
    )


async def execute_mode(alert: Alert, mode: str, thread_id: str, resume: bool = False) -> InvestigationState:
    if mode == "c0_fixed":
        from src.agent.c0_fixed import run_fixed_pipeline

        return await run_fixed_pipeline(alert, thread_id=thread_id)
    if mode == "c2_multi":
        from src.agent.c2_multi import run_multi_agent

        return await run_multi_agent(alert, thread_id=thread_id)
    from src.agent.c1_single import run_investigation

    return await run_investigation(alert, mode=mode, thread_id=thread_id, resume=resume)


def register_thread(alert: Alert, mode: str, owner: str) -> str:
    thread_id = f"thr-{uuid.uuid4().hex[:12]}"
    save_checkpoint(thread_id=thread_id, alert_id=alert.alert_id, mode=mode, current_node="registered", status="running",
                    state_dict={"alert": alert.model_dump(mode="json"), "thread_id": thread_id, "owner": owner})
    emit(thread_id, alert.alert_id, mode, "started", {
        "category": "intake", "thread_id": thread_id, "alert_id": alert.alert_id, "mode": mode,
        "message": f"Registered {mode.upper()} investigation for {alert.alert_id}",
    })
    return thread_id


def _replay_events(thread_id: str, alert: Alert, mode: str, state: InvestigationState, duration: float) -> None:
    def push(event: str, data: dict[str, Any]) -> None:
        emit(thread_id, alert.alert_id, mode, event, data)

    if state.plan:
        push("plan_updated", {"category": "planning", "steps": state.plan.steps, "graph_params": state.plan.graph_params.model_dump(mode="json"),
                              "replan_count": state.replan_count, "message": f"Plan with {len(state.plan.steps)} steps"})
    for agent in state.agent_runs:
        push("agent_updated", {"category": "agent", "agent": agent, "message": f"{agent['agent_name']}: {agent['summary']}"})
    push("tool_called", {"category": "mcp_tool", "tool_calls_used": state.tool_calls_used, "paths_found": len(state.fund_flow_paths),
                         "kyc_checked": len(state.kyc_profiles), "citations_found": len(state.regulatory_snippets),
                         "message": f"Executed {state.tool_calls_used} guarded MCP calls"})
    if state.replan_count and state.plan:
        push("replan_triggered", {"category": "replan", "replan_count": state.replan_count, "reason": state.plan.replan_reason,
                                  "new_params": state.plan.graph_params.model_dump(mode="json"),
                                  "message": f"Replan #{state.replan_count}"})
    push("verification_completed", {"category": "verifier", "duration_ms": round(duration * 1000, 1),
                                    "status": "failed" if state.error == "verification_failed" else "passed",
                                    "message": "Deterministic verification " + ("FAILED (fail-closed)" if state.error == "verification_failed" else "passed")})


async def run_thread(thread_id: str, alert: Alert, mode: str, resume: bool = False) -> str:
    """Execute (or resume) a thread, persist its result + events and issue the single-use approval token."""
    started = time.perf_counter()
    try:
        state = await execute_mode(alert, mode, thread_id, resume=resume)
        if state.worksheet is None:
            raise RuntimeError("investigation finished without a worksheet")
    except Exception:  # noqa: BLE001 - background boundary: log with a correlation id, never leak internals
        correlation = uuid.uuid4().hex[:12]
        logger.exception("investigation failed thread=%s correlation_id=%s", thread_id, correlation)
        save_checkpoint(thread_id=thread_id, alert_id=alert.alert_id, mode=mode, current_node="error", status="error",
                        state_dict={"alert": alert.model_dump(mode="json"), "thread_id": thread_id, "correlation_id": correlation})
        emit(thread_id, alert.alert_id, mode, "error", {"category": "error", "correlation_id": correlation,
                                                        "message": f"Investigation failed (correlation_id={correlation})"})
        return "error"

    duration = time.perf_counter() - started
    INVESTIGATION_DURATION.labels(mode=mode).observe(duration)
    TOOL_CALLS_TOTAL.labels(mode=mode).inc(state.tool_calls_used)
    worksheet = state.worksheet
    failed = state.error == "verification_failed"
    status = "verification_failed" if failed else "interrupt_required"
    approval = None if failed else case_repo.issue_approval_token(thread_id, worksheet.worksheet_id)
    stored = case_repo.get_worksheet(worksheet.worksheet_id)
    payload_hash = stored["current_hash"] if stored else worksheet.payload_hash
    state_dump = state.model_dump(mode="json")
    save_checkpoint(thread_id=thread_id, alert_id=alert.alert_id, mode=mode, current_node=status, status=status,
                    state_dict=state_dump, worksheet_id=worksheet.worksheet_id, payload_hash=payload_hash)
    CITATIONS_VERIFIED.labels(status="failed" if failed else "passed").inc(len(worksheet.regulatory_citations))
    INVESTIGATIONS_TOTAL.labels(mode=mode, disposition=worksheet.recommended_disposition.value).inc()

    _replay_events(thread_id, alert, mode, state, duration)
    terminal = {
        "category": "human_gate", "thread_id": thread_id, "worksheet_id": worksheet.worksheet_id, "payload_hash": payload_hash,
        "recommended_disposition": worksheet.recommended_disposition.value, "confidence_score": worksheet.confidence_score,
        "rationale": worksheet.recommendation_rationale, "replan_count": state.replan_count,
        "tool_calls_used": state.tool_calls_used, "duration_seconds": round(duration, 3),
        "worksheet": worksheet.model_dump(mode="json"), "state": state_dump,
        "approved_hash": approval["approved_hash"] if approval else None,
        "approval_token": approval["approval_token"] if approval else None,
        "message": ("Verification FAILED (fail-closed): edit the rationale until it verifies; commit is blocked."
                    if failed else "Human approval required - review evidence and Approve, Edit, or Reject."),
    }
    emit(thread_id, alert.alert_id, mode, status, terminal)
    return status


def start_background(thread_id: str, alert: Alert, mode: str) -> None:
    task = asyncio.create_task(run_thread(thread_id, alert, mode))
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
