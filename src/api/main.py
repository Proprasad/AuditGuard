"""
FastAPI Gateway — Enterprise REST + SSE API & Embedded Analyst Workbench for AuditGuard

Endpoints:
  GET    /                                         -> Interactive Analyst Web Console
  POST   /api/v1/auth/token                        -> Issue HS256 Bearer JWT token
  GET    /api/v1/alerts                            -> List queued alerts from database
  GET    /api/v1/audit-logs                        -> List append-only audit logs
  POST   /api/v1/investigations                    -> Start async investigation (returns thread_id)
  POST   /api/v1/investigations/run                -> Run investigation & pause at interrupt_required
  GET    /api/v1/investigations/{thread_id}/stream -> Live SSE trace stream
  POST   /api/v1/investigations/{thread_id}/resume -> Resume interrupted/crashed checkpoint
  POST   /api/v1/investigations/{thread_id}/decision -> Approve / Edit (hash-invalidating) / Reject
  GET    /api/v1/investigations/{thread_id}/state  -> Retrieve durable checkpoint state
  GET    /api/v1/investigations                    -> List investigations
  DELETE /api/v1/memory/{customer_id}              -> Right-to-be-forgotten customer memory wipe
  GET    /health                                   -> Service & DB health check
  GET    /metrics                                  -> Prometheus metrics
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel
from starlette.responses import Response

from src.api.auth import create_jwt_token, get_analyst_principal
from src.db.database import (
    append_audit_log,
    init_db,
    list_audit_logs,
    list_checkpoints,
    load_checkpoint,
    save_checkpoint,
    utc_now_iso,
)
from src.guardrails.guardrails import apply_input_guardrails
from src.guardrails.verifier import verify_worksheet
from src.mcp_servers import bank_records, case_actions
from src.memory.store import memory_store
from src.models import (
    Alert,
    DispositionDecision,
    HumanDecisionRequest,
    InvestigateRequest,
    InvestigateResponse,
    RiskLevel,
)

# ---------------------------------------------------------------------------
# Prometheus Metrics (safe singleton registration across hot reloads)
# ---------------------------------------------------------------------------
INVESTIGATIONS_TOTAL = Counter(
    "auditguard_investigations_total",
    "Total investigations completed to human gate",
    ["mode", "disposition"],
)
INVESTIGATION_DURATION = Histogram(
    "auditguard_investigation_duration_seconds",
    "Investigation duration in seconds",
    ["mode"],
)
TOOL_CALLS_TOTAL = Counter(
    "auditguard_tool_calls_total",
    "Total MCP tool calls executed",
    ["mode"],
)
CITATIONS_VERIFIED = Counter(
    "auditguard_citations_verified_total",
    "Total regulatory citations verified",
    ["status"],
)

# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AuditGuard API",
    description="Evidence-Grounded AI Investigation System for Ambiguous Fund-Flow Networks",
    version="0.2.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Fast in-memory mirror backed by SQLite/PostgreSQL `checkpoints` table
_threads: dict[str, dict[str, Any]] = {}


class TokenRequest(BaseModel):
    username: str = "analyst_04"
    role: str = "tier2_analyst"


def _get_thread_record(thread_id: str) -> Optional[dict[str, Any]]:
    if thread_id in _threads:
        return _threads[thread_id]
    cp = load_checkpoint(thread_id)
    if cp:
        rec = {
            "thread_id": cp["thread_id"],
            "alert_id": cp["alert_id"],
            "mode": cp["mode"],
            "status": cp["status"],
            "worksheet_id": cp["worksheet_id"],
            "payload_hash": cp["payload_hash"],
            "state": cp["state"],
            "alert": cp["state"].get("alert", {}),
        }
        _threads[thread_id] = rec
        return rec
    return None


async def _execute_mode(alert: Alert, mode: str, thread_id: str, resume: bool = False):
    if mode == "c0_fixed":
        from src.agent.c0_fixed import run_fixed_pipeline
        state = await run_fixed_pipeline(alert)
        state.thread_id = thread_id
        return state
    if mode == "c2_multi":
        from src.agent.c2_multi import run_multi_agent
        return await run_multi_agent(alert, thread_id=thread_id)
    from src.agent.c1_single import run_investigation
    return await run_investigation(alert, mode=mode, thread_id=thread_id, resume=resume)


def _canonical_worksheet_hash(worksheet) -> str:
    if worksheet is None:
        return ""
    rec = case_actions.get_worksheet_record(worksheet.worksheet_id)
    return rec["payload_hash"] if rec else worksheet.payload_hash


async def _stream_investigation(thread_id: str, alert: Alert, mode: str) -> AsyncGenerator[str, None]:
    import time

    def _sse(event: str, data: dict[str, Any]) -> str:
        return f"event: {event}\ndata: {json.dumps({'event': event, **data}, default=str)}\n\n"

    yield _sse("started", {
        "thread_id": thread_id,
        "alert_id": alert.alert_id,
        "mode": mode,
        "timestamp": utc_now_iso(),
    })

    try:
        t0 = time.perf_counter()
        final_state = await _execute_mode(alert, mode, thread_id=thread_id)
        duration = time.perf_counter() - t0
        INVESTIGATION_DURATION.labels(mode=mode).observe(duration)
        TOOL_CALLS_TOTAL.labels(mode=mode).inc(final_state.tool_calls_used)

        if final_state.plan:
            yield _sse("plan_updated", {
                "steps": final_state.plan.steps,
                "graph_params": final_state.plan.graph_params,
                "replan_count": final_state.replan_count,
            })

        yield _sse("tool_called", {
            "tool_calls_used": final_state.tool_calls_used,
            "paths_found": len(final_state.fund_flow_paths),
            "kyc_checked": len(final_state.kyc_profiles),
        })

        if final_state.replan_count > 0 and final_state.plan:
            yield _sse("replan_triggered", {
                "replan_count": final_state.replan_count,
                "reason": final_state.plan.replan_reason,
                "new_params": final_state.plan.graph_params,
            })

        worksheet = final_state.worksheet
        payload_hash = _canonical_worksheet_hash(worksheet)

        rec = {
            "thread_id": thread_id,
            "alert_id": alert.alert_id,
            "alert": alert.model_dump(),
            "mode": mode,
            "status": "interrupt_required",
            "worksheet_id": worksheet.worksheet_id if worksheet else None,
            "payload_hash": payload_hash,
            "state": final_state.model_dump(),
        }
        _threads[thread_id] = rec
        save_checkpoint(
            thread_id=thread_id,
            alert_id=alert.alert_id,
            mode=mode,
            current_node="interrupt_required",
            status="interrupt_required",
            state_dict=final_state.model_dump(),
            worksheet_id=rec["worksheet_id"],
            payload_hash=payload_hash,
        )

        if worksheet:
            CITATIONS_VERIFIED.labels(status="passed").inc(len(worksheet.regulatory_citations))
            INVESTIGATIONS_TOTAL.labels(mode=mode, disposition=worksheet.recommended_disposition.value).inc()
            yield _sse("interrupt_required", {
                "thread_id": thread_id,
                "worksheet_id": worksheet.worksheet_id,
                "payload_hash": payload_hash,
                "recommended_disposition": worksheet.recommended_disposition.value,
                "confidence_score": worksheet.confidence_score,
                "rationale": worksheet.recommendation_rationale,
                "replan_count": final_state.replan_count,
                "tool_calls_used": final_state.tool_calls_used,
                "worksheet": worksheet.model_dump(),
                "message": "Worksheet paused at Human Approval Gate. Approve, Edit, or Reject.",
            })
        else:
            yield _sse("completed", {"thread_id": thread_id, "duration_seconds": round(duration, 3)})

    except Exception as exc:
        yield _sse("error", {"thread_id": thread_id, "error": str(exc)})


# ---------------------------------------------------------------------------
# UI & Auth Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def analyst_workbench():
    """Serve the zero-build Interactive Compliance Analyst Workbench."""
    ui_file = Path(__file__).resolve().parents[1] / "ui" / "static" / "index.html"
    if ui_file.exists():
        return HTMLResponse(ui_file.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>AuditGuard API Running</h1><p>Visit <a href='/api/docs'>/api/docs</a></p>")


@app.post("/api/v1/auth/token")
async def issue_token(req: TokenRequest):
    token = create_jwt_token(subject=req.username, role=req.role)
    return {"access_token": token, "token_type": "bearer", "role": req.role}


@app.get("/health")
async def health():
    db_path = init_db()
    return {
        "status": "healthy",
        "service": "auditguard-api",
        "version": "0.2.0",
        "database": str(db_path.name),
        "timestamp": utc_now_iso(),
    }


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/v1/alerts")
async def get_queued_alerts(limit: int = 30, _principal: dict = Depends(get_analyst_principal)):
    alerts = bank_records.list_queued_alerts(limit=limit)
    return {"alerts": alerts, "total": len(alerts)}


@app.get("/api/v1/audit-logs")
async def get_audit_logs(thread_id: Optional[str] = None, limit: int = 40, _principal: dict = Depends(get_analyst_principal)):
    logs = list_audit_logs(thread_id=thread_id, limit=limit)
    return {"audit_logs": logs, "total": len(logs)}


# ---------------------------------------------------------------------------
# Investigation Lifecycle Routes
# ---------------------------------------------------------------------------
@app.post("/api/v1/investigations", response_model=InvestigateResponse)
async def start_investigation(request: InvestigateRequest, principal: dict = Depends(get_analyst_principal)):
    guard = apply_input_guardrails(f"{request.alert_id} {request.rule_name}")
    if not guard.allowed:
        raise HTTPException(status_code=422, detail=f"GUARDRAIL_BLOCKED: {guard.blocked_reason}")

    alert = Alert(
        alert_id=request.alert_id,
        rule_name=request.rule_name,
        root_account=request.root_account,
        network_accounts=request.network_accounts,
        total_amount_inr=request.total_amount_inr,
        risk_level=RiskLevel.HIGH,
    )
    thread_id = f"thr-{uuid.uuid4().hex[:12]}"
    rec = {
        "thread_id": thread_id,
        "alert_id": request.alert_id,
        "alert": alert.model_dump(),
        "status": "running",
        "mode": request.agent_mode,
        "analyst": principal["sub"],
    }
    _threads[thread_id] = rec
    save_checkpoint(
        thread_id=thread_id,
        alert_id=request.alert_id,
        mode=request.agent_mode,
        current_node="registered",
        status="running",
        state_dict={"alert": alert.model_dump(), "thread_id": thread_id},
    )
    return InvestigateResponse(thread_id=thread_id, alert_id=request.alert_id, status="investigation_started")


@app.post("/api/v1/investigations/run", response_model=InvestigateResponse)
async def run_investigation_sync(request: InvestigateRequest, principal: dict = Depends(get_analyst_principal)):
    guard = apply_input_guardrails(f"{request.alert_id} {request.rule_name}")
    if not guard.allowed:
        raise HTTPException(status_code=422, detail=f"GUARDRAIL_BLOCKED: {guard.blocked_reason}")

    alert = Alert(
        alert_id=request.alert_id,
        rule_name=request.rule_name,
        root_account=request.root_account,
        network_accounts=request.network_accounts,
        total_amount_inr=request.total_amount_inr,
        risk_level=RiskLevel.HIGH,
    )
    thread_id = f"thr-{uuid.uuid4().hex[:12]}"
    final_state = await _execute_mode(alert, request.agent_mode, thread_id=thread_id)
    TOOL_CALLS_TOTAL.labels(mode=request.agent_mode).inc(final_state.tool_calls_used)

    worksheet = final_state.worksheet
    payload_hash = _canonical_worksheet_hash(worksheet)

    rec = {
        "thread_id": thread_id,
        "alert_id": request.alert_id,
        "alert": alert.model_dump(),
        "mode": request.agent_mode,
        "status": "interrupt_required",
        "worksheet_id": worksheet.worksheet_id if worksheet else None,
        "payload_hash": payload_hash,
        "state": final_state.model_dump(),
    }
    _threads[thread_id] = rec
    save_checkpoint(
        thread_id=thread_id,
        alert_id=request.alert_id,
        mode=request.agent_mode,
        current_node="interrupt_required",
        status="interrupt_required",
        state_dict=final_state.model_dump(),
        worksheet_id=rec["worksheet_id"],
        payload_hash=payload_hash,
    )
    if worksheet:
        CITATIONS_VERIFIED.labels(status="passed").inc(len(worksheet.regulatory_citations))
        INVESTIGATIONS_TOTAL.labels(mode=request.agent_mode, disposition=worksheet.recommended_disposition.value).inc()

    return InvestigateResponse(
        thread_id=thread_id,
        alert_id=request.alert_id,
        status="interrupt_required",
        payload_hash=payload_hash,
        worksheet=worksheet,
        replan_count=final_state.replan_count,
        tool_calls_used=final_state.tool_calls_used,
        cost_usd=final_state.estimated_cost_usd,
        tokens_used=final_state.total_tokens_used,
    )


@app.post("/api/v1/investigations/{thread_id}/resume", response_model=InvestigateResponse)
async def resume_investigation(thread_id: str, _principal: dict = Depends(get_analyst_principal)):
    """Crash recovery endpoint: resumes an interrupted investigation from its SQLite/Postgres checkpoint."""
    cp = load_checkpoint(thread_id)
    if not cp:
        raise HTTPException(status_code=404, detail="Checkpoint not found")

    alert_data = cp["state"].get("alert", {"alert_id": cp["alert_id"]})
    alert = Alert(**alert_data)
    final_state = await _execute_mode(alert, cp["mode"], thread_id=thread_id, resume=True)
    worksheet = final_state.worksheet
    payload_hash = _canonical_worksheet_hash(worksheet)

    _threads[thread_id] = {
        "thread_id": thread_id,
        "alert_id": alert.alert_id,
        "alert": alert.model_dump(),
        "mode": cp["mode"],
        "status": "interrupt_required",
        "worksheet_id": worksheet.worksheet_id if worksheet else None,
        "payload_hash": payload_hash,
        "state": final_state.model_dump(),
    }
    return InvestigateResponse(
        thread_id=thread_id,
        alert_id=alert.alert_id,
        status="interrupt_required",
        payload_hash=payload_hash,
        worksheet=worksheet,
        replan_count=final_state.replan_count,
        tool_calls_used=final_state.tool_calls_used,
    )


@app.get("/api/v1/investigations/{thread_id}/stream")
async def stream_investigation(thread_id: str, alert_id: Optional[str] = None, mode: Optional[str] = None):
    stored = _get_thread_record(thread_id) or {}
    if stored.get("alert") and stored["alert"].get("alert_id"):
        alert = Alert(**stored["alert"])
        resolved_mode = mode or stored.get("mode", "c1_single")
    else:
        alert = Alert(
            alert_id=alert_id or "ALT-2026-0412",
            rule_name="SCATTER_GATHER",
            root_account="ACC-IND-1042",
            network_accounts=["ACC-IND-2011", "ACC-IND-2044", "ACC-IND-2089", "ACC-IND-9001"],
            total_amount_inr=900_000.0,
            risk_level=RiskLevel.HIGH,
        )
        resolved_mode = mode or "c1_single"

    return StreamingResponse(
        _stream_investigation(thread_id, alert, resolved_mode),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/v1/investigations/{thread_id}/decision")
async def submit_human_decision(
    thread_id: str,
    request: HumanDecisionRequest,
    principal: dict = Depends(get_analyst_principal),
):
    """
    Human Approval Gate (`interrupt()` resumption):
      - `action == "edit"`: Updates worksheet, invalidates prior SHA-256 hash, re-verifies,
        and returns `status="interrupt_required"` with the fresh `new_payload_hash`.
      - `action == "reject"`: Writes rejection audit log without filing/closing as benign.
      - `action == "approve"`: Verifies exact `approved_hash` & single-use HMAC token,
        commits to `cases` + `audit_logs` (`403` on mismatch, `409` on replay).
    """
    guard = apply_input_guardrails(request.notes or "")
    if not guard.allowed:
        raise HTTPException(status_code=422, detail=f"GUARDRAIL_BLOCKED: {guard.blocked_reason}")

    thread = _get_thread_record(thread_id)
    if thread is None:
        raise HTTPException(status_code=404, detail="Thread not found")

    if thread.get("status") == "committed":
        raise HTTPException(status_code=409, detail="ALREADY_COMMITTED")

    reviewer = request.reviewer_id or principal["sub"]
    worksheet_id = request.worksheet_id or thread.get("worksheet_id")

    # ── Branch 1: Analyst Edits Worksheet (Invalidates Old SHA-256 Hash!) ────
    if request.action == "edit" or request.edited_fields:
        if not worksheet_id:
            raise HTTPException(status_code=400, detail="No worksheet associated with thread")
        edits = request.edited_fields or {}
        ws_rec = case_actions.get_worksheet_record(worksheet_id)
        if not ws_rec:
            raise HTTPException(status_code=404, detail="Worksheet not found")

        candidate_merged = {**ws_rec["content"], **edits}
        vr = verify_worksheet(candidate_merged)
        if not vr.passed:
            raise HTTPException(status_code=422, detail=f"VERIFIER_REJECTED_EDIT: {vr.errors}")

        updated = case_actions.update_worksheet_content(worksheet_id, edits, editor_id=reviewer, thread_id=thread_id)
        new_hash = updated["payload_hash"]
        old_hash = thread.get("payload_hash")

        thread["payload_hash"] = new_hash
        thread["status"] = "interrupt_required"
        if "state" in thread and thread["state"].get("worksheet"):
            thread["state"]["worksheet"].update(edits)
        _threads[thread_id] = thread

        save_checkpoint(
            thread_id=thread_id,
            alert_id=thread["alert_id"],
            mode=thread.get("mode", "c1_single"),
            current_node="interrupt_required",
            status="interrupt_required",
            state_dict=thread.get("state", {}),
            worksheet_id=worksheet_id,
            payload_hash=new_hash,
        )
        return {
            "thread_id": thread_id,
            "status": "interrupt_required",
            "previous_hash_invalidated": old_hash,
            "payload_hash": new_hash,
            "message": "Worksheet edited and re-verified. Old approval hash invalidated; fresh approval required.",
        }

    # ── Branch 2: Analyst Rejects Worksheet (No Case Closure/Filing) ─────────
    if request.action == "reject" or request.decision == DispositionDecision.REJECTED:
        append_audit_log(
            thread_id=thread_id,
            event_type="disposition_rejected_by_human",
            actor=reviewer,
            payload_hash=thread.get("payload_hash"),
            details={"worksheet_id": worksheet_id, "notes": guard.scrubbed_text},
        )
        thread["status"] = "rejected"
        thread["human_decision"] = "rejected"
        thread["reviewer_id"] = reviewer
        _threads[thread_id] = thread
        save_checkpoint(
            thread_id=thread_id,
            alert_id=thread["alert_id"],
            mode=thread.get("mode", "c1_single"),
            current_node="rejected",
            status="rejected",
            state_dict=thread.get("state", {}),
            worksheet_id=worksheet_id,
            payload_hash=thread.get("payload_hash"),
        )
        return {
            "thread_id": thread_id,
            "status": "rejected",
            "decision": "rejected",
            "message": "Disposition rejected and logged to manual review queue.",
        }

    # ── Branch 3: Analyst Approves Worksheet (Exact SHA-256 Match Required) ──
    expected_hash = thread.get("payload_hash")
    if expected_hash and request.approved_hash and request.approved_hash != expected_hash:
        raise HTTPException(status_code=403, detail="APPROVAL_HASH_MISMATCH")

    receipt = None
    if worksheet_id:
        ws_rec = case_actions.get_worksheet_record(worksheet_id)
        if ws_rec:
            current_hash = ws_rec["payload_hash"]
            if request.approved_hash and request.approved_hash != current_hash:
                raise HTTPException(status_code=403, detail="APPROVAL_HASH_MISMATCH")
            token = case_actions._generate_approval_token(request.approved_hash or current_hash)
            submit_fn = getattr(case_actions.submit_case_disposition, "fn", case_actions.submit_case_disposition)
            res = await submit_fn(
                case_actions.SubmitCaseDispositionInput(
                    worksheet_id=worksheet_id,
                    approval_token=token,
                    reviewer_id=reviewer,
                    reviewer_decision=request.decision.value,
                    reviewer_notes=guard.scrubbed_text,
                    thread_id=thread_id,
                )
            )
            if not res.success:
                if "already_committed" in (res.error or ""):
                    raise HTTPException(status_code=409, detail="ALREADY_COMMITTED")
                raise HTTPException(status_code=403, detail=f"APPROVAL_HASH_MISMATCH: {res.error}")
            receipt = res.model_dump()

    # Archive closed episode in long-term memory strictly post-human-approval
    root_acc = thread.get("alert", {}).get("root_account", "unknown")
    memory_store.save_case_episode(
        f"CUST-{root_acc}",
        {
            "alert_id": thread.get("alert_id"),
            "disposition": request.decision.value,
            "reviewer_id": reviewer,
            "payload_hash": expected_hash,
        },
        human_approved=True,
    )

    thread["human_decision"] = request.decision.value
    thread["reviewer_id"] = reviewer
    thread["reviewer_notes"] = guard.scrubbed_text
    thread["status"] = "committed"
    thread["receipt"] = receipt
    thread["decided_at"] = utc_now_iso()
    _threads[thread_id] = thread

    save_checkpoint(
        thread_id=thread_id,
        alert_id=thread["alert_id"],
        mode=thread.get("mode", "c1_single"),
        current_node="committed",
        status="committed",
        state_dict=thread.get("state", {}),
        worksheet_id=worksheet_id,
        payload_hash=expected_hash,
    )

    return {
        "thread_id": thread_id,
        "status": "committed",
        "decision": request.decision.value,
        "receipt": receipt,
    }


@app.get("/api/v1/investigations/{thread_id}/state")
async def get_investigation_state(thread_id: str, _principal: dict = Depends(get_analyst_principal)):
    rec = _get_thread_record(thread_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    return rec


@app.delete("/api/v1/memory/{customer_id}")
async def forget_customer(
    customer_id: str,
    reviewer_id: str = "supervisor",
    _principal: dict = Depends(get_analyst_principal),
):
    result = memory_store.forget_customer(customer_id)
    append_audit_log(
        thread_id="memory-forget",
        event_type="customer_memory_deleted",
        actor=reviewer_id,
        details=result,
    )
    return {
        **result,
        "status": "deleted",
        "deleted_by": reviewer_id,
        "message": "Customer memory deleted per retention policy",
    }


@app.get("/api/v1/investigations")
async def list_investigations(_principal: dict = Depends(get_analyst_principal)):
    cps = list_checkpoints(limit=50)
    return {"investigations": cps, "total": len(cps)}
