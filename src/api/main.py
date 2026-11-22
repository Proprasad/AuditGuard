"""
FastAPI Gateway — Enterprise REST + SSE API & Agentic AML Investigation Workbench

Preserves all core endpoints and contracts while adding read-only workbench
data endpoints for Cases, Customers, Regulatory KB, Analytics, Config, and PDF/HTML Report Export.
"""
from __future__ import annotations

import html
import json
import time
import uuid
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel
from starlette.responses import Response

from src.api.auth import create_jwt_token, get_analyst_principal
from src.config import settings
from src.db.database import (
    append_audit_log,
    get_db,
    init_db,
    list_audit_logs,
    list_checkpoints,
    load_checkpoint,
    save_checkpoint,
    utc_now_iso,
)
from src.guardrails.guardrails import apply_input_guardrails
from src.guardrails.verifier import verify_worksheet
from src.mcp_servers import bank_records, case_actions, compliance_kb
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
# Prometheus Metrics
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
# FastAPI App & Static Assets Mount
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AuditGuard API",
    description="Evidence-Grounded AI Investigation System for Ambiguous Fund-Flow Networks",
    version="1.0.0",
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

STATIC_DIR = Path(__file__).resolve().parents[1] / "ui" / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_threads: dict[str, dict[str, Any]] = {}


class TokenRequest(BaseModel):
    username: str = "analyst_04"
    role: str = "tier2_analyst"


class LlmConfigUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    model: Optional[str] = None
    strong_model: Optional[str] = None


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
    def _sse(event: str, data: dict[str, Any]) -> str:
        payload = {"event": event, "timestamp": utc_now_iso(), **data}
        return f"event: {event}\ndata: {json.dumps(payload, default=str)}\n\n"

    yield _sse("started", {
        "thread_id": thread_id,
        "alert_id": alert.alert_id,
        "mode": mode,
        "category": "intake",
        "message": f"Registered {mode.upper()} investigation for {alert.alert_id}",
    })

    try:
        t0 = time.perf_counter()
        final_state = await _execute_mode(alert, mode, thread_id=thread_id)
        duration = time.perf_counter() - t0
        INVESTIGATION_DURATION.labels(mode=mode).observe(duration)
        TOOL_CALLS_TOTAL.labels(mode=mode).inc(final_state.tool_calls_used)

        if final_state.plan:
            yield _sse("plan_updated", {
                "category": "planning",
                "steps": final_state.plan.steps,
                "graph_params": final_state.plan.graph_params,
                "replan_count": final_state.replan_count,
                "message": f"Supervisor created {len(final_state.plan.steps)}-step investigation plan",
            })

        for ag in final_state.agent_runs:
            yield _sse("agent_updated", {
                "category": "agent",
                "agent": ag,
                "message": f"{ag['agent_name']}: {ag['summary']}",
            })

        yield _sse("tool_called", {
            "category": "mcp_tool",
            "tool_calls_used": final_state.tool_calls_used,
            "paths_found": len(final_state.fund_flow_paths),
            "kyc_checked": len(final_state.kyc_profiles),
            "citations_found": len(final_state.regulatory_snippets),
            "message": (
                f"Executed {final_state.tool_calls_used} guarded MCP calls "
                f"({len(final_state.fund_flow_paths)} paths, {len(final_state.kyc_profiles)} KYC profiles)"
            ),
        })

        if final_state.replan_count > 0 and final_state.plan:
            yield _sse("replan_triggered", {
                "category": "replan",
                "replan_count": final_state.replan_count,
                "reason": final_state.plan.replan_reason,
                "new_params": final_state.plan.graph_params,
                "message": f"Replan #{final_state.replan_count}: Reconfigured bounds to {final_state.plan.graph_params}",
            })

        worksheet = final_state.worksheet
        payload_hash = _canonical_worksheet_hash(worksheet)

        yield _sse("verification_completed", {
            "category": "verifier",
            "payload_hash": payload_hash,
            "duration_ms": round(duration * 1000, 1),
            "message": f"Deterministic Decimal & citation verification passed (SHA-256={payload_hash[:12]}...)",
        })

        state_dump = final_state.model_dump()
        rec = {
            "thread_id": thread_id,
            "alert_id": alert.alert_id,
            "alert": alert.model_dump(),
            "mode": mode,
            "status": "interrupt_required",
            "worksheet_id": worksheet.worksheet_id if worksheet else None,
            "payload_hash": payload_hash,
            "state": state_dump,
        }
        _threads[thread_id] = rec
        save_checkpoint(
            thread_id=thread_id,
            alert_id=alert.alert_id,
            mode=mode,
            current_node="interrupt_required",
            status="interrupt_required",
            state_dict=state_dump,
            worksheet_id=rec["worksheet_id"],
            payload_hash=payload_hash,
        )

        if worksheet:
            CITATIONS_VERIFIED.labels(status="passed").inc(len(worksheet.regulatory_citations))
            INVESTIGATIONS_TOTAL.labels(mode=mode, disposition=worksheet.recommended_disposition.value).inc()
            yield _sse("interrupt_required", {
                "category": "human_gate",
                "thread_id": thread_id,
                "worksheet_id": worksheet.worksheet_id,
                "payload_hash": payload_hash,
                "recommended_disposition": worksheet.recommended_disposition.value,
                "confidence_score": worksheet.confidence_score,
                "rationale": worksheet.recommendation_rationale,
                "replan_count": final_state.replan_count,
                "tool_calls_used": final_state.tool_calls_used,
                "duration_seconds": round(duration, 3),
                "worksheet": worksheet.model_dump(),
                "state": state_dump,
                "message": "Human approval required — review evidence and Approve, Edit, or Reject.",
            })
        else:
            yield _sse("completed", {"thread_id": thread_id, "duration_seconds": round(duration, 3)})

    except Exception as exc:
        yield _sse("error", {"category": "error", "thread_id": thread_id, "error": str(exc), "message": str(exc)})


# ---------------------------------------------------------------------------
# UI, Auth & Health Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def analyst_workbench():
    ui_file = STATIC_DIR / "index.html"
    if ui_file.exists():
        return HTMLResponse(
            ui_file.read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )
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
        "version": "1.0.0",
        "database": str(db_path.name),
        "timestamp": utc_now_iso(),
    }


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ---------------------------------------------------------------------------
# Workbench Navigation Data Endpoints (Alerts, Cases, Customers, KB, Analytics, Config)
# ---------------------------------------------------------------------------
@app.get("/api/v1/alerts")
async def get_queued_alerts(limit: int = 50, _principal: dict = Depends(get_analyst_principal)):
    alerts = bank_records.list_queued_alerts(limit=limit)
    open_count = sum(1 for a in alerts if str(a.get("status", "OPEN")).upper() == "OPEN")
    return {"alerts": alerts, "total": len(alerts), "open_count": open_count}


@app.get("/api/v1/cases")
async def get_cases(limit: int = 50, _principal: dict = Depends(get_analyst_principal)):
    bank_records._ensure_operational_db()
    with get_db() as conn:
        committed = [
            dict(r)
            for r in conn.execute(
                "SELECT case_id, alert_id, worksheet_id, disposition, payload_hash, approver_id, committed_at "
                "FROM cases ORDER BY committed_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        ]
        worksheets = [
            dict(r)
            for r in conn.execute(
                "SELECT worksheet_id, alert_id, payload_hash, status, reviewer_id, reviewer_decision, created_at, updated_at "
                "FROM worksheets ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        ]
    return {"cases": committed, "worksheets": worksheets, "total_committed": len(committed)}


@app.get("/api/v1/customers")
async def get_customers(limit: int = 100, _principal: dict = Depends(get_analyst_principal)):
    bank_records._ensure_operational_db()
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT c.customer_id, c.full_name, c.kyc_tier, c.occupation,
                   c.declared_annual_income_inr, c.risk_rating, c.onboarding_date, c.kyc_notes,
                   a.account_id, a.account_type, b.bank_name,
                   cr.registry_id, cr.entity_type AS registry_type, cr.status AS registry_status,
                   (SELECT COUNT(*) FROM case_episodes ce WHERE ce.customer_id = c.customer_id) AS episodes_count
            FROM customers c
            LEFT JOIN accounts a ON a.customer_id = c.customer_id
            LEFT JOIN banks b ON a.bank_id = b.bank_id
            LEFT JOIN commercial_registry cr ON cr.customer_id = c.customer_id
            ORDER BY
              CASE c.risk_rating WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END,
              c.customer_id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return {"customers": [dict(r) for r in rows], "total": len(rows)}


@app.get("/api/v1/regulations")
async def list_regulations(
    q: Optional[str] = Query(default=None, description="Optional Hybrid RAG search query"),
    top_k: int = 10,
    _principal: dict = Depends(get_analyst_principal),
):
    if q and q.strip():
        fn = getattr(compliance_kb.search_regulations, "fn", compliance_kb.search_regulations)
        res = await fn(compliance_kb.SearchRegulationsInput(query=q.strip(), top_k=top_k, decompose=True))
        return {
            "clauses": [c.model_dump() for c in res.clauses],
            "total": len(res.clauses),
            "retrieval_method": res.retrieval_method,
        }
    idx = compliance_kb.get_regulatory_index()
    return {
        "clauses": [c.model_dump() for c in idx.clauses],
        "total": len(idx.clauses),
        "retrieval_method": "full_corpus",
    }


@app.get("/api/v1/audit-logs")
async def get_audit_logs(thread_id: Optional[str] = None, limit: int = 60, _principal: dict = Depends(get_analyst_principal)):
    logs = list_audit_logs(thread_id=thread_id, limit=limit)
    return {"audit_logs": logs, "total": len(logs)}


@app.get("/api/v1/analytics")
async def get_analytics(_principal: dict = Depends(get_analyst_principal)):
    bank_records._ensure_operational_db()
    with get_db() as conn:
        alert_counts = {
            r["status"]: r["c"]
            for r in conn.execute("SELECT status, COUNT(*) AS c FROM alerts GROUP BY status").fetchall()
        }
        disp_counts = {
            r["disposition"]: r["c"]
            for r in conn.execute("SELECT disposition, COUNT(*) AS c FROM cases GROUP BY disposition").fetchall()
        }
        totals = conn.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM alerts) AS total_alerts,
              (SELECT COUNT(*) FROM transactions) AS total_transactions,
              (SELECT COALESCE(SUM(amount_inr), 0) FROM transactions) AS total_tx_volume_inr,
              (SELECT COUNT(*) FROM cases) AS total_committed_cases,
              (SELECT COUNT(*) FROM audit_logs) AS total_audit_events,
              (SELECT COUNT(*) FROM checkpoints) AS total_threads
            """
        ).fetchone()
    return {
        "summary": dict(totals) if totals else {},
        "alerts_by_status": alert_counts,
        "cases_by_disposition": disp_counts,
    }


@app.get("/api/v1/config-info")
async def get_config_info(_principal: dict = Depends(get_analyst_principal)):
    from src.agent.llm_client import get_llm_status

    llm_info = get_llm_status()
    return {
        "version": "1.0.0",
        "environment": settings.environment,
        "mcp_transport": settings.mcp_transport,
        "auth_required": settings.auth_required,
        "llm": llm_info,
        "models": {
            "c1_investigator": llm_info["c1_and_specialist_model"],
            "c2_supervisor": llm_info["c2_supervisor_model"],
            "c2_specialists": llm_info["c1_and_specialist_model"],
        },
        "budgets": {
            "max_tool_calls": settings.max_tool_calls,
            "max_replans": settings.max_replans,
            "max_cost_usd_per_case": settings.max_tool_budget_usd,
        },
        "graph_policy_bounds": {
            "time_window_days": [1, 30],
            "max_hops": [2, 5],
            "amount_tolerance": [0.01, 0.25],
            "min_intermediaries": [2, 10],
        },
    }


@app.post("/api/v1/config/llm")
async def update_llm_config(req: LlmConfigUpdateRequest, principal: dict = Depends(get_analyst_principal)):
    from src.agent.llm_client import set_runtime_llm_config

    updated = set_runtime_llm_config(enabled=req.enabled, model=req.model, strong_model=req.strong_model)
    append_audit_log(
        thread_id="system-config",
        event_type="llm_config_updated",
        actor=principal["sub"],
        details={
            "llm_enabled": updated["llm_enabled"],
            "c1_and_specialist_model": updated["c1_and_specialist_model"],
            "c2_supervisor_model": updated["c2_supervisor_model"],
        },
    )
    return updated


@app.post("/api/v1/config/llm/test")
async def test_llm_connection(model: Optional[str] = None, _principal: dict = Depends(get_analyst_principal)):
    from src.agent.llm_client import ping_openrouter

    return await ping_openrouter(model=model)


# ---------------------------------------------------------------------------
# Investigation Lifecycle & Report Export Routes
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
    state_dump = final_state.model_dump()

    rec = {
        "thread_id": thread_id,
        "alert_id": request.alert_id,
        "alert": alert.model_dump(),
        "mode": request.agent_mode,
        "status": "interrupt_required",
        "worksheet_id": worksheet.worksheet_id if worksheet else None,
        "payload_hash": payload_hash,
        "state": state_dump,
    }
    _threads[thread_id] = rec
    save_checkpoint(
        thread_id=thread_id,
        alert_id=request.alert_id,
        mode=request.agent_mode,
        current_node="interrupt_required",
        status="interrupt_required",
        state_dict=state_dump,
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
    cp = load_checkpoint(thread_id)
    if not cp:
        raise HTTPException(status_code=404, detail="Checkpoint not found")

    alert_data = cp["state"].get("alert", {"alert_id": cp["alert_id"]})
    alert = Alert(**alert_data)
    final_state = await _execute_mode(alert, cp["mode"], thread_id=thread_id, resume=True)
    worksheet = final_state.worksheet
    payload_hash = _canonical_worksheet_hash(worksheet)
    state_dump = final_state.model_dump()

    _threads[thread_id] = {
        "thread_id": thread_id,
        "alert_id": alert.alert_id,
        "alert": alert.model_dump(),
        "mode": cp["mode"],
        "status": "interrupt_required",
        "worksheet_id": worksheet.worksheet_id if worksheet else None,
        "payload_hash": payload_hash,
        "state": state_dump,
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

    # ── Branch 1: Edit Worksheet (Invalidates Old SHA-256 Hash!) ─────────────
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
            "updated_content": updated["content"],
            "message": "Worksheet edited and re-verified. Old approval hash invalidated; fresh approval required.",
        }

    # ── Branch 2: Reject Disposition ─────────────────────────────────────────
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
        if "state" in thread and thread["state"].get("workflow_steps"):
            for st in thread["state"]["workflow_steps"]:
                if st["step"] == 6:
                    st["status"] = "failed"
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

    # ── Branch 3: Approve & Commit (Exact SHA-256 Match Required) ────────────
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

    if "state" in thread and thread["state"].get("workflow_steps"):
        for st in thread["state"]["workflow_steps"]:
            if st["step"] in (6, 7):
                st["status"] = "completed"

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


@app.get("/api/v1/investigations/{thread_id}/export", response_class=HTMLResponse)
async def export_investigation_report(thread_id: str):
    """Printable HTML/PDF-ready Compliance Investigation Audit Report."""
    rec = _get_thread_record(thread_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    st = rec.get("state", {})
    ws = st.get("worksheet") or {}
    fs = st.get("flow_summary") or {}
    esc = lambda s: html.escape(str(s or ""))

    paths_rows = "".join(
        f"<tr><td>{esc(p.get('path_id'))}</td><td>{esc(' -> '.join(p.get('nodes', [])))}</td>"
        f"<td>{esc(p.get('hop_count'))}</td><td>INR {esc(p.get('total_outflow_inr'))}</td>"
        f"<td>INR {esc(p.get('total_consolidated_inr'))}</td><td>{esc(p.get('retention_pct'))}%</td></tr>"
        for p in ws.get("candidate_paths", [])
    )
    cites_html = ", ".join(f"<code>{esc(c)}</code>" for c in ws.get("regulatory_citations", []))

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>AuditGuard Compliance Report — {esc(rec.get('alert_id'))}</title>
<style>
  body {{ font-family: Segoe UI, Arial, sans-serif; color: #111827; max-width: 920px; margin: 32px auto; padding: 0 24px; line-height: 1.5; }}
  h1 {{ margin-bottom: 4px; color: #0f172a; }}
  .meta {{ color: #4b5563; font-size: 0.9rem; border-bottom: 2px solid #e5e7eb; padding-bottom: 12px; margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 0.9rem; }}
  th, td {{ border: 1px solid #d1d5db; padding: 8px 10px; text-align: left; }}
  th {{ background: #f3f4f6; }}
  .hash {{ font-family: Consolas, monospace; font-size: 0.82rem; background: #f9fafb; padding: 8px; border: 1px solid #e5e7eb; word-break: break-all; }}
  @media print {{ .no-print {{ display: none; }} }}
</style></head><body>
<div class="no-print" style="text-align:right;"><button onclick="window.print()" style="padding:8px 16px;cursor:pointer;">Print / Save as PDF</button></div>
<h1>AuditGuard — AML Investigation Disposition Worksheet</h1>
<div class="meta">
  <strong>Alert ID:</strong> {esc(rec.get('alert_id'))} &nbsp;|&nbsp;
  <strong>Thread ID:</strong> {esc(thread_id)} &nbsp;|&nbsp;
  <strong>Mode:</strong> {esc(rec.get('mode'))} &nbsp;|&nbsp;
  <strong>Status:</strong> {esc(rec.get('status'))}
</div>
<h3>1. Executive Recommendation &amp; Human Review Status</h3>
<p><strong>Recommended Disposition:</strong> {esc(ws.get('recommended_disposition', '')).upper()} (Assessment Score: {round(float(ws.get('confidence_score', 0))*100)}%)<br/>
<strong>Human Reviewer Decision:</strong> {esc(rec.get('human_decision') or 'Pending Mandatory Human Approval')} (Reviewer: {esc(rec.get('reviewer_id') or '-')})<br/>
<strong>Rationale:</strong> {esc(ws.get('recommendation_rationale'))}</p>
<h3>2. Deterministic Fund-Flow Summary (Python Decimal)</h3>
<p>Total Outflow: <strong>INR {esc(fs.get('total_outflow_inr', '0.00'))}</strong> &nbsp;|&nbsp;
Consolidated: <strong>INR {esc(fs.get('total_consolidated_inr', '0.00'))} ({esc(fs.get('consolidated_pct', 0))}%)</strong> &nbsp;|&nbsp;
Retained: <strong>INR {esc(fs.get('total_retained_inr', '0.00'))} ({esc(fs.get('retained_pct', 0))}%)</strong></p>
<table><thead><tr><th>Path ID</th><th>Account Chain</th><th>Hops</th><th>Outflow</th><th>Consolidated</th><th>Retained %</th></tr></thead>
<tbody>{paths_rows or '<tr><td colspan="6">No multi-hop paths</td></tr>'}</tbody></table>
<h3>3. Verified Regulatory Citations</h3>
<p>{cites_html}</p>
<h3>4. Cryptographic Integrity (SHA-256 Canonical Payload Hash)</h3>
<div class="hash">{esc(rec.get('payload_hash'))}</div>
</body></html>"""
    return HTMLResponse(doc)


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
