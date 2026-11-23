"""
AuditGuard FastAPI application: thin HTTP layer. Business logic lives in `src/api/services/*`; every `/api/v1/*`
route is authenticated (JWT, role-gated), rate limited and returns masked errors with a correlation id.
"""
from __future__ import annotations

import asyncio
import html
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from decimal import Decimal
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel
from starlette.responses import Response

from src.api.auth import Principal, create_jwt_token, require_role
from src.api.ratelimit import enforce_login_limit, rate_limit_api
from src.api.services import approval as approval_service
from src.api.services import runner
from src.api.services.erasure import erase_customer
from src.api.services.threads import get_thread, thread_view
from src.api.users import authenticate, ensure_seed_users
from src.config import env_mapping, get_policy, reload_policy, settings, validate_startup
from src.core.canonical import to_money
from src.db.database import append_audit_log, get_ro_db, init_db, list_audit_logs, list_checkpoints, read_events, utc_now_iso
from src.guardrails.guardrails import apply_input_guardrails
from src.mcp_servers import bank_records, compliance_kb
from src.mcp_servers.client import call_mcp_tool
from src.models import (
    Alert,
    DecisionRequest,
    DispositionWorksheet,
    InvestigateRequest,
    InvestigateResponse,
    RiskLevel,
)
from src.observability.loki_shipper import emit_loki_log

logger = logging.getLogger("auditguard.api")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Fail-fast startup: validated secrets/auth, validated PolicyConfig, initialised schema, seeded users."""
    for warning in validate_startup():
        logger.warning("startup warning (dev/test only): %s", warning)
    policy = reload_policy()
    init_db()
    seeded = ensure_seed_users(env_mapping())
    logger.info("PolicyConfig %s loaded (max_tool_calls=%s, max_cost_usd=%s); users=%s", policy.config_version,
                policy.budgets.max_tool_calls, policy.budgets.max_cost_usd_per_case, seeded)
    yield


app = FastAPI(
    title="AuditGuard API",
    description="Evidence-Grounded AI Investigation System for Ambiguous Fund-Flow Networks",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def loki_http_request_logger(request: Request, call_next):
    t0 = time.perf_counter()
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/api/v1/"):
        ms = round((time.perf_counter() - t0) * 1000, 1)
        emit_loki_log(
            stream_type="http_api", event="api_request",
            message=f"{request.method} {path} -> {response.status_code} ({ms}ms)",
            level="WARN" if response.status_code >= 400 else "INFO",
            extra={"method": request.method, "path": path, "status_code": response.status_code, "duration_ms": ms},
        )
    return response


@app.exception_handler(Exception)
async def masked_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    correlation = uuid.uuid4().hex[:12]
    logger.exception("unhandled error path=%s correlation_id=%s", request.url.path, correlation)
    return JSONResponse(status_code=500, content={"detail": "INTERNAL_ERROR", "correlation_id": correlation})


@app.exception_handler(RequestValidationError)
async def validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [{"loc": list(e.get("loc", [])), "msg": str(e.get("msg", ""))} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


STATIC_DIR = Path(__file__).resolve().parents[1] / "ui" / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

ANALYST = Depends(require_role("analyst"))
ADMIN = Depends(require_role("admin"))
SENIOR = Depends(require_role("senior_reviewer"))
api_deps = [Depends(rate_limit_api)]


class TokenRequest(BaseModel):
    username: str
    password: str


class LlmConfigUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    model: Optional[str] = None
    strong_model: Optional[str] = None


def _alert_from_db(alert_id: str) -> Alert:
    """Alerts always come from the trusted operational DB (no client-supplied account/amount, no fallbacks)."""
    rec = bank_records.get_alert_record(alert_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"INVALID_ALERT_ID: alert {alert_id!r} not found")
    return Alert(
        alert_id=rec["alert_id"], rule_name=rec["rule_name"], root_account=rec["root_account"],
        network_accounts=rec["network_accounts"], total_amount_inr=rec["total_amount_inr"], risk_level=RiskLevel.HIGH,
    )


def _guard_alert_id(alert_id: str) -> None:
    guard = apply_input_guardrails(alert_id)
    if not guard.allowed:
        raise HTTPException(status_code=422, detail=f"GUARDRAIL_BLOCKED: {guard.blocked_reason}")


def _require_thread(thread_id: str) -> dict[str, Any]:
    thread = thread_view(thread_id)
    if thread is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    return thread


# ---------------------------------------------------------------------------
# UI, Auth & Health Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def analyst_workbench():
    ui_file = STATIC_DIR / "index.html"
    if ui_file.exists():
        return HTMLResponse(ui_file.read_text(encoding="utf-8"),
                            headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
    return HTMLResponse("<h1>AuditGuard API Running</h1><p>Visit <a href='/api/docs'>/api/docs</a></p>")


@app.post("/api/v1/auth/token")
async def issue_token(req: TokenRequest, request: Request):
    enforce_login_limit(request)
    role = await asyncio.to_thread(authenticate, req.username, req.password)
    if role is None:
        raise HTTPException(status_code=401, detail="UNAUTHORIZED: invalid credentials")
    return {"access_token": create_jwt_token(subject=req.username, role=role), "token_type": "bearer", "role": role}


@app.get("/health")
async def health():
    db_path = init_db()
    return {"status": "healthy", "service": "auditguard-api", "version": "1.0.0",
            "database": str(db_path.name), "timestamp": utc_now_iso()}


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ---------------------------------------------------------------------------
# Workbench Navigation Data Endpoints (read-only DB connections)
# ---------------------------------------------------------------------------
@app.get("/api/v1/alerts", dependencies=api_deps)
async def get_queued_alerts(limit: int = Query(50, ge=1, le=500), _p: Principal = ANALYST):
    alerts = bank_records.list_queued_alerts(limit=limit)
    open_count = sum(1 for a in alerts if str(a.get("status", "OPEN")).upper() == "OPEN")
    return {"alerts": alerts, "total": len(alerts), "open_count": open_count}


@app.get("/api/v1/cases", dependencies=api_deps)
async def get_cases(limit: int = Query(50, ge=1, le=500), _p: Principal = ANALYST):
    init_db()
    with get_ro_db() as conn:
        committed = [dict(r) for r in conn.execute(
            "SELECT case_id, alert_id, worksheet_id, disposition, payload_hash, approver_id, committed_at "
            "FROM cases ORDER BY committed_at DESC LIMIT ?", (limit,)).fetchall()]
        worksheets = [dict(r) for r in conn.execute(
            "SELECT worksheet_id, alert_id, payload_hash, status, reviewer_id, reviewer_decision, created_at, updated_at "
            "FROM worksheets ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()]
    return {"cases": committed, "worksheets": worksheets, "total_committed": len(committed)}


@app.get("/api/v1/customers", dependencies=api_deps)
async def get_customers(limit: int = Query(100, ge=1, le=500), _p: Principal = ANALYST):
    init_db()
    with get_ro_db() as conn:
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
            ORDER BY CASE c.risk_rating WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END, c.customer_id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return {"customers": [dict(r) for r in rows], "total": len(rows)}


@app.get("/api/v1/regulations", dependencies=api_deps)
async def list_regulations(
    q: Optional[str] = Query(default=None, description="Optional Hybrid RAG search query"),
    top_k: int = Query(10, ge=1, le=50),
    _p: Principal = ANALYST,
):
    if q and q.strip():
        res = await call_mcp_tool("compliance-kb", "search_regulations", {"query": q.strip(), "top_k": top_k, "decompose": True})
        if res.get("status") == "error":
            raise HTTPException(status_code=502, detail=f"{res.get('error_code')}: {res.get('error')}")
        return {"clauses": res["clauses"], "total": len(res["clauses"]), "retrieval_method": res.get("retrieval_method")}
    idx = compliance_kb.get_regulatory_index()
    return {"clauses": [c.model_dump() for c in idx.clauses], "total": len(idx.clauses), "retrieval_method": "full_corpus"}


@app.get("/api/v1/audit-logs", dependencies=api_deps)
async def get_audit_logs(thread_id: Optional[str] = None, limit: int = Query(60, ge=1, le=500), _p: Principal = ANALYST):
    logs = list_audit_logs(thread_id=thread_id, limit=limit)
    return {"audit_logs": logs, "total": len(logs)}


@app.get("/api/v1/analytics", dependencies=api_deps)
async def get_analytics(_p: Principal = ANALYST):
    init_db()
    with get_ro_db() as conn:
        alert_counts = {r["status"]: r["c"] for r in conn.execute("SELECT status, COUNT(*) AS c FROM alerts GROUP BY status").fetchall()}
        disp_counts = {r["disposition"]: r["c"] for r in conn.execute("SELECT disposition, COUNT(*) AS c FROM cases GROUP BY disposition").fetchall()}
        totals = conn.execute(
            """
            SELECT (SELECT COUNT(*) FROM alerts) AS total_alerts,
                   (SELECT COUNT(*) FROM transactions) AS total_transactions,
                   (SELECT COUNT(*) FROM cases) AS total_committed_cases,
                   (SELECT COUNT(*) FROM audit_logs) AS total_audit_events,
                   (SELECT COUNT(*) FROM checkpoints) AS total_threads
            """
        ).fetchone()
        volume = sum((to_money(r[0]) for r in conn.execute("SELECT amount_inr FROM transactions").fetchall()), Decimal("0.00"))
    summary = dict(totals) if totals else {}
    summary["total_tx_volume_inr"] = format(volume, "f")
    return {"summary": summary, "alerts_by_status": alert_counts, "cases_by_disposition": disp_counts}


@app.get("/api/v1/config-info", dependencies=api_deps)
async def get_config_info(_p: Principal = ANALYST):
    from src.agent.llm_client import get_llm_status

    llm_info = get_llm_status()
    policy = get_policy()
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
            "max_tool_calls": policy.budgets.max_tool_calls,
            "max_replans": policy.budgets.max_replans,
            "max_critique_retries": policy.budgets.max_critique_retries,
            "max_cost_usd_per_case": str(policy.budgets.max_cost_usd_per_case),
        },
        "graph_policy_bounds": policy.graph_bounds.model_dump(mode="json"),
    }


@app.post("/api/v1/config/llm", dependencies=api_deps)
async def update_llm_config(req: LlmConfigUpdateRequest, principal: Principal = ADMIN):
    from src.agent.llm_client import set_runtime_llm_config

    try:
        updated = set_runtime_llm_config(enabled=req.enabled, model=req.model, strong_model=req.strong_model)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"INVALID_LLM_CONFIG: {exc}") from exc
    append_audit_log(
        thread_id="system-config", event_type="llm_config_updated", actor=principal.sub,
        details={"llm_enabled": updated["llm_enabled"], "c1_and_specialist_model": updated["c1_and_specialist_model"],
                 "c2_supervisor_model": updated["c2_supervisor_model"]},
    )
    return updated


@app.post("/api/v1/config/llm/test", dependencies=api_deps)
async def test_llm_connection(model: Optional[str] = None, _p: Principal = ADMIN):
    from src.agent.llm_client import ping_openrouter

    return await ping_openrouter(model=model)


# ---------------------------------------------------------------------------
# Investigation Lifecycle
# ---------------------------------------------------------------------------
@app.post("/api/v1/investigations", response_model=InvestigateResponse, dependencies=api_deps)
async def start_investigation(request: InvestigateRequest, principal: Principal = ANALYST):
    _guard_alert_id(request.alert_id)
    alert = _alert_from_db(request.alert_id)
    thread_id = runner.register_thread(alert, request.agent_mode, principal.sub)
    runner.start_background(thread_id, alert, request.agent_mode)
    return InvestigateResponse(thread_id=thread_id, alert_id=request.alert_id, status="investigation_started")


def _response_for(thread: dict[str, Any]) -> InvestigateResponse:
    state = thread["state"]
    worksheet = state.get("worksheet")
    return InvestigateResponse(
        thread_id=thread["thread_id"], alert_id=thread["alert_id"], status=thread["status"],
        payload_hash=thread.get("payload_hash"),
        worksheet=(
            DispositionWorksheet.model_validate({k: v for k, v in worksheet.items() if k in DispositionWorksheet.model_fields})
            if worksheet else None
        ),
        replan_count=state.get("replan_count", 0), tool_calls_used=state.get("tool_calls_used", 0),
        cost_usd=state.get("estimated_cost_usd", "0"), tokens_used=state.get("total_tokens_used", 0),
    )


@app.post("/api/v1/investigations/run", response_model=InvestigateResponse, dependencies=api_deps)
async def run_investigation_sync(request: InvestigateRequest, principal: Principal = ANALYST):
    _guard_alert_id(request.alert_id)
    alert = _alert_from_db(request.alert_id)
    thread_id = runner.register_thread(alert, request.agent_mode, principal.sub)
    status = await runner.run_thread(thread_id, alert, request.agent_mode)
    thread = _require_thread(thread_id)
    if status == "error":
        raise HTTPException(status_code=502, detail="INVESTIGATION_FAILED: see audit/event log for the correlation id")
    return _response_for(thread)


@app.post("/api/v1/investigations/{thread_id}/resume", response_model=InvestigateResponse, dependencies=api_deps)
async def resume_investigation(thread_id: str, _p: Principal = ANALYST):
    thread = get_thread(thread_id)
    if thread is None:
        raise HTTPException(status_code=404, detail="Checkpoint not found")
    if thread["status"] in ("committed", "rejected"):
        raise HTTPException(status_code=409, detail=f"THREAD_CLOSED: thread is {thread['status']}")
    alert = Alert(**thread["alert"])
    status = await runner.run_thread(thread_id, alert, thread["mode"], resume=True)
    if status == "error":
        raise HTTPException(status_code=502, detail="INVESTIGATION_FAILED: see audit/event log for the correlation id")
    return _response_for(_require_thread(thread_id))


async def _event_stream(thread_id: str, after_id: int, request: Request) -> AsyncGenerator[str, None]:
    """Read-only subscriber of the durable `investigation_events` log (never executes the investigation)."""
    deadline = time.monotonic() + 900
    last = after_id
    while time.monotonic() < deadline:
        if await request.is_disconnected():
            return
        events = await asyncio.to_thread(read_events, thread_id, last)
        for ev in events:
            last = ev["event_id"]
            name = ev["event"]
            payload = {k: v for k, v in ev.items() if k not in ("event", "created_at")}
            payload.update({"event": name, "timestamp": ev["created_at"]})
            yield f"id: {last}\nevent: {name}\ndata: {json.dumps(payload, default=str)}\n\n"
            if name in runner.TERMINAL_EVENTS:
                return
        await asyncio.sleep(0.4)
    yield f"event: error\ndata: {json.dumps({'event': 'error', 'message': 'stream timeout'})}\n\n"


@app.get("/api/v1/investigations/{thread_id}/stream", dependencies=api_deps)
async def stream_investigation(thread_id: str, request: Request, after_id: int = Query(0, ge=0), _p: Principal = ANALYST):
    if get_thread(thread_id) is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    return StreamingResponse(_event_stream(thread_id, after_id, request), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/v1/investigations/{thread_id}/decision", dependencies=api_deps)
async def submit_human_decision(thread_id: str, request: DecisionRequest, principal: Principal = ANALYST):
    thread = _require_thread(thread_id)
    try:
        if request.action == "edit":
            assert request.edit is not None
            return approval_service.apply_edit(thread, request.edit, principal.sub)
        if request.action == "approve":
            return await approval_service.approve(thread, request, principal.sub)
        return await approval_service.reject(thread, request, principal.sub)
    except approval_service.DecisionError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message, "discrepancies": exc.extra},
        ) from exc


@app.get("/api/v1/investigations/{thread_id}/state", dependencies=api_deps)
async def get_investigation_state(thread_id: str, _p: Principal = ANALYST):
    return _require_thread(thread_id)


@app.get("/api/v1/investigations/{thread_id}/export", response_class=HTMLResponse, dependencies=api_deps)
async def export_investigation_report(thread_id: str, _principal: Principal = ANALYST):
    """Printable HTML/PDF-ready Compliance Investigation Audit Report."""
    rec = thread_view(thread_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    st = rec.get("state", {})
    ws = st.get("worksheet") or {}
    fs = st.get("flow_summary") or {}
    def esc(s: Any) -> str:
        return html.escape(str(s or ""))

    paths_rows = "".join(
        f"<tr><td>{esc(p.get('path_id'))}</td><td>{esc(' -> '.join(p.get('nodes', [])))}</td>"
        f"<td>{esc(p.get('hop_count'))}</td><td>INR {esc(p.get('total_outflow_inr'))}</td>"
        f"<td>INR {esc(p.get('total_consolidated_inr'))}</td><td>{esc(p.get('retention_pct'))}%</td></tr>"
        for p in ws.get("candidate_paths", [])
    )
    cites_html = ", ".join(f"<code>{esc(c)}</code>" for c in ws.get("regulatory_citations", []))

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>AuditGuard Compliance Report â€” {esc(rec.get('alert_id'))}</title>
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
<h1>AuditGuard â€” AML Investigation Disposition Worksheet</h1>
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


@app.delete("/api/v1/memory/{customer_id}", dependencies=api_deps)
async def forget_customer(customer_id: str, principal: Principal = SENIOR):
    result = erase_customer(customer_id, principal.sub)
    return {**result, "status": "deleted", "deleted_by": principal.sub,
            "message": "Customer memory deleted per retention policy"}


@app.get("/api/v1/investigations", dependencies=api_deps)
async def list_investigations(_p: Principal = ANALYST):
    cps = list_checkpoints(limit=50)
    return {"investigations": cps, "total": len(cps)}
