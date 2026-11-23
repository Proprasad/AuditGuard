"""Investigation lifecycle, SSE stream, human decision, export and memory-erasure routes."""
from __future__ import annotations

import asyncio
import html
import json
import logging
import time
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from src.api.auth import Principal
from src.api.deps import (
    ANALYST, SENIOR, alert_from_db, api_deps, guard_alert_id, require_thread,
)
from src.api.services import approval as approval_service
from src.api.services import runner
from src.api.services.erasure import erase_customer
from src.api.services.threads import get_thread, thread_view
from src.db.database import list_checkpoints, read_events
from src.models import Alert, DecisionRequest, DispositionWorksheet, InvestigateRequest, InvestigateResponse

logger = logging.getLogger("auditguard.api")
router = APIRouter()

# ---------------------------------------------------------------------------
# Investigation Lifecycle
# ---------------------------------------------------------------------------
@router.post("/api/v1/investigations", response_model=InvestigateResponse, dependencies=api_deps)
async def start_investigation(request: InvestigateRequest, principal: Principal = ANALYST):
    guard_alert_id(request.alert_id)
    alert = alert_from_db(request.alert_id)
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


@router.post("/api/v1/investigations/run", response_model=InvestigateResponse, dependencies=api_deps)
async def run_investigation_sync(request: InvestigateRequest, principal: Principal = ANALYST):
    guard_alert_id(request.alert_id)
    alert = alert_from_db(request.alert_id)
    thread_id = runner.register_thread(alert, request.agent_mode, principal.sub)
    status = await runner.run_thread(thread_id, alert, request.agent_mode)
    thread = require_thread(thread_id)
    if status == "error":
        raise HTTPException(status_code=502, detail="INVESTIGATION_FAILED: see audit/event log for the correlation id")
    return _response_for(thread)


@router.post("/api/v1/investigations/{thread_id}/resume", response_model=InvestigateResponse, dependencies=api_deps)
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
    return _response_for(require_thread(thread_id))


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


@router.get("/api/v1/investigations/{thread_id}/stream", dependencies=api_deps)
async def stream_investigation(thread_id: str, request: Request, after_id: int = Query(0, ge=0), _p: Principal = ANALYST):
    if get_thread(thread_id) is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    return StreamingResponse(_event_stream(thread_id, after_id, request), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/api/v1/investigations/{thread_id}/decision", dependencies=api_deps)
async def submit_human_decision(thread_id: str, request: DecisionRequest, principal: Principal = ANALYST):
    thread = require_thread(thread_id)
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


@router.get("/api/v1/investigations/{thread_id}/state", dependencies=api_deps)
async def get_investigation_state(thread_id: str, _p: Principal = ANALYST):
    return require_thread(thread_id)


@router.get("/api/v1/investigations/{thread_id}/export", response_class=HTMLResponse, dependencies=api_deps)
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


@router.delete("/api/v1/memory/{customer_id}", dependencies=api_deps)
async def forget_customer(customer_id: str, principal: Principal = SENIOR):
    result = erase_customer(customer_id, principal.sub)
    return {**result, "status": "deleted", "deleted_by": principal.sub,
            "message": "Customer memory deleted per retention policy"}


@router.get("/api/v1/investigations", dependencies=api_deps)
async def list_investigations(_p: Principal = ANALYST):
    cps = list_checkpoints(limit=50)
    return {"investigations": cps, "total": len(cps)}
