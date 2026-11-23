"""Workbench navigation data (read-only DB connections) and admin LLM configuration."""
from __future__ import annotations

import logging
from decimal import Decimal
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from src.api.auth import Principal
from src.api.deps import (
    ADMIN, ANALYST, LlmConfigUpdateRequest, api_deps,
)
from src.config import get_policy, settings
from src.core.canonical import to_money
from src.db.database import append_audit_log, get_ro_db, init_db, list_audit_logs
from src.mcp_servers import bank_records, compliance_kb
from src.mcp_servers.client import call_mcp_tool

logger = logging.getLogger("auditguard.api")
router = APIRouter()

# ---------------------------------------------------------------------------
# Workbench Navigation Data Endpoints (read-only DB connections)
# ---------------------------------------------------------------------------
@router.get("/api/v1/alerts", dependencies=api_deps)
async def get_queued_alerts(limit: int = Query(50, ge=1, le=500), _p: Principal = ANALYST):
    alerts = bank_records.list_queued_alerts(limit=limit)
    open_count = sum(1 for a in alerts if str(a.get("status", "OPEN")).upper() == "OPEN")
    return {"alerts": alerts, "total": len(alerts), "open_count": open_count}


@router.get("/api/v1/cases", dependencies=api_deps)
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


@router.get("/api/v1/customers", dependencies=api_deps)
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


@router.get("/api/v1/regulations", dependencies=api_deps)
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


@router.get("/api/v1/audit-logs", dependencies=api_deps)
async def get_audit_logs(thread_id: Optional[str] = None, limit: int = Query(60, ge=1, le=500), _p: Principal = ANALYST):
    logs = list_audit_logs(thread_id=thread_id, limit=limit)
    return {"audit_logs": logs, "total": len(logs)}


@router.get("/api/v1/analytics", dependencies=api_deps)
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


@router.get("/api/v1/config-info", dependencies=api_deps)
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


@router.post("/api/v1/config/llm", dependencies=api_deps)
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


@router.post("/api/v1/config/llm/test", dependencies=api_deps)
async def test_llm_connection(model: Optional[str] = None, _p: Principal = ADMIN):
    from src.agent.llm_client import ping_openrouter

    return await ping_openrouter(model=model)


