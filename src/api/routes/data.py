"""Workbench navigation data (read-only repository calls) and admin LLM configuration."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query

from src.api.auth import Principal
from src.api.deps import (
    ADMIN,
    ANALYST,
    LlmConfigUpdateRequest,
    api_deps,
)
from src.config import get_policy, settings
from src.db import read_repo
from src.db.database import append_audit_log, list_audit_logs
from src.mcp_servers import bank_records, compliance_kb
from src.mcp_servers.client import call_mcp_tool

logger = logging.getLogger("auditguard.api")
router = APIRouter()


@router.get("/api/v1/alerts", dependencies=api_deps)
async def get_queued_alerts(limit: int = Query(50, ge=1, le=500), _p: Principal = ANALYST) -> dict[str, Any]:
    alerts = await asyncio.to_thread(bank_records.list_queued_alerts, limit)
    open_count = sum(1 for a in alerts if str(a.get("status", "OPEN")).upper() == "OPEN")
    return {"alerts": alerts, "total": len(alerts), "open_count": open_count}


@router.get("/api/v1/cases", dependencies=api_deps)
async def get_cases(limit: int = Query(50, ge=1, le=500), _p: Principal = ANALYST) -> dict[str, Any]:
    return await asyncio.to_thread(read_repo.fetch_cases_and_worksheets, limit)


@router.get("/api/v1/customers", dependencies=api_deps)
async def get_customers(limit: int = Query(100, ge=1, le=500), _p: Principal = ANALYST) -> dict[str, Any]:
    return await asyncio.to_thread(read_repo.fetch_customers, limit)


def _full_regulatory_corpus() -> dict[str, Any]:
    idx = compliance_kb.get_regulatory_index()
    return {
        "clauses": [c.model_dump() for c in idx.clauses],
        "total": len(idx.clauses),
        "retrieval_method": "full_corpus",
    }


@router.get("/api/v1/regulations", dependencies=api_deps)
async def list_regulations(
    q: Optional[str] = Query(default=None, description="Optional Hybrid RAG search query"),
    top_k: int = Query(10, ge=1, le=50),
    _p: Principal = ANALYST,
) -> dict[str, Any]:
    if q and q.strip():
        res = await call_mcp_tool(
            "compliance-kb", "search_regulations", {"query": q.strip(), "top_k": top_k, "decompose": True}
        )
        if res.get("status") == "error":
            raise HTTPException(status_code=502, detail=f"{res.get('error_code')}: {res.get('error')}")
        return {
            "clauses": res["clauses"],
            "total": len(res["clauses"]),
            "retrieval_method": res.get("retrieval_method"),
        }
    return await asyncio.to_thread(_full_regulatory_corpus)


@router.get("/api/v1/audit-logs", dependencies=api_deps)
async def get_audit_logs(
    thread_id: Optional[str] = None, limit: int = Query(60, ge=1, le=500), _p: Principal = ANALYST
) -> dict[str, Any]:
    logs = await asyncio.to_thread(list_audit_logs, thread_id, limit)
    return {"audit_logs": logs, "total": len(logs)}


@router.get("/api/v1/analytics", dependencies=api_deps)
async def get_analytics(_p: Principal = ANALYST) -> dict[str, Any]:
    return await asyncio.to_thread(read_repo.fetch_analytics)


@router.get("/api/v1/config-info", dependencies=api_deps)
async def get_config_info(_p: Principal = ANALYST) -> dict[str, Any]:
    from src.agent.llm_client import get_llm_status, get_model_for_role

    llm_info = await asyncio.to_thread(get_llm_status)
    specialist_m = await asyncio.to_thread(get_model_for_role, "c2_specialists")
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
            "c2_specialists": specialist_m,
            "judge": policy.model_for("judge").model_id,
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
async def update_llm_config(req: LlmConfigUpdateRequest, principal: Principal = ADMIN) -> dict[str, Any]:
    from src.agent.llm_client import set_runtime_llm_config

    try:
        updated = await asyncio.to_thread(set_runtime_llm_config, req.enabled, req.model, req.strong_model)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"INVALID_LLM_CONFIG: {exc}") from exc
    await asyncio.to_thread(
        append_audit_log,
        "system-config",
        "llm_config_updated",
        principal.sub,
        {
            "llm_enabled": updated["llm_enabled"],
            "c1_and_specialist_model": updated["c1_and_specialist_model"],
            "c2_supervisor_model": updated["c2_supervisor_model"],
        },
    )
    return updated


@router.post("/api/v1/config/llm/test", dependencies=api_deps)
async def test_llm_connection(model: Optional[str] = None, _p: Principal = ADMIN) -> dict[str, Any]:
    from src.agent.llm_client import ping_openrouter

    return await ping_openrouter(model=model)
