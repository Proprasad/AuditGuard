"""
Unified MCP Tool Client
Supports `MCP_TRANSPORT=http` (Docker / separate FastMCP servers) and
`MCP_TRANSPORT=inprocess` (local dev / unit tests).
"""
from __future__ import annotations

import os
from src.config import settings


async def call_mcp_tool(server: str, tool: str, params: dict) -> dict:
    """
    Call a FastMCP server tool over HTTP when MCP_TRANSPORT=http,
    or execute in-process directly in local dev mode (with HTTP fallback).
    """
    transport = os.getenv("MCP_TRANSPORT", "inprocess").lower()

    if transport == "http":
        import httpx
        port_map = {
            "compliance-kb": settings.mcp_compliance_kb_port,
            "graph-engine": settings.mcp_graph_engine_port,
            "bank-records": settings.mcp_bank_records_port,
            "case-actions": settings.mcp_case_actions_port,
        }
        port = port_map.get(server, 8010)
        url = f"http://localhost:{port}/mcp/v1/tools/{tool}"
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, json=params)
                resp.raise_for_status()
                return resp.json()
        except Exception:
            pass

    try:
        if server == "bank-records":
            from src.mcp_servers import bank_records as mod
            schema_map = {
                "get_alert_context": mod.GetAlertContextInput,
                "get_account_transactions": mod.GetAccountTransactionsInput,
                "get_kyc_profile": mod.GetKYCProfileInput,
                "get_counterparty_history": mod.GetCounterpartyHistoryInput,
                "check_commercial_registry": mod.CheckCommercialRegistryInput,
            }
        elif server == "graph-engine":
            from src.mcp_servers import graph_engine as mod
            schema_map = {
                "find_candidate_fund_flows": mod.FindCandidateFlowsInput,
                "compute_flow_conservation": mod.FlowConservationInput,
                "compare_graph_runs": mod.CompareGraphRunsInput,
            }
        elif server == "compliance-kb":
            from src.mcp_servers import compliance_kb as mod
            schema_map = {
                "search_regulations": mod.SearchRegulationsInput,
                "get_clause_by_id": mod.GetClauseInput,
            }
        elif server == "case-actions":
            from src.mcp_servers import case_actions as mod
            schema_map = {
                "draft_disposition_report": mod.DraftDispositionInput,
                "submit_case_disposition": mod.SubmitCaseDispositionInput,
            }
        else:
            return {"error": f"Unknown MCP server: {server}"}

        fn = getattr(mod, tool)
        raw_fn = getattr(fn, "fn", fn)
        input_cls = schema_map[tool]
        result = await raw_fn(input_cls(**params))
        return result.model_dump() if hasattr(result, "model_dump") else result
    except Exception as e:
        return {"error": str(e), "fallback": True, "server": server, "tool": tool}
