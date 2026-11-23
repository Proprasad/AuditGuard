"""T2: MCP contract tests - every call goes through the real FastMCP protocol client (no raw `.fn`)."""

import pytest

from src.db.database import get_db
from src.mcp_servers.client import call_mcp_tool


@pytest.mark.asyncio
async def test_compliance_kb_happy_and_missing():
    res = await call_mcp_tool("compliance-kb", "search_regulations", {"query": "scatter gather PMLA", "top_k": 3})
    assert len(res["clauses"]) >= 1
    missing = await call_mcp_tool("compliance-kb", "get_clause_by_id", {"clause_id": "NON-EXISTENT-999"})
    assert missing["relevance_score"] == 0.0 and missing["source"] == "unknown"


@pytest.mark.asyncio
async def test_bank_records_happy_and_not_found():
    ctx = await call_mcp_tool("bank-records", "get_alert_context", {"alert_id": "ALT-2026-0412"})
    assert ctx["alert_id"] == "ALT-2026-0412" and len(ctx["transactions"]) >= 3

    with get_db() as conn:
        account_id = conn.execute("SELECT account_id FROM accounts ORDER BY account_id LIMIT 1").fetchone()[0]
    kyc = await call_mcp_tool("bank-records", "get_kyc_profile", {"account_id": account_id})
    assert kyc["account_id"] == account_id

    missing = await call_mcp_tool("bank-records", "get_kyc_profile", {"account_id": "ACC-DOES-NOT-EXIST"})
    assert missing["error_code"] == "ACCOUNT_NOT_FOUND"
    unknown = await call_mcp_tool("bank-records", "get_alert_context", {"alert_id": "ALT-NOPE-1"})
    assert unknown["error_code"] == "INVALID_ALERT_ID"


@pytest.mark.asyncio
async def test_graph_engine_bounds_error():
    res = await call_mcp_tool(
        "graph-engine",
        "find_candidate_fund_flows",
        {"root_account": "ACC-1", "transactions": [], "time_window_days": 365, "max_hops": 3},
    )
    assert res["status"] == "error" and res["error_code"] == "POLICY_BOUNDS_EXCEEDED"


@pytest.mark.asyncio
async def test_case_actions_draft_and_reject_invalid_token():
    draft = await call_mcp_tool(
        "case-actions",
        "draft_disposition_report",
        {
            "alert_id": "ALT-TEST-1",
            "recommended_disposition": "escalate_str",
            "recommendation_rationale": "Test rationale",
            "confidence_score": 0.85,
            "regulatory_citations": ["PMLA-2002-S13"],
        },
    )
    assert draft["worksheet_id"].startswith("DWS-") and len(draft["payload_hash"]) == 64
    bad = await call_mcp_tool(
        "case-actions",
        "submit_case_disposition",
        {
            "worksheet_id": draft["worksheet_id"],
            "approval_token": "APPROVE:badhash:badsig",
            "reviewer_id": "analyst_01",
            "thread_id": "thr-test",
        },
    )
    assert bad["success"] is False and "Approval rejected" in bad["error"]


@pytest.mark.asyncio
async def test_invalid_arguments_are_a_typed_error_not_an_exception():
    res = await call_mcp_tool("bank-records", "get_alert_context", {"bogus": 1})
    assert res["status"] == "error" and res["error_code"] == "MCP_TOOL_ERROR"


@pytest.mark.asyncio
async def test_unknown_server_and_unknown_tool_are_typed_errors():
    assert (await call_mcp_tool("nope", "x", {}))["error_code"] == "UNKNOWN_MCP_SERVER"
    assert (await call_mcp_tool("bank-records", "no_such_tool", {}))["status"] == "error"


@pytest.mark.asyncio
async def test_unreachable_http_server_is_mcp_unavailable(monkeypatch):
    from src.config import settings

    monkeypatch.setattr(settings, "mcp_transport", "http")
    monkeypatch.setattr(settings, "mcp_bank_records_port", 1)
    res = await call_mcp_tool("bank-records", "get_alert_context", {"alert_id": "ALT-2026-0412"}, timeout_s=3)
    assert res["status"] == "error" and res["error_code"] in {"MCP_UNAVAILABLE", "MCP_TIMEOUT"}
