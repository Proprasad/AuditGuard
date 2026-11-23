"""T2: MCP Server Contract Tests across all 4 FastMCP servers."""
import pytest
from src.mcp_servers import compliance_kb, graph_engine, bank_records, case_actions


def _fn(tool):
    return getattr(tool, "fn", tool)


@pytest.mark.asyncio
async def test_compliance_kb_happy_and_missing():
    res = await _fn(compliance_kb.search_regulations)(
        compliance_kb.SearchRegulationsInput(query="scatter gather PMLA", top_k=3)
    )
    assert len(res.clauses) >= 1

    missing = await _fn(compliance_kb.get_clause_by_id)(
        compliance_kb.GetClauseInput(clause_id="NON-EXISTENT-999")
    )
    assert missing.relevance_score == 0.0
    assert missing.source == "unknown"


@pytest.mark.asyncio
async def test_bank_records_happy():
    ctx = await _fn(bank_records.get_alert_context)(
        bank_records.GetAlertContextInput(alert_id="ALT-2026-0412")
    )
    assert ctx["alert_id"] == "ALT-2026-0412"
    assert len(ctx["transactions"]) >= 3

    from src.db.database import get_db

    with get_db() as conn:
        account_id = conn.execute("SELECT account_id FROM accounts ORDER BY account_id LIMIT 1").fetchone()[0]
    kyc = await _fn(bank_records.get_kyc_profile)(bank_records.GetKYCProfileInput(account_id=account_id))
    assert kyc["account_id"] == account_id

    missing = await _fn(bank_records.get_kyc_profile)(bank_records.GetKYCProfileInput(account_id="ACC-DOES-NOT-EXIST"))
    assert missing.get("error_code") == "ACCOUNT_NOT_FOUND"

    unknown = await _fn(bank_records.get_alert_context)(bank_records.GetAlertContextInput(alert_id="ALT-NOPE-1"))
    assert unknown.get("error_code") == "INVALID_ALERT_ID"


@pytest.mark.asyncio
async def test_graph_engine_bounds_error():
    res = await _fn(graph_engine.find_candidate_fund_flows)(
        graph_engine.FindCandidateFlowsInput(
            root_account="ACC-1",
            transactions=[],
            time_window_days=365,
            max_hops=3,
        )
    )
    assert res.status == "error"
    assert res.error_code == "POLICY_BOUNDS_EXCEEDED"


@pytest.mark.asyncio
async def test_case_actions_draft_and_reject_invalid_token():
    draft = await _fn(case_actions.draft_disposition_report)(
        case_actions.DraftDispositionInput(
            alert_id="ALT-TEST-1",
            recommended_disposition="escalate_str",
            recommendation_rationale="Test rationale",
            confidence_score=0.85,
            regulatory_citations=["PMLA-2002-S13"],
        )
    )
    assert draft.worksheet_id.startswith("DWS-")
    assert len(draft.payload_hash) == 64

    bad_submit = await _fn(case_actions.submit_case_disposition)(
        case_actions.SubmitCaseDispositionInput(
            worksheet_id=draft.worksheet_id,
            approval_token="APPROVE:badhash:badsig",
            reviewer_id="analyst_01",
            thread_id="thr-test",
        )
    )
    assert bad_submit.success is False
    assert "Approval rejected" in (bad_submit.error or "")
