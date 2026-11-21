"""T4: Cryptographic Approval Invalidation Tests (Signature Challenge B)"""
import pytest
from src.mcp_servers import case_actions
from src.guardrails.verifier import verify_worksheet, verify_inr_math


def _fn(tool):
    return getattr(tool, "fn", tool)


@pytest.mark.asyncio
async def test_editing_one_rupee_invalidates_approval():
    """Editing 1 rupee in a drafted worksheet after approval token generation must fail verification."""
    draft = await _fn(case_actions.draft_disposition_report)(
        case_actions.DraftDispositionInput(
            alert_id="ALT-2026-0412",
            recommended_disposition="escalate_str",
            recommendation_rationale="Outflow INR 900000.00, consolidated INR 828000.00",
            confidence_score=0.88,
            candidate_paths=[{"path_id": "PATH-01", "total_amount": 900000.00}],
            regulatory_citations=["PMLA-2002-S13"],
        )
    )

    valid_token = case_actions._generate_approval_token(draft.payload_hash)

    # Simulate analyst editing 1 rupee in the stored worksheet without re-approving
    case_actions._worksheets[draft.worksheet_id]["content"]["candidate_paths"][0]["total_amount"] = 900001.00

    res = await _fn(case_actions.submit_case_disposition)(
        case_actions.SubmitCaseDispositionInput(
            worksheet_id=draft.worksheet_id,
            approval_token=valid_token,
            reviewer_id="analyst_04",
            reviewer_decision="escalate_str",
        )
    )
    assert res.success is False
    assert "token_invalidated_by_edit" in (res.error or "")


def test_deterministic_verifier_blocks_guilt_claims():
    bad_ws = {
        "recommended_disposition": "escalate_str",
        "recommendation_rationale": "Money laundering has occurred in this account.",
        "confidence_score": 0.9,
        "regulatory_citations": ["PMLA-2002-S13"],
    }
    vr = verify_worksheet(bad_ws)
    assert vr.passed is False
    assert vr.checks["no_prohibited_claims"] is False

    ok, detail = verify_inr_math("900000.00", "855000.00", tolerance=0.05)
    assert ok is True
