"""T4: cryptographic approval invalidation (single-use, hash-bound, tamper-evident tokens)."""

import pytest

from src.core.verifier import verify_worksheet
from src.db import case_repo
from src.db.database import get_db


def _content(rationale: str = "Outflow INR 900000.00 consolidated across intermediaries.") -> dict:
    return {
        "alert_id": "ALT-2026-0412",
        "recommended_disposition": "escalate_str",
        "recommendation_rationale": rationale,
        "confidence_score": 0.88,
        "regulatory_citations": ["PMLA-2002-S13"],
    }


def test_tampering_with_stored_worksheet_invalidates_token():
    draft = case_repo.upsert_draft(_content(), thread_id="thr-t4", revision=1)
    approval = case_repo.issue_approval_token("thr-t4", draft["worksheet_id"])
    with get_db() as conn:  # simulate out-of-band tampering with the stored worksheet
        conn.execute(
            (
                "UPDATE worksheets SET content_json = REPLACE(content_json, "
                "'900000.00', '900001.00') WHERE worksheet_id = ?"
            ),
            (draft["worksheet_id"],),
        )
    with pytest.raises(case_repo.CaseRepoError) as exc:
        case_repo.commit_case(draft["worksheet_id"], approval["approval_token"], "reviewer", "", "thr-t4")
    assert exc.value.code == "TOKEN_INVALIDATED_BY_EDIT"


def test_token_is_single_use_and_edit_supersedes_it():
    draft = case_repo.upsert_draft(_content(), thread_id="thr-t4b", revision=1)
    old = case_repo.issue_approval_token("thr-t4b", draft["worksheet_id"])
    case_repo.update_worksheet_content(draft["worksheet_id"], _content("Revised rationale text."), "analyst")
    with pytest.raises(case_repo.CaseRepoError) as exc:
        case_repo.commit_case(draft["worksheet_id"], old["approval_token"], "reviewer", "", "thr-t4b")
    assert exc.value.code in {"ALREADY_CONSUMED", "TOKEN_INVALIDATED_BY_EDIT"}

    fresh = case_repo.issue_approval_token("thr-t4b", draft["worksheet_id"])
    receipt = case_repo.commit_case(draft["worksheet_id"], fresh["approval_token"], "reviewer", "ok", "thr-t4b")
    assert receipt["case_id"].startswith("CASE-DISP-")
    with pytest.raises(case_repo.CaseRepoError) as again:
        case_repo.commit_case(draft["worksheet_id"], fresh["approval_token"], "reviewer", "ok", "thr-t4b")
    assert again.value.code == "ALREADY_COMMITTED"


def test_deterministic_verifier_blocks_guilt_claims():
    bad = {**_content("Money laundering has occurred in this account.")}
    result = verify_worksheet(bad, {})
    assert result.passed is False
    assert result.discrepancies
