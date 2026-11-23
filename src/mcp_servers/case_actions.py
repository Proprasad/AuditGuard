"""
MCP Server: case-actions (WRITE - approval gated)

Thin FastMCP adapter over the write-scoped `src.db.case_repo`:
  * draft_disposition_report  : idempotent draft keyed on (thread_id, revision)
  * submit_case_disposition   : requires a valid, single-use, hash-bound HMAC approval token; consumes it,
                                transitions the worksheet and INSERTs the case in ONE transaction
Zero automated external regulatory filings (commits strictly to the Case Management DB).
"""

from __future__ import annotations

import os
from typing import Any, Literal, Optional

from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from src.db import case_repo
from src.db.case_repo import CaseRepoError
from src.db.database import utc_now_iso

mcp = FastMCP(
    name="case-actions",
    instructions="Write-gated server for case dispositions. Commits require a single-use HMAC approval token "
    "bound to the exact SHA-256 hash of the reviewed worksheet.",
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DraftDispositionInput(_Strict):
    alert_id: str
    thread_id: Optional[str] = None
    recommended_disposition: str
    recommendation_rationale: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    candidate_paths: list[dict[str, Any]] = Field(default_factory=list)
    regulatory_citations: list[str] = Field(default_factory=list)
    kyc_summaries: list[str] = Field(default_factory=list)
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    degraded_evidence: list[str] = Field(default_factory=list)
    alert_amount_inr: Optional[str] = None
    verification_status: Literal["passed", "failed"] = "passed"
    verification_discrepancies: list[dict[str, Any]] = Field(default_factory=list)


class DraftDispositionOutput(_Strict):
    status: str = "ok"
    worksheet_id: str
    alert_id: str
    payload_hash: str
    created_at: str
    content: dict[str, Any]


class SubmitCaseDispositionInput(_Strict):
    worksheet_id: str
    approval_token: str
    reviewer_id: str
    reviewer_notes: str = ""
    thread_id: str


class SubmitCaseDispositionOutput(_Strict):
    status: str = "ok"
    success: bool
    case_id: str = ""
    worksheet_id: str
    final_disposition: str = ""
    submitted_at: str
    audit_entry_id: str = ""
    error_code: Optional[str] = None
    error: Optional[str] = None


@mcp.tool()
def draft_disposition_report(params: DraftDispositionInput) -> DraftDispositionOutput:
    """Persist a draft disposition worksheet and return its canonical SHA-256 hash (idempotent per thread revision)."""
    now = utc_now_iso()
    content = {**params.model_dump(exclude={"thread_id"}), "drafted_at": now}
    record = case_repo.upsert_draft(content, thread_id=params.thread_id, revision=1)
    return DraftDispositionOutput(
        worksheet_id=record["worksheet_id"],
        alert_id=params.alert_id,
        payload_hash=record["payload_hash"],
        created_at=now,
        content=record["content"],
    )


@mcp.tool()
def submit_case_disposition(params: SubmitCaseDispositionInput) -> SubmitCaseDispositionOutput:
    """Commit the approved disposition. Replays, tampered payloads and invalid tokens are rejected."""
    now = utc_now_iso()
    try:
        receipt = case_repo.commit_case(
            params.worksheet_id,
            params.approval_token,
            params.reviewer_id,
            params.reviewer_notes,
            params.thread_id,
        )
    except CaseRepoError as exc:
        case_repo.log_rejection(params.thread_id, params.reviewer_id, params.worksheet_id, exc.code)
        return SubmitCaseDispositionOutput(
            success=False,
            status="error",
            worksheet_id=params.worksheet_id,
            submitted_at=now,
            error_code=exc.code,
            error=f"Approval rejected: {exc.code}: {exc.message}",
        )
    return SubmitCaseDispositionOutput(
        success=True,
        case_id=receipt["case_id"],
        worksheet_id=params.worksheet_id,
        final_disposition=receipt["disposition"],
        submitted_at=receipt["committed_at"],
        audit_entry_id=receipt["audit_entry_id"],
    )


if __name__ == "__main__":
    port = int(os.getenv("MCP_CASE_ACTIONS_PORT", "8013"))
    mcp.run(transport="streamable-http", host="0.0.0.0", port=port)  # noqa: S104 - container bind
