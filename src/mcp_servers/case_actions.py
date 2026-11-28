"""
MCP Server: case-actions (WRITE - approval gated)

Thin FastMCP adapter over the write-scoped `src.db.case_repo`:
  * draft_disposition_report  : server-side verified, idempotent draft keyed on (thread_id, revision)
  * submit_case_disposition   : requires a valid, single-use, hash-bound HMAC approval token; consumes it,
                                transitions the worksheet and INSERTs the case in ONE transaction
Zero automated external regulatory filings (commits strictly to the Case Management DB).
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Literal, Optional

from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from src.mcp_servers.annotations import COMMIT_WRITE_TOOL, DRAFT_WRITE_TOOL
from src.core.canonical import Confidence
from src.core.verifier import check_prohibited_claims, check_tipping_off, verify_worksheet
from src.db import case_repo
from src.db.case_repo import CaseRepoError
from src.db.database import utc_now_iso
from src.mcp_servers.http_auth import serve_mcp_http

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
    confidence_score: Confidence
    candidate_paths: list[dict[str, Any]] = Field(default_factory=list)
    regulatory_citations: list[str] = Field(default_factory=list)
    kyc_summaries: list[str] = Field(default_factory=list)
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    degraded_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    alert_amount_inr: Optional[str] = None
    verification_status: Literal["passed", "failed"] = "passed"
    verification_discrepancies: list[dict[str, Any]] = Field(default_factory=list)
    evidence_registry: Optional[dict[str, Any]] = None
    calc_log: Optional[list[dict[str, Any]]] = None
    enforce_verifier_gate: bool = True


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
    message: Optional[str] = None
    error: Optional[str] = None


def _enforce_server_side_verification(
    content: dict[str, Any],
    evidence_registry: Optional[dict[str, Any]],
    calc_log: Optional[list[dict[str, Any]]] = None,
    enforce_verifier_gate: bool = True,
) -> dict[str, Any]:
    """
    Defense-in-depth verification:
    - Always runs Verifier v2 when `evidence_registry` is provided so discrepancies are recorded.
    - When `enforce_verifier_gate=True` (default), any violation downgrades disposition to `request_info`.
    - When `enforce_verifier_gate=False` (E4 `no_verifier` ablation), discrepancies are recorded without
      blocking or downgrading `recommended_disposition`.
    """
    if content.get("verification_status") != "passed" and enforce_verifier_gate:
        return content
    texts = [str(content.get("recommendation_rationale", ""))] + [
        str(h.get("explanation", "")) for h in content.get("hypotheses", []) if isinstance(h, dict)
    ]
    guilt_hits = [hit for t in texts for hit in check_prohibited_claims(t)]
    tipping_hits = [hit for t in texts for hit in check_tipping_off(t)]
    if guilt_hits or tipping_hits:
        content["verification_status"] = "failed"
        content["verification_discrepancies"] = [
            {"code": code, "field": "recommendation_rationale", "detail": str(hits)}
            for code, hits in (("PROHIBITED_CLAIM", guilt_hits), ("TIPPING_OFF", tipping_hits))
            if hits
        ]
        if enforce_verifier_gate:
            content["recommended_disposition"] = "request_info"
        return content
    if evidence_registry is not None:
        vr = verify_worksheet(content, evidence_registry, calc_log=calc_log)
        if not vr.passed:
            content["verification_status"] = "failed"
            content["verification_discrepancies"] = [d.model_dump() for d in vr.discrepancies]
            if enforce_verifier_gate:
                content["recommended_disposition"] = "request_info"
    return content


@mcp.tool(annotations=DRAFT_WRITE_TOOL)
async def draft_disposition_report(params: DraftDispositionInput) -> DraftDispositionOutput:
    """Persist a verified draft disposition worksheet and return its canonical SHA-256 hash."""
    now = utc_now_iso()
    excluded = {"thread_id", "evidence_registry", "calc_log", "enforce_verifier_gate"}
    raw_content = {**params.model_dump(mode="json", exclude=excluded), "drafted_at": now}
    verified_content = _enforce_server_side_verification(
        raw_content, params.evidence_registry, params.calc_log, params.enforce_verifier_gate
    )
    record = await asyncio.to_thread(case_repo.upsert_draft, verified_content, params.thread_id, 1)
    return DraftDispositionOutput(
        worksheet_id=record["worksheet_id"],
        alert_id=params.alert_id,
        payload_hash=record["payload_hash"],
        created_at=now,
        content=record["content"],
    )


@mcp.tool(annotations=COMMIT_WRITE_TOOL)
async def submit_case_disposition(params: SubmitCaseDispositionInput) -> SubmitCaseDispositionOutput:
    """Commit the approved disposition. Replays, tampered payloads and invalid tokens are rejected."""
    now = utc_now_iso()
    try:
        receipt = await asyncio.to_thread(
            case_repo.commit_case,
            params.worksheet_id,
            params.approval_token,
            params.reviewer_id,
            params.reviewer_notes,
            params.thread_id,
        )
    except CaseRepoError as exc:
        await asyncio.to_thread(
            case_repo.log_rejection, params.thread_id, params.reviewer_id, params.worksheet_id, exc.code
        )
        msg = f"Approval rejected: {exc.code}: {exc.message}"
        return SubmitCaseDispositionOutput(
            success=False,
            status="error",
            worksheet_id=params.worksheet_id,
            submitted_at=now,
            error_code=exc.code,
            message=msg,
            error=msg,
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
    serve_mcp_http(mcp, port=port)
