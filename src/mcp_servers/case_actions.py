"""
MCP Server: case-actions (WRITE — Approval Gated)
Backed by relational SQLite/PostgreSQL tables (`worksheets`, `cases`, `audit_logs`)
with an in-memory mirror `_worksheets` kept for backwards-compatibility in unit tests.

Signature Challenge B:
  - Canonical SHA-256 payload hashing
  - Single-use HMAC-SHA256 approval tokens
  - Post-draft edits immediately invalidate prior approval tokens
  - Zero automated external regulatory filings (commits strictly to Case Management DB)

Tools: draft_disposition_report, submit_case_disposition
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from typing import Any, Optional

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from src.config import settings
from src.db.database import append_audit_log, get_db, init_db, utc_now_iso

mcp = FastMCP(
    name="case-actions",
    instructions="Write-gated server for case dispositions. All writes require a valid "
                 "HMAC approval token matching the current SHA-256 canonical payload hash.",
)

# Mirror cache kept synchronized with SQLite `worksheets` table (supports direct inspection in tests)
_worksheets: dict[str, dict[str, Any]] = {}


def _hmac_key() -> bytes:
    env_secret = os.getenv("HMAC_SECRET")
    if env_secret:
        return env_secret.encode()
    return settings.hmac_secret.get_secret_value().encode()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class DraftDispositionInput(BaseModel):
    alert_id: str
    recommended_disposition: str
    recommendation_rationale: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    candidate_paths: list[dict[str, Any]] = Field(default_factory=list)
    regulatory_citations: list[str] = Field(default_factory=list)
    kyc_summaries: list[str] = Field(default_factory=list)


class DraftDispositionOutput(BaseModel):
    worksheet_id: str
    alert_id: str
    payload_hash: str
    approval_token_required: str
    created_at: str
    content: dict[str, Any]


class SubmitCaseDispositionInput(BaseModel):
    worksheet_id: str
    approval_token: str
    reviewer_id: str
    reviewer_decision: str
    reviewer_notes: str = ""
    thread_id: str = "cli-or-direct"


class SubmitCaseDispositionOutput(BaseModel):
    success: bool
    case_id: str = ""
    worksheet_id: str
    final_disposition: str
    submitted_at: str
    audit_entry_id: str
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Cryptographic SHA-256 & HMAC Helpers
# ---------------------------------------------------------------------------
def _compute_payload_hash(content: dict[str, Any]) -> str:
    canonical = json.dumps(content, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _generate_approval_token(payload_hash: str) -> str:
    signature = hmac.new(_hmac_key(), payload_hash.encode(), hashlib.sha256).hexdigest()
    return f"APPROVE:{payload_hash}:{signature}"


def get_worksheet_record(worksheet_id: str) -> Optional[dict[str, Any]]:
    if worksheet_id in _worksheets:
        return _worksheets[worksheet_id]
    init_db()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM worksheets WHERE worksheet_id = ?", (worksheet_id,)).fetchone()
        if not row:
            return None
        rec = {
            "worksheet_id": row["worksheet_id"],
            "content": json.loads(row["content_json"]),
            "payload_hash": row["payload_hash"],
            "status": row["status"],
        }
        _worksheets[worksheet_id] = rec
        return rec


def update_worksheet_content(worksheet_id: str, updated_fields: dict[str, Any], editor_id: str, thread_id: str) -> Optional[dict[str, Any]]:
    """
    Apply an analyst edit to a drafted worksheet:
    Recomputes SHA-256 (`new_hash`), invalidating any prior approval token,
    persists to SQLite `worksheets`, and records an append-only audit log entry.
    """
    rec = get_worksheet_record(worksheet_id)
    if not rec:
        return None
    old_hash = rec["payload_hash"]
    new_content = {**rec["content"], **updated_fields, "edited_at": utc_now_iso(), "edited_by": editor_id}
    new_hash = _compute_payload_hash(new_content)
    rec["content"] = new_content
    rec["payload_hash"] = new_hash
    rec["status"] = "pending_review"
    _worksheets[worksheet_id] = rec

    init_db()
    with get_db() as conn:
        conn.execute(
            """
            UPDATE worksheets
            SET content_json = ?, payload_hash = ?, status = 'pending_review', updated_at = ?
            WHERE worksheet_id = ?
            """,
            (json.dumps(new_content, default=str), new_hash, utc_now_iso(), worksheet_id),
        )

    append_audit_log(
        thread_id=thread_id,
        event_type="worksheet_edited_hash_invalidated",
        actor=editor_id,
        payload_hash=new_hash,
        details={"worksheet_id": worksheet_id, "previous_hash": old_hash, "new_hash": new_hash},
    )
    return rec


def _verify_approval_token(worksheet_id: str, token: str) -> tuple[bool, str, Optional[dict[str, Any]]]:
    ws = get_worksheet_record(worksheet_id)
    if ws is None:
        return False, "worksheet_not_found", None

    if ws.get("status") == "submitted":
        return False, "already_committed", ws

    # Always recompute SHA-256 of current content so any in-memory or DB mutation is caught
    current_hash = _compute_payload_hash(ws["content"])

    parts = token.split(":")
    if len(parts) != 3 or parts[0] != "APPROVE":
        return False, "invalid_token_format", ws

    token_hash, token_sig = parts[1], parts[2]
    if token_hash != current_hash:
        return False, "token_invalidated_by_edit", ws

    expected_sig = hmac.new(_hmac_key(), token_hash.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(token_sig, expected_sig):
        return False, "invalid_hmac_signature", ws

    return True, "valid", ws


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------
@mcp.tool()
async def draft_disposition_report(params: DraftDispositionInput) -> DraftDispositionOutput:
    """Draft a citation-verified disposition worksheet and persist it with its SHA-256 hash."""
    init_db()
    worksheet_id = f"DWS-{uuid.uuid4().hex[:8].upper()}"
    now = utc_now_iso()

    content = {
        "alert_id": params.alert_id,
        "recommended_disposition": params.recommended_disposition,
        "recommendation_rationale": params.recommendation_rationale,
        "confidence_score": params.confidence_score,
        "candidate_paths": params.candidate_paths,
        "regulatory_citations": params.regulatory_citations,
        "kyc_summaries": params.kyc_summaries,
        "drafted_at": now,
    }
    payload_hash = _compute_payload_hash(content)

    record = {
        "worksheet_id": worksheet_id,
        "content": content,
        "payload_hash": payload_hash,
        "status": "pending_review",
    }
    _worksheets[worksheet_id] = record

    with get_db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO worksheets
            (worksheet_id, alert_id, content_json, payload_hash, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'pending_review', ?, ?)
            """,
            (worksheet_id, params.alert_id, json.dumps(content, default=str), payload_hash, now, now),
        )

    append_audit_log(
        thread_id="draft",
        event_type="draft_created",
        actor="auditguard_agent",
        payload_hash=payload_hash,
        details={"worksheet_id": worksheet_id, "alert_id": params.alert_id},
    )

    return DraftDispositionOutput(
        worksheet_id=worksheet_id,
        alert_id=params.alert_id,
        payload_hash=payload_hash,
        approval_token_required=f"APPROVE:{payload_hash}:<hmac>",
        created_at=now,
        content=content,
    )


@mcp.tool()
async def submit_case_disposition(params: SubmitCaseDispositionInput) -> SubmitCaseDispositionOutput:
    """
    Atomically commit an approved disposition to `cases` and `audit_logs`.
    Rejects tampered payloads (`token_invalidated_by_edit`) and replays (`already_committed`).
    """
    init_db()
    now = utc_now_iso()
    is_valid, reason, ws = _verify_approval_token(params.worksheet_id, params.approval_token)

    if not is_valid or ws is None:
        append_audit_log(
            thread_id=params.thread_id,
            event_type="submission_rejected",
            actor=params.reviewer_id,
            details={"worksheet_id": params.worksheet_id, "reason": reason},
        )
        return SubmitCaseDispositionOutput(
            success=False,
            worksheet_id=params.worksheet_id,
            final_disposition="",
            submitted_at=now,
            audit_entry_id="",
            error=f"Approval rejected: {reason}",
        )

    current_hash = _compute_payload_hash(ws["content"])
    case_id = f"CASE-DISP-{uuid.uuid4().hex[:8].upper()}"
    alert_id = ws["content"].get("alert_id", f"ALT-{uuid.uuid4().hex[:6]}")

    ws["status"] = "submitted"
    ws["reviewer_id"] = params.reviewer_id
    ws["reviewer_decision"] = params.reviewer_decision
    ws["reviewer_notes"] = params.reviewer_notes
    ws["submitted_at"] = now
    _worksheets[params.worksheet_id] = ws

    with get_db() as conn:
        conn.execute(
            """
            UPDATE worksheets
            SET status = 'submitted', reviewer_id = ?, reviewer_decision = ?, reviewer_notes = ?, updated_at = ?
            WHERE worksheet_id = ?
            """,
            (params.reviewer_id, params.reviewer_decision, params.reviewer_notes, now, params.worksheet_id),
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO cases
            (case_id, alert_id, worksheet_id, disposition, worksheet_json, payload_hash, approver_id, committed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                alert_id,
                params.worksheet_id,
                params.reviewer_decision,
                json.dumps(ws["content"], default=str),
                current_hash,
                params.reviewer_id,
                now,
            ),
        )
        conn.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?",
            (params.reviewer_decision.upper(), alert_id),
        )

    log_id = append_audit_log(
        thread_id=params.thread_id,
        case_id=case_id,
        event_type="case_committed",
        actor=params.reviewer_id,
        payload_hash=current_hash,
        details={
            "worksheet_id": params.worksheet_id,
            "alert_id": alert_id,
            "disposition": params.reviewer_decision,
            "notes": params.reviewer_notes,
        },
    )

    return SubmitCaseDispositionOutput(
        success=True,
        case_id=case_id,
        worksheet_id=params.worksheet_id,
        final_disposition=params.reviewer_decision,
        submitted_at=now,
        audit_entry_id=f"AUD-{log_id:06d}",
    )


if __name__ == "__main__":
    port = int(os.getenv("MCP_CASE_ACTIONS_PORT", "8013"))
    mcp.run(transport="streamable-http", host="0.0.0.0", port=port)
