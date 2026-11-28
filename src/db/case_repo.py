"""
Write-scoped repository used ONLY by the case-actions MCP server.

Connections come from `get_scoped_db`, whose SQL authorizer denies any write/DDL outside
{worksheets, approval_tokens, cases, audit_logs}. Approval tokens are single-use, HMAC-signed and bound to the
canonical SHA-256 of the exact worksheet content; consumption + case insert + worksheet transition happen in ONE
transaction (all-or-nothing).
"""

from __future__ import annotations

from datetime import timedelta
import hashlib
import hmac
import json
import sqlite3
from typing import Any, Optional
import uuid

from src.config import get_hmac_secret
from src.core.canonical import canonical_sha256, dumps_json, parse_utc_timestamp, utc_now
from src.db.database import DbConn, get_db, get_scoped_db, init_db, utc_now_iso

CASE_WRITE_TABLES = frozenset({"worksheets", "approval_tokens", "cases", "audit_logs"})
APPROVAL_TOKEN_TTL_SECONDS = 15 * 60  # 15 minutes per Phase 0 spec


class CaseRepoError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------------------------------
# Tokens: HMAC(secret, hash|sub|nonce), single-use, 15-minute TTL
# ---------------------------------------------------------------------------------------------------
def _signature(token_id: str, sha: str, reviewer_id: str) -> str:
    msg = f"{sha}|{reviewer_id}|{token_id}".encode("utf-8")
    return hmac.new(get_hmac_secret(), msg, hashlib.sha256).hexdigest()


def build_approval_token(token_id: str, sha: str, reviewer_id: str) -> str:
    return f"APPROVE:{token_id}:{sha}:{_signature(token_id, sha, reviewer_id)}"


def token_digest(token: str) -> str:
    """At-rest form of an approval token: only this digest is stored, never the bearer token itself."""
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------------------------------
# Maker-checker: the requester and the last editor of a worksheet may never approve it
# ---------------------------------------------------------------------------------------------------
REQUESTED_EVENT = "investigation_requested"


def _requester(conn: DbConn, thread_id: str) -> Optional[str]:
    row = conn.execute(
        "SELECT actor FROM audit_logs WHERE thread_id = ? AND event_type = ? ORDER BY log_id ASC LIMIT 1",
        (thread_id, REQUESTED_EVENT),
    ).fetchone()
    return str(row["actor"]) if row else None


def requester_of(thread_id: str) -> Optional[str]:
    """Identity (JWT `sub`) that started `thread_id`, from the append-only audit log."""
    init_db()
    with get_db() as conn:
        return _requester(conn, thread_id)


def maker_checker_conflict(requester: Optional[str], content: dict[str, Any], reviewer_id: str) -> Optional[str]:
    """Return why `reviewer_id` may not approve, or None. Unknown requesters are handled by the caller."""
    if requester is not None and reviewer_id == requester:
        return "the investigation requester cannot approve their own investigation"
    if reviewer_id == content.get("edited_by"):
        return "the last editor of the worksheet cannot approve their own edit"
    return None


def parse_approval_token(token: str) -> Optional[tuple[str, str, str]]:
    parts = token.split(":")
    if len(parts) != 4 or parts[0] != "APPROVE" or not all(parts[1:]):
        return None
    return parts[1], parts[2], parts[3]


# ---------------------------------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------------------------------
def get_worksheet(worksheet_id: str) -> Optional[dict[str, Any]]:
    init_db()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM worksheets WHERE worksheet_id = ?", (worksheet_id,)).fetchone()
    if row is None:
        return None
    content = json.loads(row["content_json"])
    return {
        "worksheet_id": row["worksheet_id"],
        "alert_id": row["alert_id"],
        "thread_id": row["thread_id"],
        "revision": row["revision"],
        "status": row["status"],
        "content": content,
        "stored_hash": row["payload_hash"],
        "current_hash": canonical_sha256(content),
    }


def _audit(
    conn: DbConn,
    thread_id: str,
    event_type: str,
    actor: str,
    details: dict[str, Any],
    payload_hash: Optional[str] = None,
    case_id: Optional[str] = None,
) -> None:
    conn.execute(
        "INSERT INTO audit_logs (case_id, thread_id, event_type, actor, payload_hash, details_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (case_id, thread_id, event_type, actor, payload_hash, dumps_json(details), utc_now_iso()),
    )


# ---------------------------------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------------------------------
def upsert_draft(content: dict[str, Any], thread_id: Optional[str], revision: int = 1) -> dict[str, Any]:
    """Idempotent draft keyed on (thread_id, revision): re-drafting overwrites the pending sheet, never duplicates."""
    init_db()
    sha = canonical_sha256(content)
    now = utc_now_iso()
    with get_scoped_db(CASE_WRITE_TABLES) as conn:
        existing = None
        if thread_id:
            existing = conn.execute(
                (
                    "SELECT worksheet_id, status, content_json, payload_hash "
                    "FROM worksheets WHERE thread_id = ? AND revision = ?"
                ),
                (thread_id, revision),
            ).fetchone()
        if existing and existing["status"] == "submitted":
            return {
                "worksheet_id": existing["worksheet_id"],
                "payload_hash": existing["payload_hash"],
                "content": json.loads(existing["content_json"]),
                "created": False,
            }
        if existing:
            worksheet_id = existing["worksheet_id"]
            conn.execute(
                (
                    "UPDATE worksheets SET content_json = ?, payload_hash = ?, status "
                    "= 'pending_review', updated_at = ? WHERE worksheet_id = ?"
                ),
                (dumps_json(content), sha, now, worksheet_id),
            )
        else:
            worksheet_id = f"DWS-{uuid.uuid4().hex[:8].upper()}"
            conn.execute(
                "INSERT INTO worksheets (worksheet_id, alert_id, content_json, "
                "payload_hash, status, thread_id, revision, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'pending_review', ?, ?, ?, ?)",
                (worksheet_id, content["alert_id"], dumps_json(content), sha, thread_id, revision, now, now),
            )
        _audit(
            conn,
            thread_id or "draft",
            "draft_created",
            "auditguard_agent",
            {"worksheet_id": worksheet_id, "alert_id": content["alert_id"]},
            sha,
        )
    return {
        "worksheet_id": worksheet_id,
        "payload_hash": sha,
        "content": content,
        "created": existing is None,
    }


def update_worksheet_content(worksheet_id: str, new_content: dict[str, Any], editor_id: str) -> dict[str, Any]:
    """Apply an analyst edit: recompute SHA-256, bump revision, supersede every unconsumed approval token."""
    now = utc_now_iso()
    new_sha = canonical_sha256(new_content)
    with get_scoped_db(CASE_WRITE_TABLES) as conn:
        row = conn.execute(
            "SELECT status, payload_hash, thread_id, revision FROM worksheets WHERE worksheet_id = ?",
            (worksheet_id,),
        ).fetchone()
        if row is None:
            raise CaseRepoError("WORKSHEET_NOT_FOUND", f"worksheet {worksheet_id} not found")
        if row["status"] != "pending_review":
            raise CaseRepoError("WORKSHEET_NOT_PENDING", f"worksheet is {row['status']}")
        conn.execute(
            (
                "UPDATE worksheets SET content_json = ?, payload_hash = ?, "
                "revision = revision + 1, updated_at = ? WHERE worksheet_id = ?"
            ),
            (dumps_json(new_content), new_sha, now, worksheet_id),
        )
        conn.execute(
            (
                "UPDATE approval_tokens SET consumed_at = ?, consumed_by = "
                "'superseded_by_edit' WHERE worksheet_id = ? AND consumed_at IS NULL"
            ),
            (now, worksheet_id),
        )
        _audit(
            conn,
            row["thread_id"] or "edit",
            "worksheet_edited_hash_invalidated",
            editor_id,
            {"worksheet_id": worksheet_id, "previous_hash": row["payload_hash"], "new_hash": new_sha},
            new_sha,
        )
    return {"worksheet_id": worksheet_id, "previous_hash": row["payload_hash"], "payload_hash": new_sha}


def issue_approval_token(
    thread_id: str,
    worksheet_id: str,
    reviewer_id: str = "reviewer",
    ttl_seconds: int = APPROVAL_TOKEN_TTL_SECONDS,
) -> dict[str, Any]:
    """Issue a fresh single-use token bound to `(current_hash, reviewer_id, nonce)` with a 15-minute TTL."""
    if not reviewer_id.strip():
        raise CaseRepoError("MISSING_REVIEWER_ID", "reviewer identity is required to mint an approval token")
    ws = get_worksheet(worksheet_id)
    if ws is None:
        raise CaseRepoError("WORKSHEET_NOT_FOUND", f"worksheet {worksheet_id} not found")
    token_id = uuid.uuid4().hex
    now_dt = utc_now()
    now = now_dt.isoformat()
    expires_at = (now_dt + timedelta(seconds=ttl_seconds)).isoformat()
    sha = ws["current_hash"]
    token = build_approval_token(token_id, sha, reviewer_id)
    with get_scoped_db(CASE_WRITE_TABLES) as conn:
        conn.execute(
            (
                "UPDATE approval_tokens SET consumed_at = ?, consumed_by = "
                "'superseded' WHERE worksheet_id = ? AND issued_to = ? AND consumed_at IS NULL"
            ),
            (now, worksheet_id, reviewer_id),
        )
        conn.execute(
            "INSERT INTO approval_tokens (token_id, thread_id, worksheet_id, "
            "worksheet_sha256, hmac_token, issued_to, issued_at, expires_at, consumed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            (token_id, thread_id, worksheet_id, sha, token_digest(token), reviewer_id, now, expires_at),
        )
    return {
        "token_id": token_id,
        "worksheet_id": worksheet_id,
        "approved_hash": sha,
        "approval_token": token,
        "issued_to": reviewer_id,
        "issued_at": now,
        "expires_at": expires_at,
    }


def _validate_commit_token(
    conn: DbConn, worksheet_id: str, approval_token: str, reviewer_id: str
) -> tuple[Any, dict[str, Any], str, str]:
    parsed = parse_approval_token(approval_token)
    if parsed is None:
        raise CaseRepoError("INVALID_TOKEN_FORMAT", "approval token is malformed")
    token_id, token_sha, token_sig = parsed
    ws = conn.execute("SELECT * FROM worksheets WHERE worksheet_id = ?", (worksheet_id,)).fetchone()
    if ws is None:
        raise CaseRepoError("WORKSHEET_NOT_FOUND", f"worksheet {worksheet_id} not found")
    if ws["status"] == "submitted":
        raise CaseRepoError("ALREADY_COMMITTED", "worksheet already committed")
    content = json.loads(ws["content_json"])
    current_sha = canonical_sha256(content)
    tok = conn.execute(
        "SELECT * FROM approval_tokens WHERE token_id = ? AND worksheet_id = ?", (token_id, worksheet_id)
    ).fetchone()
    if tok is None:
        raise CaseRepoError("TOKEN_NOT_FOUND", "approval token was not issued for this worksheet")
    if tok["consumed_at"] is not None:
        raise CaseRepoError("ALREADY_CONSUMED", "approval token already consumed or superseded")
    if token_sha != current_sha or tok["worksheet_sha256"] != current_sha:
        raise CaseRepoError("TOKEN_INVALIDATED_BY_EDIT", "worksheet changed since the token was issued")
    if tok["issued_to"] != reviewer_id:
        raise CaseRepoError("TOKEN_IDENTITY_MISMATCH", "approval token was signed for a different reviewer")
    if tok["expires_at"] and parse_utc_timestamp(tok["expires_at"]) <= utc_now():
        raise CaseRepoError("TOKEN_EXPIRED", "approval token has expired (15-minute TTL)")
    expected_sig = _signature(token_id, token_sha, reviewer_id)
    if not hmac.compare_digest(token_sig, expected_sig) or not hmac.compare_digest(
        str(tok["hmac_token"]), token_digest(approval_token)
    ):
        raise CaseRepoError("INVALID_HMAC_SIGNATURE", "approval token signature invalid")
    conflict = maker_checker_conflict(_requester(conn, str(ws["thread_id"] or "")), content, reviewer_id)
    if conflict:
        raise CaseRepoError("SELF_APPROVAL_FORBIDDEN", conflict)
    return ws, content, current_sha, token_id


def commit_case(
    worksheet_id: str, approval_token: str, reviewer_id: str, reviewer_notes: str, thread_id: str
) -> dict[str, Any]:
    """Atomically verify + consume the single-use token, mark the worksheet submitted and INSERT the case."""
    now = utc_now_iso()
    with get_scoped_db(CASE_WRITE_TABLES) as conn:
        ws, content, current_sha, token_id = _validate_commit_token(conn, worksheet_id, approval_token, reviewer_id)
        consumed = conn.execute(
            (
                "UPDATE approval_tokens SET consumed_at = ?, consumed_by = ? WHERE "
                "token_id = ? AND worksheet_sha256 = ? AND consumed_at IS NULL"
            ),
            (now, reviewer_id, token_id, current_sha),
        )
        if consumed.rowcount != 1:
            raise CaseRepoError("ALREADY_CONSUMED", "approval token already consumed")
        conn.execute(
            "UPDATE approval_tokens SET consumed_at = ?, consumed_by = 'superseded_by_commit' "
            "WHERE worksheet_id = ? AND consumed_at IS NULL",
            (now, worksheet_id),
        )
        moved = conn.execute(
            "UPDATE worksheets SET status = 'submitted', reviewer_id = ?, "
            "reviewer_decision = ?, reviewer_notes = ?, updated_at = ? "
            "WHERE worksheet_id = ? AND status = 'pending_review'",
            (reviewer_id, content["recommended_disposition"], reviewer_notes, now, worksheet_id),
        )
        if moved.rowcount != 1:
            raise CaseRepoError("WORKSHEET_NOT_PENDING", "worksheet is not pending review")
        case_id = f"CASE-DISP-{uuid.uuid4().hex[:8].upper()}"
        try:
            conn.execute(
                "INSERT INTO cases (case_id, alert_id, worksheet_id, disposition, "
                "worksheet_json, payload_hash, approver_id, committed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case_id,
                    ws["alert_id"],
                    worksheet_id,
                    content["recommended_disposition"],
                    dumps_json(content),
                    current_sha,
                    reviewer_id,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise CaseRepoError("ALREADY_COMMITTED", f"a case already exists for alert {ws['alert_id']}") from exc
        details = {
            "worksheet_id": worksheet_id,
            "alert_id": ws["alert_id"],
            "disposition": content["recommended_disposition"],
        }
        cur = conn.execute(
            "INSERT INTO audit_logs (case_id, thread_id, event_type, actor, payload_hash, details_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (case_id, thread_id, "case_committed", reviewer_id, current_sha, dumps_json(details), now),
        )
        log_id = int(cur.lastrowid or 0)
    return {
        "case_id": case_id,
        "alert_id": ws["alert_id"],
        "disposition": content["recommended_disposition"],
        "payload_hash": current_sha,
        "audit_entry_id": f"AUD-{log_id:06d}",
        "committed_at": now,
    }


def log_rejection(thread_id: str, reviewer_id: str, worksheet_id: str, code: str) -> None:
    with get_scoped_db(CASE_WRITE_TABLES) as conn:
        _audit(
            conn,
            thread_id,
            "submission_rejected",
            reviewer_id,
            {"worksheet_id": worksheet_id, "reason": code},
        )


def current_approval(worksheet_id: str, reviewer_id: Optional[str] = None) -> Optional[dict[str, Any]]:
    """
    Read-only lookup of the active (unconsumed, non-expired) token metadata for `reviewer_id` on `worksheet_id`.
    Tokens are stored as digests only, so `approval_token` is always None here: the bearer token is returned once,
    by `issue_approval_token` (`/decision/prepare`), and must be kept by the client.
    """
    ws = get_worksheet(worksheet_id)
    if ws is None:
        return None
    base: dict[str, Any] = {
        "token_id": None,
        "approved_hash": ws["current_hash"],
        "approval_token": None,
        "issued_to": None,
        "issued_at": None,
        "expires_at": None,
    }
    if not reviewer_id:
        return base
    with get_db() as conn:
        row = conn.execute(
            "SELECT token_id, worksheet_sha256, hmac_token, issued_to, issued_at, expires_at "
            "FROM approval_tokens WHERE worksheet_id = ? AND issued_to = ? AND consumed_at IS NULL "
            "ORDER BY issued_at DESC LIMIT 1",
            (worksheet_id, reviewer_id),
        ).fetchone()
    if row is None or row["worksheet_sha256"] != ws["current_hash"]:
        return base
    if row["expires_at"] and parse_utc_timestamp(row["expires_at"]) <= utc_now():
        return base
    return {
        "token_id": row["token_id"],
        "approved_hash": row["worksheet_sha256"],
        "approval_token": None,
        "issued_to": row["issued_to"],
        "issued_at": row["issued_at"],
        "expires_at": row["expires_at"],
    }


def mark_rejected(worksheet_id: str, reviewer_id: str, thread_id: str, notes: str) -> None:
    now = utc_now_iso()
    with get_scoped_db(CASE_WRITE_TABLES) as conn:
        conn.execute(
            "UPDATE worksheets SET status = 'rejected', reviewer_id = ?, reviewer_decision = 'rejected', "
            "reviewer_notes = ?, updated_at = ? WHERE worksheet_id = ?",
            (reviewer_id, notes, now, worksheet_id),
        )
        conn.execute(
            (
                "UPDATE approval_tokens SET consumed_at = ?, consumed_by = "
                "'rejected' WHERE worksheet_id = ? AND consumed_at IS NULL"
            ),
            (now, worksheet_id),
        )
        _audit(
            conn,
            thread_id,
            "disposition_rejected_by_human",
            reviewer_id,
            {"worksheet_id": worksheet_id, "notes": notes},
        )
