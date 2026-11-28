"""Human decision logic: restricted edits, hash+token-bound approval, reject. All identity comes from the JWT."""

from __future__ import annotations

import asyncio
from datetime import timezone
import logging
from typing import Any

from src.agent.graph import resume_and_commit_gate, resume_gate
from src.core.canonical import utc_now
from src.core.verifier import verify_worksheet
from src.db import case_repo
from src.db.database import get_ro_db, save_checkpoint, utc_now_iso
from src.guardrails.guardrails import apply_input_guardrails, detect_injection
from src.memory.store import memory_store
from src.models import DecisionRequest, DispositionDecision, EditWorksheetRequest

logger = logging.getLogger("auditguard.approval")
ALLOWED_FINAL = {
    DispositionDecision.ESCALATE_STR,
    DispositionDecision.CLOSE_BENIGN,
    DispositionDecision.REQUEST_INFO,
}
_STATUS_FOR_CODE = {
    "ALREADY_COMMITTED": 409,
    "ALREADY_CONSUMED": 409,
    "WORKSHEET_NOT_PENDING": 409,
    "VERIFICATION_FAILED": 409,
    "PROHIBITED_GUILT_CLAIM": 422,
    "TOKEN_INVALIDATED_BY_EDIT": 403,
    "TOKEN_IDENTITY_MISMATCH": 403,
    "TOKEN_EXPIRED": 403,
    "INVALID_HMAC_SIGNATURE": 403,
    "INVALID_TOKEN_FORMAT": 403,
    "TOKEN_NOT_FOUND": 403,
    "UNAPPROVED_CRITICAL_ACTION": 403,
    "SELF_APPROVAL_FORBIDDEN": 403,
}


class DecisionError(Exception):
    def __init__(self, status_code: int, code: str, message: str = "", extra: Any = None) -> None:
        super().__init__(message or code)
        self.status_code, self.code, self.message, self.extra = status_code, code, message or code, extra


async def _release_gate(thread: dict[str, Any], decision: dict[str, Any]) -> None:
    """Resume the paused LangGraph `human_gate` interrupt on rejection so the graph run terminates cleanly."""
    try:
        await resume_gate(thread["thread_id"], thread["mode"], decision)
    except Exception:  # noqa: BLE001 - surface loudly, never mask
        logger.exception("failed to resume LangGraph human_gate for thread=%s", thread["thread_id"])


def _checkpoint(thread: dict[str, Any], status: str) -> None:
    save_checkpoint(
        thread_id=thread["thread_id"],
        alert_id=thread["alert_id"],
        mode=thread["mode"],
        current_node=status,
        status=status,
        state_dict=thread["state"],
        worksheet_id=thread["worksheet_id"],
        payload_hash=thread["payload_hash"],
    )


def _require_open(thread: dict[str, Any], allowed: tuple[str, ...]) -> dict[str, Any]:
    status = thread["status"]
    if status == "committed":
        raise DecisionError(409, "ALREADY_COMMITTED")
    if status not in allowed:
        raise DecisionError(
            409,
            "NOT_READY" if status in ("running", "error", "interrupted") else "THREAD_CLOSED",
            f"thread status is {status}",
        )
    ws = case_repo.get_worksheet(thread["worksheet_id"]) if thread.get("worksheet_id") else None
    if ws is None:
        raise DecisionError(404, "WORKSHEET_NOT_FOUND")
    if ws["status"] == "submitted":
        raise DecisionError(409, "ALREADY_COMMITTED")
    return ws


def _enforce_maker_checker(thread: dict[str, Any], ws: dict[str, Any], reviewer: str) -> None:
    """Four-eyes rule: neither the requester nor the last editor may approve. Unknown requester fails closed."""
    requester = case_repo.requester_of(thread["thread_id"])
    if requester is None:
        raise DecisionError(409, "REQUESTER_UNKNOWN", "no recorded requester for this thread; approval refused")
    conflict = case_repo.maker_checker_conflict(requester, ws["content"], reviewer)
    if conflict:
        raise DecisionError(403, "SELF_APPROVAL_FORBIDDEN", conflict)


def prepare_decision(thread: dict[str, Any], approved_hash: str | None, reviewer: str) -> dict[str, Any]:
    """Mint a single-use, 15-minute approval token bound to `(current_hash, reviewer, nonce)`."""
    ws = _require_open(thread, ("interrupt_required",))
    _enforce_maker_checker(thread, ws, reviewer)
    if approved_hash and approved_hash != ws["current_hash"]:
        raise DecisionError(403, "APPROVAL_HASH_MISMATCH", "approved_hash does not match the current worksheet")
    recheck = verify_worksheet(
        ws["content"],
        thread["state"].get("evidence_registry", {}),
        calc_log=thread["state"].get("calc_log"),
    )
    if not recheck.passed or ws["content"].get("verification_status") == "failed":
        raise DecisionError(
            409,
            "VERIFICATION_FAILED",
            "worksheet fails deterministic verification",
            [d.model_dump() for d in recheck.discrepancies] or ws["content"].get("verification_discrepancies"),
        )
    approval = case_repo.issue_approval_token(thread["thread_id"], ws["worksheet_id"], reviewer_id=reviewer)
    return {
        "thread_id": thread["thread_id"],
        "worksheet_id": ws["worksheet_id"],
        "approved_hash": approval["approved_hash"],
        "approval_token": approval["approval_token"],
        "issued_to": approval["issued_to"],
        "issued_at": approval["issued_at"],
        "expires_at": approval["expires_at"],
    }


def apply_edit(thread: dict[str, Any], edit: EditWorksheetRequest, reviewer: str) -> dict[str, Any]:
    """Restricted edit. The editor becomes `edited_by`, so a different senior reviewer must approve the new hash."""
    ws = _require_open(thread, ("interrupt_required", "verification_failed"))
    changes: dict[str, Any] = {}
    if edit.recommended_disposition is not None:
        if edit.recommended_disposition not in ALLOWED_FINAL:
            raise DecisionError(
                422, "INVALID_DISPOSITION", "disposition must be escalate_str, close_benign or request_info"
            )
        changes["recommended_disposition"] = edit.recommended_disposition.value
    for field in ("recommendation_rationale", "analyst_notes"):
        value = getattr(edit, field)
        if value is not None:
            if detect_injection(value):
                raise DecisionError(422, "GUARDRAIL_BLOCKED", "prompt_injection_detected")
            changes[field] = value
    if not changes:
        raise DecisionError(422, "EMPTY_EDIT", "no editable field supplied")

    candidate = {**ws["content"], **changes}
    registry = thread["state"].get("evidence_registry", {})
    result = verify_worksheet(candidate, registry, calc_log=thread["state"].get("calc_log"))
    if not result.passed:
        raise DecisionError(
            422,
            "VERIFIER_REJECTED_EDIT",
            "edit failed deterministic verification",
            [d.model_dump() for d in result.discrepancies],
        )
    candidate.update(
        {
            "edited_by": reviewer,
            "edited_at": utc_now().isoformat(),
            "verification_status": "passed",
            "verification_discrepancies": [],
        }
    )
    updated = case_repo.update_worksheet_content(ws["worksheet_id"], candidate, reviewer)
    thread["payload_hash"] = updated["payload_hash"]
    worksheet = thread["state"].get("worksheet") or {}
    worksheet.update(
        {
            "recommended_disposition": candidate["recommended_disposition"],
            "recommendation_rationale": candidate["recommendation_rationale"],
            "analyst_notes": candidate.get("analyst_notes"),
            "edited_by": candidate["edited_by"],
            "edited_at": candidate["edited_at"],
            "verification_status": candidate["verification_status"],
            "verification_discrepancies": candidate["verification_discrepancies"],
            "payload_hash": updated["payload_hash"],
        }
    )
    thread["state"]["worksheet"] = worksheet
    thread["state"]["error"] = None
    _checkpoint(thread, "interrupt_required")
    return {
        "thread_id": thread["thread_id"],
        "status": "interrupt_required",
        "previous_hash_invalidated": updated["previous_hash"],
        "payload_hash": updated["payload_hash"],
        "approved_hash": updated["payload_hash"],
        "approval_token": None,
        "updated_content": candidate,
        "message": (
            "Worksheet edited and re-verified. Prior approval tokens are void; a different senior reviewer "
            "(not the requester or this editor) must prepare and approve the new hash."
        ),
    }


def _customer_for_alert(alert_id: str) -> str | None:
    with get_ro_db() as conn:
        row = conn.execute(
            (
                "SELECT acc.customer_id FROM alerts a JOIN accounts acc ON "
                "a.seed_account_id = acc.account_id WHERE a.alert_id = ?"
            ),
            (alert_id,),
        ).fetchone()
    return str(row["customer_id"]) if row else None


def _persist_post_commit(
    thread: dict[str, Any],
    final_disposition: str,
    reviewer: str,
    current_hash: str,
) -> None:
    thread["state"]["workflow_steps"] = [
        {**s, "status": "completed"} if s.get("step") in (6, 7) else s
        for s in thread["state"].get("workflow_steps", [])
    ]
    _checkpoint(thread, "committed")
    if customer_id := _customer_for_alert(thread["alert_id"]):
        now_iso = utc_now().astimezone(timezone.utc).isoformat()
        memory_store.save_entity_profile(
            customer_id,
            {
                "last_alert_id": thread["alert_id"],
                "last_disposition": final_disposition,
                "reviewed_by": reviewer,
                "reviewed_at": now_iso,
            },
        )
        memory_store.save_case_episode(
            customer_id,
            {
                "alert_id": thread["alert_id"],
                "disposition": final_disposition,
                "reviewer_id": reviewer,
                "payload_hash": current_hash,
                "archived_at": now_iso,
            },
            human_approved=True,
        )


async def approve(thread: dict[str, Any], req: DecisionRequest, reviewer: str) -> dict[str, Any]:
    ws = await asyncio.to_thread(_require_open, thread, ("interrupt_required",))
    await asyncio.to_thread(_enforce_maker_checker, thread, ws, reviewer)
    if not (req.approved_hash and req.approval_token):
        raise DecisionError(422, "MISSING_APPROVAL_CREDENTIALS", "approved_hash and approval_token are required")
    if req.approved_hash != ws["current_hash"]:
        raise DecisionError(403, "APPROVAL_HASH_MISMATCH", "approved_hash does not match the current worksheet")
    recheck = verify_worksheet(
        ws["content"],
        thread["state"].get("evidence_registry", {}),
        calc_log=thread["state"].get("calc_log"),
    )
    if not recheck.passed or ws["content"].get("verification_status") == "failed":
        raise DecisionError(
            409,
            "VERIFICATION_FAILED",
            "worksheet fails deterministic verification",
            [d.model_dump() for d in recheck.discrepancies] or ws["content"].get("verification_discrepancies"),
        )

    guard = apply_input_guardrails(req.notes)
    if not guard.allowed:
        raise DecisionError(422, "GUARDRAIL_BLOCKED", guard.blocked_reason)

    result = await resume_and_commit_gate(
        thread["thread_id"],
        thread["mode"],
        {
            "action": "approve",
            "worksheet_id": ws["worksheet_id"],
            "approval_token": req.approval_token,
            "reviewer": reviewer,
            "reviewer_notes": guard.scrubbed_text,
            "thread_id": thread["thread_id"],
            "disposition": ws["content"].get("recommended_disposition"),
        },
    )
    if result is None:
        raise DecisionError(
            409,
            "INTERRUPT_NOT_ACTIVE",
            "LangGraph thread is not paused at human_gate interrupt; commit rejected fail-closed",
        )
    if not result.get("success"):
        code = str(result.get("error_code") or "COMMIT_FAILED")
        raise DecisionError(
            _STATUS_FOR_CODE.get(code, 400),
            code,
            str(result.get("error") or result.get("message") or code),
            result.get("discrepancies"),
        )

    await asyncio.to_thread(_persist_post_commit, thread, result["final_disposition"], reviewer, ws["current_hash"])
    return {
        "thread_id": thread["thread_id"],
        "status": "committed",
        "decision": result["final_disposition"],
        "receipt": {k: result[k] for k in ("case_id", "audit_entry_id", "submitted_at", "worksheet_id")},
    }


def _persist_reject(thread: dict[str, Any], worksheet_id: str, reviewer: str, notes: str) -> None:
    case_repo.mark_rejected(worksheet_id, reviewer, thread["thread_id"], notes)
    thread["state"]["workflow_steps"] = [
        {**s, "status": "failed"} if s.get("step") == 6 else s for s in thread["state"].get("workflow_steps", [])
    ]
    _checkpoint(thread, "rejected")


async def reject(thread: dict[str, Any], req: DecisionRequest, reviewer: str) -> dict[str, Any]:
    ws = await asyncio.to_thread(_require_open, thread, ("interrupt_required", "verification_failed"))
    guard = apply_input_guardrails(req.notes)
    if not guard.allowed:
        raise DecisionError(422, "GUARDRAIL_BLOCKED", guard.blocked_reason)
    await asyncio.to_thread(_persist_reject, thread, ws["worksheet_id"], reviewer, guard.scrubbed_text)
    await _release_gate(thread, {"action": "reject", "reviewer": reviewer})
    return {
        "thread_id": thread["thread_id"],
        "status": "rejected",
        "decision": "rejected",
        "decided_at": utc_now_iso(),
        "message": "Disposition rejected and logged to the manual review queue.",
    }
