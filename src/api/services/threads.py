"""Investigation thread access: DB (checkpoints + worksheets + approval tokens) is the single source of truth."""

from __future__ import annotations

from typing import Any, Optional

from src.db import case_repo
from src.db.database import load_checkpoint


def get_thread(thread_id: str) -> Optional[dict[str, Any]]:
    cp = load_checkpoint(thread_id)
    if cp is None:
        return None
    return {
        "thread_id": cp["thread_id"],
        "alert_id": cp["alert_id"],
        "mode": cp["mode"],
        "status": cp["status"],
        "current_node": cp["current_node"],
        "worksheet_id": cp["worksheet_id"],
        "payload_hash": cp["payload_hash"],
        "state": cp["state"],
        "alert": cp["state"].get("alert", {}),
    }


def thread_view(thread_id: str) -> Optional[dict[str, Any]]:
    """Thread record with the CURRENT worksheet (post-edit) and the current unconsumed approval token overlaid."""
    thread = get_thread(thread_id)
    if thread is None or not thread["worksheet_id"]:
        return thread
    ws = case_repo.get_worksheet(thread["worksheet_id"])
    if ws is None:
        return thread
    content = ws["content"]
    worksheet = thread["state"].get("worksheet") or {}
    worksheet.update(
        {
            "recommended_disposition": content.get("recommended_disposition"),
            "recommendation_rationale": content.get("recommendation_rationale"),
            "payload_hash": ws["current_hash"],
            "verification_status": content.get("verification_status", "passed"),
        }
    )
    thread["state"]["worksheet"] = worksheet
    thread["payload_hash"] = ws["current_hash"]
    thread["worksheet_status"] = ws["status"]
    thread["verification_discrepancies"] = content.get("verification_discrepancies", [])
    thread["approval"] = case_repo.current_approval(thread["worksheet_id"])
    return thread
