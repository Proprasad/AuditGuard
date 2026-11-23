"""Right-to-erasure: one transaction purges/redacts a customer's data across every table (audit skeleton kept)."""

from __future__ import annotations

import sqlite3
from typing import Any

from src.core.canonical import dumps_json
from src.db.database import append_audit_log, get_db, init_db, utc_now_iso
from src.memory.store import memory_store


def _select_col(conn: sqlite3.Connection, sql: str, keys: list[str]) -> list[str]:
    out: list[str] = []
    for k in keys:
        out.extend(r[0] for r in conn.execute(sql, (k,)).fetchall())
    return out


def _update_many(conn: sqlite3.Connection, sql: str, marker: str, keys: list[str]) -> int:
    total = 0
    for k in keys:
        total += conn.execute(sql, (marker, k)).rowcount
    return total


def erase_customer(customer_id: str, actor: str) -> dict[str, Any]:
    init_db()
    memory_result = memory_store.forget_customer(customer_id)
    marker = dumps_json({"redacted": True, "reason": "right_to_erasure", "redacted_at": utc_now_iso()})
    counts: dict[str, int] = {}
    with get_db() as conn:
        accounts = [r[0] for r in conn.execute("SELECT account_id FROM accounts WHERE customer_id = ?", (customer_id,))]
        alerts = _select_col(conn, "SELECT alert_id FROM alerts WHERE seed_account_id = ?", accounts)
        threads = _select_col(conn, "SELECT thread_id FROM checkpoints WHERE alert_id = ?", alerts)
        worksheets = _select_col(conn, "SELECT worksheet_id FROM worksheets WHERE alert_id = ?", alerts)
        cases = _select_col(conn, "SELECT case_id FROM cases WHERE alert_id = ?", alerts)

        counts["entity_profiles"] = conn.execute(
            "DELETE FROM entity_profiles WHERE customer_id = ?", (customer_id,)
        ).rowcount
        counts["case_episodes"] = conn.execute(
            "DELETE FROM case_episodes WHERE customer_id = ?", (customer_id,)
        ).rowcount
        counts["approval_tokens"] = sum(
            conn.execute("DELETE FROM approval_tokens WHERE worksheet_id = ?", (w,)).rowcount for w in worksheets
        )
        counts["worksheets"] = _update_many(
            conn, "UPDATE worksheets SET content_json = ? WHERE worksheet_id = ?", marker, worksheets
        )
        counts["cases"] = _update_many(conn, "UPDATE cases SET worksheet_json = ? WHERE case_id = ?", marker, cases)
        counts["checkpoints"] = _update_many(
            conn, "UPDATE checkpoints SET state_json = ? WHERE thread_id = ?", marker, threads
        )
        counts["investigation_events"] = _update_many(
            conn, "UPDATE investigation_events SET payload_json = ? WHERE thread_id = ?", marker, threads
        )
        counts["audit_logs"] = _update_many(
            conn, "UPDATE audit_logs SET details_json = ? WHERE thread_id = ?", marker, threads
        ) + _update_many(conn, "UPDATE audit_logs SET details_json = ? WHERE case_id = ?", marker, cases)
    result = {
        "customer_id": customer_id,
        "profile_removed": memory_result["profile_removed"],
        "episodes_removed": memory_result["episodes_removed"],
        "tables": counts,
        "deleted_at": utc_now_iso(),
    }
    append_audit_log(
        thread_id="memory-forget",
        event_type="customer_memory_deleted",
        actor=actor,
        details={"customer_id": customer_id, "tables": counts},
    )
    return result
