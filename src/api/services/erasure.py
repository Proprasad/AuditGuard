"""Right-to-erasure: one transaction purges/redacts a customer's data across every table (audit skeleton kept)."""
from __future__ import annotations

from typing import Any

from src.core.canonical import dumps_json
from src.db.database import append_audit_log, get_db, init_db, utc_now_iso
from src.memory.store import memory_store


def _in(values: list[str]) -> str:
    return ",".join("?" for _ in values) or "NULL"


def erase_customer(customer_id: str, actor: str) -> dict[str, Any]:
    init_db()
    memory_result = memory_store.forget_customer(customer_id)
    marker = dumps_json({"redacted": True, "reason": "right_to_erasure", "redacted_at": utc_now_iso()})
    counts: dict[str, int] = {}
    with get_db() as conn:
        accounts = [r[0] for r in conn.execute("SELECT account_id FROM accounts WHERE customer_id = ?", (customer_id,))]
        alerts = [r[0] for r in conn.execute(f"SELECT alert_id FROM alerts WHERE seed_account_id IN ({_in(accounts)})", accounts)]  # noqa: S608
        threads = [r[0] for r in conn.execute(f"SELECT thread_id FROM checkpoints WHERE alert_id IN ({_in(alerts)})", alerts)]  # noqa: S608
        worksheets = [r[0] for r in conn.execute(f"SELECT worksheet_id FROM worksheets WHERE alert_id IN ({_in(alerts)})", alerts)]  # noqa: S608
        cases = [r[0] for r in conn.execute(f"SELECT case_id FROM cases WHERE alert_id IN ({_in(alerts)})", alerts)]  # noqa: S608

        counts["entity_profiles"] = conn.execute("DELETE FROM entity_profiles WHERE customer_id = ?", (customer_id,)).rowcount
        counts["case_episodes"] = conn.execute("DELETE FROM case_episodes WHERE customer_id = ?", (customer_id,)).rowcount
        counts["approval_tokens"] = conn.execute(f"DELETE FROM approval_tokens WHERE worksheet_id IN ({_in(worksheets)})", worksheets).rowcount  # noqa: S608
        counts["worksheets"] = conn.execute(f"UPDATE worksheets SET content_json = ? WHERE worksheet_id IN ({_in(worksheets)})", [marker, *worksheets]).rowcount  # noqa: S608
        counts["cases"] = conn.execute(f"UPDATE cases SET worksheet_json = ? WHERE case_id IN ({_in(cases)})", [marker, *cases]).rowcount  # noqa: S608
        counts["checkpoints"] = conn.execute(f"UPDATE checkpoints SET state_json = ? WHERE thread_id IN ({_in(threads)})", [marker, *threads]).rowcount  # noqa: S608
        counts["investigation_events"] = conn.execute(f"UPDATE investigation_events SET payload_json = ? WHERE thread_id IN ({_in(threads)})", [marker, *threads]).rowcount  # noqa: S608
        counts["audit_logs"] = conn.execute(
            f"UPDATE audit_logs SET details_json = ? WHERE thread_id IN ({_in(threads)}) OR case_id IN ({_in(cases)})",  # noqa: S608
            [marker, *threads, *cases],
        ).rowcount
    result = {"customer_id": customer_id, "profile_removed": memory_result["profile_removed"],
              "episodes_removed": memory_result["episodes_removed"], "tables": counts, "deleted_at": utc_now_iso()}
    append_audit_log(thread_id="memory-forget", event_type="customer_memory_deleted", actor=actor,
                     details={"customer_id": customer_id, "tables": counts})
    return result
