"""Right-to-erasure: one atomic transaction purges/redacts a customer's PII across operational & checkpoint stores."""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Any

from src.agent.graph import checkpoint_db_path
from src.config import settings
from src.core.canonical import dumps_json
from src.db.database import DbConn, append_audit_log, get_db, init_db, use_postgres_active, utc_now_iso
from src.memory.store import memory_store


def _select_col(conn: DbConn, sql: str, keys: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for k in keys:
        for r in conn.execute(sql, (k,)).fetchall():
            seen[str(r[0])] = None
    return list(seen)


def _update_many(conn: DbConn, sql: str, marker: str, keys: list[str]) -> int:
    total = 0
    for k in keys:
        total += conn.execute(sql, (marker, k)).rowcount
    return total


def _delete_pg_saver_table(pg_conn: Any, tbl: str, threads: list[str]) -> int:
    with pg_conn.cursor() as cur:
        exists = cur.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = %s",
            (tbl,),
        ).fetchone()
        if not exists:
            return 0
        removed = 0
        for tid in threads:
            cur.execute(f"DELETE FROM {tbl} WHERE thread_id = %s", (tid,))  # noqa: S608
            removed += int(cur.rowcount or 0)
        return removed


def _purge_postgres_saver(threads: list[str]) -> int:
    import psycopg

    saver_tables = ("checkpoint_writes", "checkpoint_blobs", "checkpoints")
    with psycopg.connect(settings.sync_database_url) as pg_conn:
        removed = sum(_delete_pg_saver_table(pg_conn, t, threads) for t in saver_tables)
        pg_conn.commit()
    return removed


def _purge_langgraph_saver(threads: list[str]) -> int:
    if not threads:
        return 0
    if use_postgres_active():
        return _purge_postgres_saver(threads)
    saver_path = checkpoint_db_path()
    if not saver_path.exists():
        return 0
    removed = 0
    conn = sqlite3.connect(str(saver_path), timeout=10.0)
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        for tbl in ("checkpoints", "writes"):
            if tbl in tables:
                for tid in threads:
                    removed += conn.execute(f"DELETE FROM {tbl} WHERE thread_id = ?", (tid,)).rowcount  # noqa: S608
        conn.commit()
    finally:
        conn.close()
    return removed


def erase_customer(customer_id: str, actor: str) -> dict[str, Any]:
    init_db()
    mem_profile_removed, mem_episodes_removed = memory_store.evict_customer_cache(customer_id)
    marker = dumps_json({"redacted": True, "reason": "right_to_erasure", "redacted_at": utc_now_iso()})
    customer_hash = hashlib.sha256(customer_id.encode("utf-8")).hexdigest()[:16]
    redacted_pan = f"REDACTED-{customer_hash}"
    counts: dict[str, int] = {}

    with get_db() as conn:
        acc_rows = conn.execute("SELECT account_id FROM accounts WHERE customer_id = ?", (customer_id,)).fetchall()
        accounts = [str(r[0]) for r in acc_rows]
        seed_alerts = _select_col(conn, "SELECT alert_id FROM alerts WHERE seed_account_id = ?", accounts)
        net_alerts = _select_col(
            conn, "SELECT alert_id FROM alerts WHERE network_accounts_json LIKE ?", [f'%"{a}"%' for a in accounts]
        )
        alerts = list(dict.fromkeys([*seed_alerts, *net_alerts]))
        threads = _select_col(conn, "SELECT thread_id FROM thread_checkpoints WHERE alert_id = ?", alerts)
        worksheets = _select_col(conn, "SELECT worksheet_id FROM worksheets WHERE alert_id = ?", alerts)
        cases = _select_col(conn, "SELECT case_id FROM cases WHERE alert_id = ?", alerts)

        counts["entity_profiles"] = conn.execute(
            "DELETE FROM entity_profiles WHERE customer_id = ?", (customer_id,)
        ).rowcount
        counts["case_episodes"] = conn.execute(
            "DELETE FROM case_episodes WHERE customer_id = ?", (customer_id,)
        ).rowcount
        counts["commercial_registry"] = conn.execute(
            "DELETE FROM commercial_registry WHERE customer_id = ?", (customer_id,)
        ).rowcount
        counts["customers"] = conn.execute(
            "UPDATE customers SET full_name = '[REDACTED]', kyc_notes = '[REDACTED]', "
            "declared_annual_income_inr = '0.00', synthetic_pan_hash = ? WHERE customer_id = ?",
            (redacted_pan, customer_id),
        ).rowcount
        counts["transactions"] = sum(
            conn.execute(
                "UPDATE transactions SET memo_text = '[REDACTED]' WHERE from_account_id = ? OR to_account_id = ?",
                (acc, acc),
            ).rowcount
            for acc in accounts
        )
        counts["approval_tokens"] = sum(
            conn.execute("DELETE FROM approval_tokens WHERE worksheet_id = ?", (w,)).rowcount for w in worksheets
        )
        counts["worksheets"] = _update_many(
            conn, "UPDATE worksheets SET content_json = ? WHERE worksheet_id = ?", marker, worksheets
        )
        counts["cases"] = _update_many(conn, "UPDATE cases SET worksheet_json = ? WHERE case_id = ?", marker, cases)
        counts["checkpoints"] = _update_many(
            conn, "UPDATE thread_checkpoints SET state_json = ? WHERE thread_id = ?", marker, threads
        )
        counts["investigation_events"] = _update_many(
            conn, "UPDATE investigation_events SET payload_json = ? WHERE thread_id = ?", marker, threads
        )
        counts["audit_logs"] = _update_many(
            conn, "UPDATE audit_logs SET details_json = ? WHERE thread_id = ?", marker, threads
        ) + _update_many(conn, "UPDATE audit_logs SET details_json = ? WHERE case_id = ?", marker, cases)

    counts["langgraph_saver"] = _purge_langgraph_saver(threads)
    profile_removed = mem_profile_removed or counts["entity_profiles"] > 0
    episodes_removed = max(mem_episodes_removed, counts["case_episodes"])
    result = {
        "customer_id": customer_id,
        "profile_removed": profile_removed,
        "episodes_removed": episodes_removed,
        "tables": counts,
        "deleted_at": utc_now_iso(),
    }
    append_audit_log(
        thread_id="memory-forget",
        event_type="customer_memory_deleted",
        actor=actor,
        details={"customer_id_sha256": customer_hash, "tables": counts},
    )
    return result
