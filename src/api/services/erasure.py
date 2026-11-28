"""
Right-to-erasure for one customer across the LangGraph checkpoint saver and the operational DB.

The two stores cannot share one transaction, so the order is fixed and every failure is loud:
  1. The checkpoint saver is purged first. If that fails, nothing has changed; the call fails and can be retried.
  2. The operational tables are then redacted in one DB transaction. If that fails, the saver copy is already gone
     (over-erasure of the subject's own data is the safe direction); the call fails and a retry completes it.
Each failure writes a `customer_erasure_failed` audit row (hashed customer id, stage, error type) and raises
`ErasureIncomplete`; the API maps it to `503 ERASURE_INCOMPLETE`. Erasure is idempotent, so retrying is safe.

Not covered (see docs/memory_policy.md): run transcripts under `runs/<run_id>/` and log lines already shipped
to Loki, which are bounded by their own retention instead.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import logging
import sqlite3
from typing import Any

from src.agent.graph import checkpoint_db_path
from src.config import settings
from src.core.canonical import dumps_json
from src.db.database import DbConn, append_audit_log, get_db, init_db, use_postgres_active, utc_now_iso
from src.memory.store import memory_store

logger = logging.getLogger("auditguard.erasure")


def _db_errors() -> tuple[type[BaseException], ...]:
    errors: list[type[BaseException]] = [sqlite3.Error, OSError]
    try:
        import psycopg

        errors.append(psycopg.Error)
    except ImportError:  # pragma: no cover - psycopg is a core dependency; SQLite-only installs still work
        pass
    return tuple(errors)


_DB_ERRORS = _db_errors()


class ErasureIncomplete(RuntimeError):
    """Raised when one erasure stage failed; `stage` says which store still needs the retry."""

    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(f"erasure incomplete at {stage}: {detail}")
        self.stage = stage


@dataclass(frozen=True)
class _Scope:
    accounts: list[str]
    threads: list[str]
    worksheets: list[str]
    cases: list[str]


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


def _collect_scope(conn: DbConn, customer_id: str) -> _Scope:
    acc_rows = conn.execute("SELECT account_id FROM accounts WHERE customer_id = ?", (customer_id,)).fetchall()
    accounts = [str(r[0]) for r in acc_rows]
    seed_alerts = _select_col(conn, "SELECT alert_id FROM alerts WHERE seed_account_id = ?", accounts)
    net_alerts = _select_col(
        conn, "SELECT alert_id FROM alerts WHERE network_accounts_json LIKE ?", [f'%"{a}"%' for a in accounts]
    )
    alerts = list(dict.fromkeys([*seed_alerts, *net_alerts]))
    return _Scope(
        accounts=accounts,
        threads=_select_col(conn, "SELECT thread_id FROM thread_checkpoints WHERE alert_id = ?", alerts),
        worksheets=_select_col(conn, "SELECT worksheet_id FROM worksheets WHERE alert_id = ?", alerts),
        cases=_select_col(conn, "SELECT case_id FROM cases WHERE alert_id = ?", alerts),
    )


def _redact_operational(
    conn: DbConn, customer_id: str, scope: _Scope, marker: str, redacted_pan: str
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in ("entity_profiles", "case_episodes", "commercial_registry"):
        counts[table] = conn.execute(f"DELETE FROM {table} WHERE customer_id = ?", (customer_id,)).rowcount  # noqa: S608
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
        for acc in scope.accounts
    )
    counts["approval_tokens"] = sum(
        conn.execute("DELETE FROM approval_tokens WHERE worksheet_id = ?", (w,)).rowcount for w in scope.worksheets
    )
    counts["worksheets"] = _update_many(
        conn, "UPDATE worksheets SET content_json = ? WHERE worksheet_id = ?", marker, scope.worksheets
    )
    counts["cases"] = _update_many(conn, "UPDATE cases SET worksheet_json = ? WHERE case_id = ?", marker, scope.cases)
    counts["checkpoints"] = _update_many(
        conn, "UPDATE thread_checkpoints SET state_json = ? WHERE thread_id = ?", marker, scope.threads
    )
    counts["investigation_events"] = _update_many(
        conn, "UPDATE investigation_events SET payload_json = ? WHERE thread_id = ?", marker, scope.threads
    )
    counts["audit_logs"] = _update_many(
        conn, "UPDATE audit_logs SET details_json = ? WHERE thread_id = ?", marker, scope.threads
    ) + _update_many(conn, "UPDATE audit_logs SET details_json = ? WHERE case_id = ?", marker, scope.cases)
    return counts


def _fail(stage: str, exc: BaseException, actor: str, customer_hash: str) -> ErasureIncomplete:
    details = {"customer_id_sha256": customer_hash, "stage": stage, "error_type": type(exc).__name__}
    try:
        append_audit_log(thread_id="memory-forget", event_type="customer_erasure_failed", actor=actor, details=details)
    except _DB_ERRORS:
        logger.exception("could not record erasure failure customer_sha256=%s stage=%s", customer_hash, stage)
    logger.error("erasure incomplete customer_sha256=%s stage=%s error=%s", customer_hash, stage, type(exc).__name__)
    return ErasureIncomplete(stage, type(exc).__name__)


def erase_customer(customer_id: str, actor: str) -> dict[str, Any]:
    """Erase one customer: checkpoint saver first, then one operational transaction (see module docstring)."""
    init_db()
    marker = dumps_json({"redacted": True, "reason": "right_to_erasure", "redacted_at": utc_now_iso()})
    customer_hash = hashlib.sha256(customer_id.encode("utf-8")).hexdigest()[:16]
    with get_db() as conn:
        scope = _collect_scope(conn, customer_id)
    try:
        saver_removed = _purge_langgraph_saver(scope.threads)
    except _DB_ERRORS as exc:
        raise _fail("checkpoint_saver", exc, actor, customer_hash) from exc
    try:
        with get_db() as conn:
            counts = _redact_operational(conn, customer_id, scope, marker, f"REDACTED-{customer_hash}")
    except _DB_ERRORS as exc:
        raise _fail("operational", exc, actor, customer_hash) from exc
    counts["langgraph_saver"] = saver_removed
    mem_profile_removed, mem_episodes_removed = memory_store.evict_customer_cache(customer_id)
    result = {
        "customer_id": customer_id,
        "profile_removed": mem_profile_removed or counts["entity_profiles"] > 0,
        "episodes_removed": max(mem_episodes_removed, counts["case_episodes"]),
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
