"""
AuditGuard Relational Persistence Layer (Dual Backend: SQLite Local Default + PostgreSQL via `psycopg`).

Provides privilege-separated connections:
  - `get_ro_db()`     : read-only (`?mode=ro` + `PRAGMA query_only` in SQLite; `READ ONLY` + `statement_timeout` in PG)
  - `get_scoped_db()` : table-scoped writer (`set_authorizer` in SQLite; write-target guard in PG)
  - `get_db()`        : general transactional connection for startup/checkpoints/admin flags
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Optional, Union

from src.config import settings
from src.core.canonical import dumps_json
from src.db.postgres_backend import PostgresCompatConnection, postgres_ddl
from src.db.seeder import seed_from_directories, upsert_case_into_db

DbConn = Union[sqlite3.Connection, PostgresCompatConnection]
AuditObserver = Callable[[dict[str, Any]], None]

_DB_LOCK = threading.RLock()
_DEFAULT_SQLITE_PATH = Path(__file__).resolve().parents[2] / "data" / "auditguard.db"
SCHEMA_VERSION = 3
_REFERENCE_TABLES_DROP_ORDER = ("transactions", "alerts", "accounts", "commercial_registry", "customers")
_initialized_targets: set[str] = set()
_AUDIT_OBSERVERS: list[AuditObserver] = []


def register_audit_observer(observer: AuditObserver) -> None:
    if observer not in _AUDIT_OBSERVERS:
        _AUDIT_OBSERVERS.append(observer)

SQLITE_DDL = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS banks (bank_id TEXT PRIMARY KEY, bank_name TEXT NOT NULL, ifsc_prefix TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY, full_name TEXT NOT NULL, synthetic_pan_hash TEXT UNIQUE NOT NULL,
    kyc_tier TEXT CHECK (kyc_tier IN ('FULL', 'MINIMAL', 'EXPIRED')), occupation TEXT NOT NULL,
    declared_annual_income_inr TEXT NOT NULL, risk_rating TEXT CHECK (risk_rating IN ('LOW', 'MEDIUM', 'HIGH')),
    onboarding_date TEXT NOT NULL, kyc_notes TEXT
);
CREATE TABLE IF NOT EXISTS commercial_registry (
    registry_id TEXT PRIMARY KEY, customer_id TEXT REFERENCES customers(customer_id),
    entity_type TEXT CHECK (entity_type IN ('MARKETPLACE', 'EMPLOYER', 'NGO_80G', 'CHIT_FUND', 'MERCHANT')),
    registration_number TEXT UNIQUE NOT NULL, status TEXT CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    registered_since TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY, bank_id TEXT REFERENCES banks(bank_id),
    customer_id TEXT REFERENCES customers(customer_id),
    account_type TEXT CHECK (account_type IN ('SAVINGS', 'CURRENT', 'ESCROW', 'SALARY')),
    status TEXT CHECK (status IN ('ACTIVE', 'DORMANT', 'FROZEN')), opened_date TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions (
    txn_id TEXT PRIMARY KEY, from_account_id TEXT REFERENCES accounts(account_id),
    to_account_id TEXT REFERENCES accounts(account_id), amount_inr TEXT NOT NULL,
    txn_timestamp TEXT NOT NULL, channel TEXT CHECK (channel IN ('IMPS', 'NEFT', 'RTGS', 'UPI')), memo_text TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY, seed_account_id TEXT REFERENCES accounts(account_id),
    triggered_at TEXT NOT NULL, rule_triggered TEXT NOT NULL, initial_amount_inr TEXT NOT NULL,
    network_accounts_json TEXT NOT NULL DEFAULT '[]', status TEXT DEFAULT 'OPEN'
);
CREATE TABLE IF NOT EXISTS worksheets (
    worksheet_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, content_json TEXT NOT NULL, payload_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_review', reviewer_id TEXT, reviewer_decision TEXT, reviewer_notes TEXT,
    thread_id TEXT, revision INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY, alert_id TEXT UNIQUE NOT NULL, worksheet_id TEXT NOT NULL,
    disposition TEXT CHECK (disposition IN (
        'ESCALATE_STR_REVIEW', 'CLOSE_BENIGN', 'INSUFFICIENT_DATA', 'REJECTED',
        'escalate_str', 'close_benign', 'request_info', 'rejected'
    )),
    worksheet_json TEXT NOT NULL, payload_hash TEXT NOT NULL, approver_id TEXT NOT NULL, committed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('analyst', 'senior_reviewer', 'admin')), created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY, revoked_by TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS investigation_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT, thread_id TEXT NOT NULL,
    event TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approval_tokens (
    token_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, worksheet_id TEXT NOT NULL,
    worksheet_sha256 TEXT NOT NULL, hmac_token TEXT NOT NULL, issued_at TEXT NOT NULL,
    consumed_at TEXT, consumed_by TEXT
);
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, thread_id TEXT NOT NULL,
    event_type TEXT NOT NULL, actor TEXT NOT NULL, payload_hash TEXT,
    details_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS thread_checkpoints (
    thread_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, mode TEXT NOT NULL, current_node TEXT NOT NULL,
    status TEXT NOT NULL, worksheet_id TEXT, payload_hash TEXT,
    state_json TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entity_profiles (
    customer_id TEXT PRIMARY KEY, profile_json TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_episodes (
    episode_id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id TEXT NOT NULL,
    episode_json TEXT NOT NULL, archived_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reflexion_playbook (
    lesson_id TEXT PRIMARY KEY, trigger_precondition TEXT NOT NULL, observed_failure TEXT NOT NULL,
    actionable_rule TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    reviewer_rationale TEXT DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS system_flags (flag_key TEXT PRIMARY KEY, flag_value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_txn_from ON transactions(from_account_id, txn_timestamp);
CREATE INDEX IF NOT EXISTS idx_txn_to ON transactions(to_account_id, txn_timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_thread ON audit_logs(thread_id);
CREATE INDEX IF NOT EXISTS idx_episodes_cust ON case_episodes(customer_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_worksheet_thread_revision
    ON worksheets(thread_id, revision) WHERE thread_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_approval_worksheet ON approval_tokens(worksheet_id);
CREATE INDEX IF NOT EXISTS idx_events_thread ON investigation_events(thread_id, event_id);
"""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def use_postgres_active() -> bool:
    env_val = os.getenv("USE_POSTGRES")
    if env_val is not None:
        return env_val.strip().lower() in ("1", "true", "yes", "on")
    return bool(settings.use_postgres)


def get_sqlite_path() -> Path:
    custom = os.getenv("SQLITE_DB_PATH")
    path = Path(custom) if custom else _DEFAULT_SQLITE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def reset_db_init() -> None:
    """Public reset hook for isolated test fixtures and evaluation harnesses."""
    _initialized_targets.clear()


@contextmanager
def get_db() -> Iterator[DbConn]:
    if use_postgres_active():
        pg = PostgresCompatConnection(settings.sync_database_url, timeout_s=15.0)
        try:
            yield pg
            pg.commit()
        except Exception:
            pg.rollback()
            raise
        finally:
            pg.close()
        return
    with _DB_LOCK:
        conn = sqlite3.connect(str(get_sqlite_path()), timeout=15.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _migrate_sqlite(conn: sqlite3.Connection) -> None:
    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if version >= SCHEMA_VERSION:
        return
    existing = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if version < 2 and "alerts" in existing:
        for table in _REFERENCE_TABLES_DROP_ORDER:
            conn.execute(f"DROP TABLE IF EXISTS {table}")  # noqa: S608
    if "checkpoints" in existing and "thread_checkpoints" not in existing:
        conn.execute("ALTER TABLE checkpoints RENAME TO thread_checkpoints")
    if "worksheets" in existing:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(worksheets)").fetchall()}
        if "thread_id" not in cols:
            conn.execute("ALTER TABLE worksheets ADD COLUMN thread_id TEXT")
        if "revision" not in cols:
            conn.execute("ALTER TABLE worksheets ADD COLUMN revision INTEGER NOT NULL DEFAULT 1")


def _seed_banks(conn: DbConn) -> None:
    banks = [
        ("BNK-HDFC", "HDFC Bank Synthetic", "HDFC0"),
        ("BNK-ICIC", "ICICI Bank Synthetic", "ICIC0"),
        ("BNK-SBIN", "State Bank Synthetic", "SBIN0"),
        ("BNK-AXIS", "Axis Bank Synthetic", "UTIB0"),
    ]
    conn.executemany("INSERT OR IGNORE INTO banks (bank_id, bank_name, ifsc_prefix) VALUES (?, ?, ?)", banks)


def init_db(force: bool = False) -> Path:
    if use_postgres_active():
        key = f"postgres://{settings.postgres_host}:{settings.postgres_port}/{settings.postgres_db}"
        if key not in _initialized_targets or force:
            with get_db() as conn:
                conn.executescript(postgres_ddl())
                _seed_banks(conn)
            _initialized_targets.add(key)
        return Path(settings.postgres_db)

    db_path = get_sqlite_path()
    key = str(db_path.resolve())
    if key in _initialized_targets and not force:
        return db_path
    with get_db() as conn:
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("expected sqlite3.Connection when USE_POSTGRES is disabled")
        _migrate_sqlite(conn)
        conn.executescript(SQLITE_DDL)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.execute("PRAGMA journal_mode = WAL")
        _seed_banks(conn)
    _initialized_targets.add(key)
    return db_path


def seed_operational_db(dev_dir: Optional[Path] = None) -> int:
    init_db()
    with get_db() as conn:
        return seed_from_directories(conn, dev_dir=dev_dir)


def ensure_dev_alerts_seeded() -> int:
    """Seed dev + showcase fixtures if the operational `alerts` table is empty."""
    init_db()
    with get_ro_db() as conn:
        row = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
        existing = int(row[0]) if row else 0
    return seed_operational_db() if existing == 0 else 0


@contextmanager
def get_ro_db(timeout_s: float = 5.0) -> Iterator[DbConn]:
    init_db()
    if use_postgres_active():
        pg = PostgresCompatConnection(settings.sync_database_url, read_only=True, timeout_s=timeout_s)
        try:
            yield pg
        finally:
            pg.close()
        return
    uri = get_sqlite_path().resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=timeout_s)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    deadline = time.monotonic() + timeout_s
    conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
    try:
        yield conn
    finally:
        conn.close()


_WRITE_ACTIONS = {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}
_DDL_ACTIONS = {
    getattr(sqlite3, name)
    for name in dir(sqlite3)
    if name.startswith(("SQLITE_CREATE_", "SQLITE_DROP_", "SQLITE_ALTER_"))
}


@contextmanager
def get_scoped_db(allowed_write_tables: Iterable[str]) -> Iterator[DbConn]:
    init_db()
    allowed = frozenset(allowed_write_tables)
    if use_postgres_active():
        pg = PostgresCompatConnection(settings.sync_database_url, allowed_write_tables=allowed, timeout_s=15.0)
        try:
            yield pg
            pg.commit()
        except Exception:
            pg.rollback()
            raise
        finally:
            pg.close()
        return

    def authorizer(
        action: int, arg1: Optional[str], _arg2: Optional[str], _db: Optional[str], _src: Optional[str]
    ) -> int:
        if action in _WRITE_ACTIONS and arg1 not in allowed:
            return sqlite3.SQLITE_DENY
        if action in _DDL_ACTIONS or action == sqlite3.SQLITE_ATTACH:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    with _DB_LOCK:
        conn = sqlite3.connect(str(get_sqlite_path()), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.set_authorizer(authorizer)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def save_checkpoint(
    thread_id: str,
    alert_id: str,
    mode: str,
    current_node: str,
    status: str,
    state_dict: dict[str, Any],
    worksheet_id: Optional[str] = None,
    payload_hash: Optional[str] = None,
) -> None:
    init_db()
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO thread_checkpoints "
            "(thread_id, alert_id, mode, current_node, status, worksheet_id, payload_hash, state_json, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                thread_id,
                alert_id,
                mode,
                current_node,
                status,
                worksheet_id,
                payload_hash,
                dumps_json(state_dict),
                utc_now_iso(),
            ),
        )


def load_checkpoint(thread_id: str) -> Optional[dict[str, Any]]:
    init_db()
    with get_ro_db() as conn:
        row = conn.execute("SELECT * FROM thread_checkpoints WHERE thread_id = ?", (thread_id,)).fetchone()
    if not row:
        return None
    return {
        "thread_id": row["thread_id"],
        "alert_id": row["alert_id"],
        "mode": row["mode"],
        "current_node": row["current_node"],
        "status": row["status"],
        "worksheet_id": row["worksheet_id"],
        "payload_hash": row["payload_hash"],
        "state": json.loads(row["state_json"]),
        "updated_at": row["updated_at"],
    }


def list_checkpoints(limit: int = 50) -> list[dict[str, Any]]:
    init_db()
    with get_ro_db() as conn:
        rows = conn.execute(
            "SELECT thread_id, alert_id, mode, current_node, status, worksheet_id, payload_hash, updated_at "
            "FROM thread_checkpoints ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def append_audit_log(
    thread_id: str,
    event_type: str,
    actor: str,
    details: dict[str, Any],
    case_id: Optional[str] = None,
    payload_hash: Optional[str] = None,
) -> int:
    init_db()
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO audit_logs (case_id, thread_id, event_type, actor, payload_hash, details_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (case_id, thread_id, event_type, actor, payload_hash, dumps_json(details), utc_now_iso()),
        )
        log_id = int(cur.lastrowid or 0)

    event_record = {
        "log_id": log_id,
        "thread_id": thread_id,
        "event_type": event_type,
        "actor": actor,
        "case_id": case_id,
        "payload_hash": payload_hash,
        "details": details,
    }
    for observer in _AUDIT_OBSERVERS:
        observer(event_record)
    return log_id


def list_audit_logs(thread_id: Optional[str] = None, limit: int = 50) -> list[dict[str, Any]]:
    init_db()
    with get_ro_db() as conn:
        if thread_id:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE thread_id = ? ORDER BY log_id DESC LIMIT ?",
                (thread_id, limit),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY log_id DESC LIMIT ?", (limit,)).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d.pop("details_json", "{}"))
        out.append(d)
    return out


def append_event(thread_id: str, event: str, payload: dict[str, Any]) -> int:
    init_db()
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO investigation_events (thread_id, event, payload_json, created_at) VALUES (?, ?, ?, ?)",
            (thread_id, event, dumps_json(payload), utc_now_iso()),
        )
        return int(cur.lastrowid or 0)


def read_events(thread_id: str, after_id: int = 0) -> list[dict[str, Any]]:
    init_db()
    with get_ro_db() as conn:
        rows = conn.execute(
            "SELECT event_id, event, payload_json, created_at FROM investigation_events "
            "WHERE thread_id = ? AND event_id > ? ORDER BY event_id ASC LIMIT 200",
            (thread_id, after_id),
        ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        data = json.loads(r["payload_json"])
        out.append(
            {
                **(data if isinstance(data, dict) else {"value": data}),
                "event_id": int(r["event_id"]),
                "event": str(r["event"]),
                "created_at": str(r["created_at"]),
            }
        )
    return out


__all__ = [
    "DbConn",
    "SCHEMA_VERSION",
    "SQLITE_DDL",
    "append_audit_log",
    "append_event",
    "get_db",
    "get_ro_db",
    "get_scoped_db",
    "get_sqlite_path",
    "init_db",
    "list_audit_logs",
    "list_checkpoints",
    "load_checkpoint",
    "read_events",
    "reset_db_init",
    "save_checkpoint",
    "seed_operational_db",
    "upsert_case_into_db",
    "use_postgres_active",
    "utc_now_iso",
]
