"""
AuditGuard Relational Persistence Layer (SQLite Local Default / PostgreSQL Ready)

Implements the canonical schema from Blueprint Section 6.2 plus durable
LangGraph state checkpoints (FR-6) and long-term memory tables (Section 11.1):
  - banks, customers, commercial_registry, accounts, transactions, alerts
  - worksheets, cases, audit_logs
  - checkpoints (durable mid-run crash/resume per thread_id)
  - entity_profiles, case_episodes, reflexion_playbook

Zero external daemon required for local execution (defaults to `data/auditguard.db` via sqlite3),
while supporting PostgreSQL (`psycopg`) when `USE_POSTGRES=true` in Docker/production.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterator, Optional

from src.core.canonical import loads_json, to_money

_DB_LOCK = threading.RLock()
_DEFAULT_SQLITE_PATH = Path(__file__).resolve().parents[2] / "data" / "auditguard.db"
SCHEMA_VERSION = 2
_REFERENCE_TABLES_DROP_ORDER = ("transactions", "alerts", "accounts", "commercial_registry", "customers")
DEFAULT_SEED_INCOME = Decimal("500000.00")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _m(value: Any) -> Decimal:
    """Exact money from seed fixtures (JSON is loaded with Decimal; python literals are repr-exact)."""
    return to_money(str(value) if isinstance(value, float) else value)


def get_sqlite_path() -> Path:
    custom = os.getenv("SQLITE_DB_PATH")
    path = Path(custom) if custom else _DEFAULT_SQLITE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


SQLITE_DDL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS banks (
    bank_id TEXT PRIMARY KEY,
    bank_name TEXT NOT NULL,
    ifsc_prefix TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY,
    full_name TEXT NOT NULL,
    synthetic_pan_hash TEXT UNIQUE NOT NULL,
    kyc_tier TEXT CHECK (kyc_tier IN ('FULL', 'MINIMAL', 'EXPIRED')),
    occupation TEXT NOT NULL,
    declared_annual_income_inr TEXT NOT NULL,
    risk_rating TEXT CHECK (risk_rating IN ('LOW', 'MEDIUM', 'HIGH')),
    onboarding_date TEXT NOT NULL,
    kyc_notes TEXT
);

CREATE TABLE IF NOT EXISTS commercial_registry (
    registry_id TEXT PRIMARY KEY,
    customer_id TEXT REFERENCES customers(customer_id),
    entity_type TEXT CHECK (entity_type IN ('MARKETPLACE', 'EMPLOYER', 'NGO_80G', 'CHIT_FUND', 'MERCHANT')),
    registration_number TEXT UNIQUE NOT NULL,
    status TEXT CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    registered_since TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    bank_id TEXT REFERENCES banks(bank_id),
    customer_id TEXT REFERENCES customers(customer_id),
    account_type TEXT CHECK (account_type IN ('SAVINGS', 'CURRENT', 'ESCROW', 'SALARY')),
    status TEXT CHECK (status IN ('ACTIVE', 'DORMANT', 'FROZEN')),
    opened_date TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    txn_id TEXT PRIMARY KEY,
    from_account_id TEXT REFERENCES accounts(account_id),
    to_account_id TEXT REFERENCES accounts(account_id),
    amount_inr TEXT NOT NULL,
    txn_timestamp TEXT NOT NULL,
    channel TEXT CHECK (channel IN ('IMPS', 'NEFT', 'RTGS', 'UPI')),
    memo_text TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    seed_account_id TEXT REFERENCES accounts(account_id),
    triggered_at TEXT NOT NULL,
    rule_triggered TEXT NOT NULL,
    initial_amount_inr TEXT NOT NULL,
    network_accounts_json TEXT NOT NULL DEFAULT '[]',
    status TEXT DEFAULT 'OPEN'
);

CREATE TABLE IF NOT EXISTS worksheets (
    worksheet_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    content_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_review',
    reviewer_id TEXT,
    reviewer_decision TEXT,
    reviewer_notes TEXT,
    thread_id TEXT,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    alert_id TEXT UNIQUE NOT NULL,
    worksheet_id TEXT NOT NULL,
    disposition TEXT CHECK (disposition IN ('ESCALATE_STR_REVIEW', 'CLOSE_BENIGN', 'INSUFFICIENT_DATA', 'REJECTED', 'escalate_str', 'close_benign', 'request_info', 'rejected')),
    worksheet_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    committed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_tokens (
    token_id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    worksheet_id TEXT NOT NULL,
    worksheet_sha256 TEXT NOT NULL,
    hmac_token TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    consumed_at TEXT,
    consumed_by TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    thread_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload_hash TEXT,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    thread_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    current_node TEXT NOT NULL,
    status TEXT NOT NULL,
    worksheet_id TEXT,
    payload_hash TEXT,
    state_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entity_profiles (
    customer_id TEXT PRIMARY KEY,
    profile_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_episodes (
    episode_id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id TEXT NOT NULL,
    episode_json TEXT NOT NULL,
    archived_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reflexion_playbook (
    lesson_id TEXT PRIMARY KEY,
    trigger_precondition TEXT NOT NULL,
    observed_failure TEXT NOT NULL,
    actionable_rule TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    reviewer_rationale TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_flags (
    flag_key TEXT PRIMARY KEY,
    flag_value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_txn_from ON transactions(from_account_id, txn_timestamp);
CREATE INDEX IF NOT EXISTS idx_txn_to ON transactions(to_account_id, txn_timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_thread ON audit_logs(thread_id);
CREATE INDEX IF NOT EXISTS idx_episodes_cust ON case_episodes(customer_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_worksheet_thread_revision ON worksheets(thread_id, revision) WHERE thread_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_approval_worksheet ON approval_tokens(worksheet_id);
"""


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    """Thread-safe SQLite connection context manager with Row factory."""
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


_initialized_paths: set[str] = set()


def _migrate(conn: sqlite3.Connection) -> None:
    """Schema v2: money columns are exact TEXT; worksheets gain (thread_id, revision); approval_tokens added."""
    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if version >= SCHEMA_VERSION:
        return
    existing = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "alerts" in existing:  # legacy NUMERIC money columns -> reference data is re-seeded from fixtures
        for table in _REFERENCE_TABLES_DROP_ORDER:
            conn.execute(f"DROP TABLE IF EXISTS {table}")  # noqa: S608 - fixed internal table names
    if "worksheets" in existing:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(worksheets)").fetchall()}
        if "thread_id" not in cols:
            conn.execute("ALTER TABLE worksheets ADD COLUMN thread_id TEXT")
        if "revision" not in cols:
            conn.execute("ALTER TABLE worksheets ADD COLUMN revision INTEGER NOT NULL DEFAULT 1")


def init_db(force: bool = False) -> Path:
    """Create canonical tables if they do not exist (and migrate legacy schemas)."""
    db_path = get_sqlite_path()
    key = str(db_path.resolve())
    if key in _initialized_paths and not force:
        return db_path

    with get_db() as conn:
        _migrate(conn)
        conn.executescript(SQLITE_DDL)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        # Seed simulated Indian banks
        banks = [
            ("BNK-HDFC", "HDFC Bank Synthetic", "HDFC0"),
            ("BNK-ICIC", "ICICI Bank Synthetic", "ICIC0"),
            ("BNK-SBIN", "State Bank Synthetic", "SBIN0"),
            ("BNK-AXIS", "Axis Bank Synthetic", "UTIB0"),
        ]
        conn.executemany(
            "INSERT OR IGNORE INTO banks (bank_id, bank_name, ifsc_prefix) VALUES (?, ?, ?)",
            banks,
        )
    _initialized_paths.add(key)
    return db_path


def _upsert_case_into_db(conn: sqlite3.Connection, case: dict[str, Any]) -> None:
    """Insert a synthetic case's accounts, customers, registry, transactions, and alert."""
    root_acc = case["root_account"]
    net_accs = case.get("network_accounts", [])
    txs = case.get("transactions", [])
    kyc_map = case.get("kyc_profiles", {})

    # Collect every referenced account across root, network, and transactions
    all_accounts: list[str] = []
    for acc in [root_acc, *net_accs, *[t["sender_account"] for t in txs], *[t["receiver_account"] for t in txs]]:
        if acc and acc not in all_accounts:
            all_accounts.append(acc)

    banks = ["BNK-HDFC", "BNK-ICIC", "BNK-SBIN", "BNK-AXIS"]

    for idx, acc_id in enumerate(all_accounts):
        kyc = kyc_map.get(acc_id, {})
        cust_id = kyc.get("customer_id") or f"CUST-{acc_id}"
        pan_raw = kyc.get("pan") or f"SYNTH-{acc_id}"
        pan_hash = hashlib.sha256(pan_raw.encode()).hexdigest()
        risk = str(kyc.get("risk_category", "MEDIUM")).upper()
        if risk not in ("LOW", "MEDIUM", "HIGH"):
            risk = "MEDIUM"
        income = str(_m(kyc.get("declared_annual_income_inr", DEFAULT_SEED_INCOME)))
        entity_type_raw = str(kyc.get("entity_type", "individual")).lower()
        occupation = kyc.get("occupation") or entity_type_raw
        notes = kyc.get("kyc_notes", "")

        conn.execute(
            """
            INSERT OR REPLACE INTO customers
            (customer_id, full_name, synthetic_pan_hash, kyc_tier, occupation,
             declared_annual_income_inr, risk_rating, onboarding_date, kyc_notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cust_id,
                kyc.get("entity_name", f"Entity-{acc_id[-6:]}"),
                pan_hash,
                kyc.get("kyc_tier", "FULL"),
                occupation,
                income,
                risk,
                "2023-06-15",
                notes,
            ),
        )

        acc_type = "CURRENT" if entity_type_raw in ("company", "trust", "ngo") else "SAVINGS"
        conn.execute(
            """
            INSERT OR REPLACE INTO accounts
            (account_id, bank_id, customer_id, account_type, status, opened_date)
            VALUES (?, ?, ?, ?, 'ACTIVE', '2023-06-15')
            """,
            (acc_id, banks[idx % len(banks)], cust_id, acc_type),
        )

        if kyc.get("is_commercially_registered"):
            reg_type = str(kyc.get("registry_type") or "MERCHANT").upper()
            if reg_type == "GST":
                reg_type = "MARKETPLACE" if "marketplace" in str(case.get("category", "")) else "MERCHANT"
            if reg_type not in ("MARKETPLACE", "EMPLOYER", "NGO_80G", "CHIT_FUND", "MERCHANT"):
                reg_type = "MERCHANT"
            conn.execute(
                """
                INSERT OR REPLACE INTO commercial_registry
                (registry_id, customer_id, entity_type, registration_number, status, registered_since)
                VALUES (?, ?, ?, ?, 'ACTIVE', '2022-04-01')
                """,
                (
                    f"REG-{acc_id}",
                    cust_id,
                    reg_type,
                    f"SYNTH-REG-{acc_id}",
                ),
            )

    for tx in txs:
        ch = str(tx.get("channel", "NEFT")).upper()
        if ch not in ("IMPS", "NEFT", "RTGS", "UPI"):
            ch = "NEFT"
        conn.execute(
            """
            INSERT OR REPLACE INTO transactions
            (txn_id, from_account_id, to_account_id, amount_inr, txn_timestamp, channel, memo_text)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tx["tx_id"],
                tx["sender_account"],
                tx["receiver_account"],
                str(_m(tx["amount_inr"])),
                tx["timestamp"],
                ch,
                tx.get("memo") or "",
            ),
        )

    conn.execute(
        """
        INSERT OR REPLACE INTO alerts
        (alert_id, seed_account_id, triggered_at, rule_triggered, initial_amount_inr, network_accounts_json, status)
        VALUES (?, ?, ?, ?, ?, ?, 'OPEN')
        """,
        (
            case["alert_id"],
            root_acc,
            case["triggered_at"],
            case.get("rule_name", "SCATTER_GATHER"),
            str(_m(case["total_amount_inr"])),
            json.dumps(net_accs),
        ),
    )


def seed_operational_db(dev_dir: Optional[Path] = None) -> int:
    """
    Seed the operational database strictly from `data/synthetic/dev/` plus
    the two Blueprint walkthrough showcase alerts (`ALT-2026-0412` & `ALT-2026-0508`).
    NEVER reads `eval/held_out/` (enforcing Non-Negotiable Rule #4: Held-Out Isolation).
    """
    init_db()
    root_dir = Path(__file__).resolve().parents[2]
    target_dev = dev_dir or (root_dir / "data" / "synthetic" / "dev")

    count = 0
    with get_db() as conn:
        if target_dev.exists():
            for fp in sorted(target_dev.glob("*.json")):
                case = loads_json(fp.read_text(encoding="utf-8"))
                if case.get("is_held_out"):
                    continue
                _upsert_case_into_db(conn, case)
                count += 1

        # Blueprint Walkthrough 1: ALT-2026-0412 (Staggered Day-11 Fee-Skimming Scatter-Gather)
        wt1 = {
            "alert_id": "ALT-2026-0412",
            "rule_name": "SCATTER_GATHER_900K",
            "root_account": "ACC-IND-1042",
            "network_accounts": ["ACC-IND-2011", "ACC-IND-2044", "ACC-IND-2089", "ACC-IND-9001"],
            "total_amount_inr": 900000.00,
            "triggered_at": "2026-09-10T10:00:00Z",
            "kyc_profiles": {
                "ACC-IND-1042": {
                    "account_id": "ACC-IND-1042",
                    "entity_name": "R. Verma Trading",
                    "entity_type": "individual",
                    "risk_category": "HIGH",
                    "declared_annual_income_inr": 450000.00,
                    "is_commercially_registered": False,
                    "kyc_notes": "Declared retail clerk; sudden high-value outward transfers",
                },
                "ACC-IND-2011": {"account_id": "ACC-IND-2011", "entity_type": "individual", "risk_category": "MEDIUM", "declared_annual_income_inr": 300000.00, "is_commercially_registered": False},
                "ACC-IND-2044": {"account_id": "ACC-IND-2044", "entity_type": "individual", "risk_category": "MEDIUM", "declared_annual_income_inr": 320000.00, "is_commercially_registered": False},
                "ACC-IND-2089": {"account_id": "ACC-IND-2089", "entity_type": "individual", "risk_category": "MEDIUM", "declared_annual_income_inr": 280000.00, "is_commercially_registered": False},
                "ACC-IND-9001": {"account_id": "ACC-IND-9001", "entity_type": "individual", "risk_category": "HIGH", "declared_annual_income_inr": 500000.00, "is_commercially_registered": False},
            },
            "transactions": [
                {"tx_id": "TXN-8801", "sender_account": "ACC-IND-1042", "receiver_account": "ACC-IND-2011", "amount_inr": 300000.00, "timestamp": "2026-09-10T09:00:00Z", "channel": "NEFT", "memo": "Transfer"},
                {"tx_id": "TXN-8802", "sender_account": "ACC-IND-1042", "receiver_account": "ACC-IND-2044", "amount_inr": 300000.00, "timestamp": "2026-09-10T09:15:00Z", "channel": "NEFT", "memo": "Transfer"},
                {"tx_id": "TXN-8803", "sender_account": "ACC-IND-1042", "receiver_account": "ACC-IND-2089", "amount_inr": 300000.00, "timestamp": "2026-09-10T09:30:00Z", "channel": "IMPS", "memo": "Transfer"},
                {"tx_id": "TXN-8891", "sender_account": "ACC-IND-2011", "receiver_account": "ACC-IND-9001", "amount_inr": 276000.00, "timestamp": "2026-09-21T14:00:00Z", "channel": "RTGS", "memo": "Settlement"},
                {"tx_id": "TXN-8892", "sender_account": "ACC-IND-2044", "receiver_account": "ACC-IND-9001", "amount_inr": 276000.00, "timestamp": "2026-09-21T14:20:00Z", "channel": "RTGS", "memo": "Settlement"},
                {"tx_id": "TXN-8893", "sender_account": "ACC-IND-2089", "receiver_account": "ACC-IND-9001", "amount_inr": 276000.00, "timestamp": "2026-09-21T14:45:00Z", "channel": "RTGS", "memo": "Settlement"},
            ],
        }
        _upsert_case_into_db(conn, wt1)

        # Blueprint Walkthrough 2: ALT-2026-0508 (Benign GST Marketplace Payout)
        wt2 = {
            "alert_id": "ALT-2026-0508",
            "rule_name": "SCATTER_GATHER_1250K",
            "root_account": "ACC-MKT-5081",
            "network_accounts": ["ACC-SEL-5082", "ACC-SEL-5083", "ACC-SEL-5084", "ACC-LOG-5090"],
            "total_amount_inr": 1250000.00,
            "triggered_at": "2026-09-15T11:00:00Z",
            "category": "marketplace_payout",
            "kyc_profiles": {
                "ACC-MKT-5081": {
                    "account_id": "ACC-MKT-5081",
                    "entity_name": "CraftBazaar India Marketplace Pvt Ltd",
                    "entity_type": "company",
                    "risk_category": "LOW",
                    "declared_annual_income_inr": 45000000.00,
                    "is_commercially_registered": True,
                    "registry_type": "MARKETPLACE",
                    "kyc_notes": "Active GST-registered handicraft marketplace; 18 months weekly artisan payouts",
                },
                "ACC-SEL-5082": {"account_id": "ACC-SEL-5082", "entity_name": "Jaipur Looms", "entity_type": "company", "risk_category": "LOW", "declared_annual_income_inr": 4800000.00, "is_commercially_registered": True, "registry_type": "MERCHANT"},
                "ACC-SEL-5083": {"account_id": "ACC-SEL-5083", "entity_name": "Kutch Artisans", "entity_type": "company", "risk_category": "LOW", "declared_annual_income_inr": 3600000.00, "is_commercially_registered": True, "registry_type": "MERCHANT"},
                "ACC-SEL-5084": {"account_id": "ACC-SEL-5084", "entity_name": "Bastar Crafts", "entity_type": "company", "risk_category": "LOW", "declared_annual_income_inr": 3100000.00, "is_commercially_registered": True, "registry_type": "MERCHANT"},
                "ACC-LOG-5090": {"account_id": "ACC-LOG-5090", "entity_name": "SwiftShip Courier Escrow", "entity_type": "company", "risk_category": "LOW", "declared_annual_income_inr": 90000000.00, "is_commercially_registered": True, "registry_type": "MERCHANT"},
            },
            "transactions": [
                {"tx_id": "TXN-9501", "sender_account": "ACC-MKT-5081", "receiver_account": "ACC-SEL-5082", "amount_inr": 400000.00, "timestamp": "2026-09-15T10:00:00Z", "channel": "NEFT", "memo": "Weekly marketplace seller payout"},
                {"tx_id": "TXN-9502", "sender_account": "ACC-MKT-5081", "receiver_account": "ACC-SEL-5083", "amount_inr": 425000.00, "timestamp": "2026-09-15T10:05:00Z", "channel": "NEFT", "memo": "Weekly marketplace seller payout"},
                {"tx_id": "TXN-9503", "sender_account": "ACC-MKT-5081", "receiver_account": "ACC-SEL-5084", "amount_inr": 425000.00, "timestamp": "2026-09-15T10:10:00Z", "channel": "NEFT", "memo": "Weekly marketplace seller payout"},
                {"tx_id": "TXN-9504", "sender_account": "ACC-SEL-5082", "receiver_account": "ACC-LOG-5090", "amount_inr": 35000.00, "timestamp": "2026-09-16T12:00:00Z", "channel": "UPI", "memo": "Courier logistics settlement"},
            ],
        }
        _upsert_case_into_db(conn, wt2)
        count += 2

    return count


# ---------------------------------------------------------------------------
# Durable Checkpoint Persistence (FR-6: Mid-Run Crash / Resume)
# ---------------------------------------------------------------------------
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
            """
            INSERT OR REPLACE INTO checkpoints
            (thread_id, alert_id, mode, current_node, status, worksheet_id, payload_hash, state_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                thread_id,
                alert_id,
                mode,
                current_node,
                status,
                worksheet_id,
                payload_hash,
                json.dumps(state_dict, default=str),
                utc_now_iso(),
            ),
        )


def load_checkpoint(thread_id: str) -> Optional[dict[str, Any]]:
    init_db()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM checkpoints WHERE thread_id = ?", (thread_id,)).fetchone()
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
    with get_db() as conn:
        rows = conn.execute(
            "SELECT thread_id, alert_id, mode, current_node, status, worksheet_id, payload_hash, updated_at "
            "FROM checkpoints ORDER BY updated_at DESC LIMIT ?",
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
            """
            INSERT INTO audit_logs (case_id, thread_id, event_type, actor, payload_hash, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (case_id, thread_id, event_type, actor, payload_hash, json.dumps(details, default=str), utc_now_iso()),
        )
        log_id = int(cur.lastrowid or 0)

    from src.observability.loki_shipper import emit_loki_log

    emit_loki_log(
        stream_type="audit_trail",
        event=event_type,
        message=f"[AUDIT #{log_id}] {event_type} by {actor} (thread={thread_id})",
        level="INFO",
        extra={
            "log_id": log_id,
            "thread_id": thread_id,
            "actor": actor,
            "case_id": case_id,
            "payload_hash": payload_hash,
            "details": details,
        },
    )
    return log_id


def list_audit_logs(thread_id: Optional[str] = None, limit: int = 50) -> list[dict[str, Any]]:
    init_db()
    with get_db() as conn:
        if thread_id:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE thread_id = ? ORDER BY log_id DESC LIMIT ?",
                (thread_id, limit),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY log_id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d.pop("details_json", "{}"))
            out.append(d)
        return out
