"""
Operational-DB hygiene tool: purge held-out leakage and (optionally) reset runtime state.

Usage:
    python scripts/purge_operational_db.py --check                 # read-only scan, exit 1 if leakage
    python scripts/purge_operational_db.py --purge --reset-runtime # delete leakage + runtime pollution

Held-out identifiers (alert IDs, case IDs, transaction IDs, account IDs) are read from
`eval/held_out/*.json`. Every TEXT column of every table is scanned (JSON blobs included).
Reference data (alerts/transactions/accounts/customers/commercial_registry) is only deleted for
identifiers that exist exclusively in the held-out split (never for IDs shared with the dev split).
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "auditguard.db"
HELD_OUT_DIR = ROOT / "eval" / "held_out"
DEV_DIR = ROOT / "data" / "synthetic" / "dev"

RUNTIME_TABLES = ["worksheets", "checkpoints", "cases", "audit_logs", "case_episodes", "entity_profiles"]
REFERENCE_TABLES = ["alerts", "transactions", "accounts", "customers", "commercial_registry"]


def _collect_ids(directory: Path) -> dict[str, set[str]]:
    ids: dict[str, set[str]] = {"alert": set(), "case": set(), "tx": set(), "account": set()}
    for fp in sorted(directory.glob("*.json")):
        case = json.loads(fp.read_text(encoding="utf-8"))
        ids["alert"].add(case["alert_id"])
        if case.get("case_id"):
            ids["case"].add(case["case_id"])
        ids["account"].add(case["root_account"])
        ids["account"].update(case.get("network_accounts", []))
        for tx in case.get("transactions", []):
            ids["tx"].add(tx["tx_id"])
            ids["account"].update([tx["sender_account"], tx["receiver_account"]])
    return ids


def held_out_exclusive_ids() -> dict[str, set[str]]:
    held = _collect_ids(HELD_OUT_DIR)
    dev = _collect_ids(DEV_DIR) if DEV_DIR.exists() else {k: set() for k in held}
    # Showcase alerts also legitimately live in the operational DB.
    dev["alert"].update({"ALT-2026-0412", "ALT-2026-0508"})
    return {k: held[k] - dev[k] for k in held}


def _tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
    return [r[0] for r in rows]


def scan(conn: sqlite3.Connection, needles: set[str]) -> dict[str, list[int]]:
    """Return {table: [rowid,...]} for every row whose any column contains any needle."""
    hits: dict[str, list[int]] = {}
    for table in _tables(conn):
        rows = conn.execute(f'SELECT rowid, * FROM "{table}"').fetchall()  # noqa: S608 (table names from sqlite_master)
        bad: list[int] = []
        for row in rows:
            blob = " ".join(str(v) for v in row[1:] if v is not None)
            if any(n in blob for n in needles):
                bad.append(int(row[0]))
        if bad:
            hits[table] = bad
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(DB_PATH))
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--purge", action="store_true")
    ap.add_argument("--reset-runtime", action="store_true")
    args = ap.parse_args()

    ids = held_out_exclusive_ids()
    needles = ids["alert"] | ids["case"] | ids["tx"] | ids["account"]
    print(
        f"held-out exclusive IDs: alerts={len(ids['alert'])} cases={len(ids['case'])} "
        f"tx={len(ids['tx'])} accounts={len(ids['account'])}"
    )

    uri = f"file:{Path(args.db).as_posix()}" + ("?mode=ro" if args.check and not args.purge else "")
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        before = scan(conn, needles)
        print("BEFORE leakage (rows per table):", {t: len(r) for t, r in before.items()} or "none")

        if args.purge:
            for table, rowids in before.items():
                conn.executemany(f'DELETE FROM "{table}" WHERE rowid = ?', [(r,) for r in rowids])  # noqa: S608
            if args.reset_runtime:
                for table in RUNTIME_TABLES:
                    n = conn.execute(f'DELETE FROM "{table}"').rowcount  # noqa: S608
                    print(f"reset runtime table {table}: deleted {n}")
                conn.execute("UPDATE alerts SET status = 'OPEN'")
            conn.commit()
            conn.execute("VACUUM")

        after: dict[str, list[int]] = scan(conn, needles)
        print("AFTER leakage (rows per table):", {t: len(r) for t, r in after.items()} or "none")
        counts: dict[str, Any] = {t: conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in _tables(conn)}  # noqa: S608
        print("table row counts:", counts)
        return 1 if after else 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
