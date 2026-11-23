"""
PostgreSQL (`psycopg`) compatibility backend mirroring the `sqlite3` Row/Cursor/Connection contract.

Enables 100% shared relational state across Docker/multi-process deployments when `USE_POSTGRES=true`
without duplicating repository SQL:
  - Positional `?` placeholders outside single-quoted literals translate cleanly to `%s`.
  - `INSERT OR IGNORE` / `INSERT OR REPLACE` translate to deterministic `ON CONFLICT (<pk>)` clauses.
  - `INSERT INTO audit_logs | investigation_events | case_episodes` return generated serial IDs (`lastrowid`).
  - Read-only connections enforce `SET TRANSACTION READ ONLY` + `statement_timeout`; scoped connections
    enforce write-table allow-lists (`CASE_WRITE_TABLES`).
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import psycopg

_TABLE_PK: dict[str, str] = {
    "banks": "bank_id",
    "customers": "customer_id",
    "commercial_registry": "registry_id",
    "accounts": "account_id",
    "transactions": "txn_id",
    "alerts": "alert_id",
    "worksheets": "worksheet_id",
    "cases": "case_id",
    "users": "username",
    "revoked_tokens": "jti",
    "approval_tokens": "token_id",
    "checkpoints": "thread_id",
    "entity_profiles": "customer_id",
    "reflexion_playbook": "lesson_id",
    "system_flags": "flag_key",
}
_SERIAL_PK: dict[str, str] = {
    "audit_logs": "log_id",
    "investigation_events": "event_id",
    "case_episodes": "episode_id",
}
_INSERT_REPLACE_RE = re.compile(
    r"^\s*INSERT\s+OR\s+(IGNORE|REPLACE)\s+INTO\s+([a-zA-Z0-9_]+)\s*\(([^)]+)\)\s*VALUES\s*\((.+)\)\s*;?\s*$",
    re.IGNORECASE | re.DOTALL,
)
_INSERT_SERIAL_RE = re.compile(r"^\s*INSERT\s+INTO\s+(audit_logs|investigation_events|case_episodes)\b", re.IGNORECASE)
_WRITE_TARGET_RE = re.compile(
    r"^\s*(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|DELETE\s+FROM|"
    r"CREATE\s+TABLE|DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE(?:\s+TABLE)?)\s+"
    r"(?:IF\s+(?:NOT\s+)?EXISTS\s+)?([a-zA-Z0-9_]+)",
    re.IGNORECASE,
)


class CompatRow(Mapping[str, Any]):
    """Hybrid mapping + sequence row compatible with `sqlite3.Row` (`row['col']`, `row[0]`, `dict(row)`)."""

    def __init__(self, columns: Sequence[str], values: Sequence[Any]) -> None:
        self._cols = tuple(columns)
        self._vals = tuple(values)
        self._map = dict(zip(self._cols, self._vals, strict=False))

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._vals[key]
        return self._map[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._cols)

    def __len__(self) -> int:
        return len(self._cols)


def _qmark_to_pyformat(sql: str) -> str:
    out: list[str] = []
    in_quote = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            out.append(ch)
            if in_quote and i + 1 < len(sql) and sql[i + 1] == "'":
                out.append("'")
                i += 2
                continue
            in_quote = not in_quote
        elif ch == "?" and not in_quote:
            out.append("%s")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def translate_sql(sql: str) -> tuple[str, str | None]:
    """Translate SQLite dialect SQL to PostgreSQL SQL, returning `(pg_sql, returning_col)`."""
    converted = _qmark_to_pyformat(sql.strip())
    m = _INSERT_REPLACE_RE.match(converted)
    if m:
        mode, table, cols_raw, vals_raw = m.group(1).upper(), m.group(2).lower(), m.group(3), m.group(4)
        pk = _TABLE_PK.get(table)
        if not pk:
            raise ValueError(f"unknown primary key for upsert table {table!r}")
        cols = [c.strip() for c in cols_raw.split(",")]
        if mode == "IGNORE":
            sql_ignore = f"INSERT INTO {table} ({cols_raw}) VALUES ({vals_raw}) ON CONFLICT ({pk}) DO NOTHING"  # noqa: S608
            return sql_ignore, None
        updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in cols if c != pk)
        conflict = f"DO UPDATE SET {updates}" if updates else "DO NOTHING"
        sql_upsert = f"INSERT INTO {table} ({cols_raw}) VALUES ({vals_raw}) ON CONFLICT ({pk}) {conflict}"  # noqa: S608
        return sql_upsert, None

    sm = _INSERT_SERIAL_RE.match(converted)
    if sm and "RETURNING " not in converted.upper():
        tbl = sm.group(1).lower()
        col = _SERIAL_PK[tbl]
        return f"{converted.rstrip(';')} RETURNING {col}", col
    return converted, None


def enforce_write_scope(sql: str, allowed: frozenset[str] | None) -> None:
    if allowed is None:
        return
    m = _WRITE_TARGET_RE.match(sql)
    if m and m.group(1).lower() not in allowed:
        raise sqlite3.DatabaseError(f"write denied to table {m.group(1)!r} outside allowed scope")


class CompatCursor:
    def __init__(self, rows: list[CompatRow], rowcount: int, lastrowid: int | None) -> None:
        self._rows = rows
        self.rowcount = rowcount
        self.lastrowid = lastrowid
        self._idx = 0

    def fetchone(self) -> CompatRow | None:
        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return row

    def fetchall(self) -> list[CompatRow]:
        rest = self._rows[self._idx :]
        self._idx = len(self._rows)
        return rest

    def __iter__(self) -> Iterator[CompatRow]:
        return iter(self.fetchall())


class PostgresCompatConnection:
    """Thin wrapper over `psycopg.Connection` matching the `sqlite3.Connection` methods used by repos."""

    def __init__(
        self,
        dsn: str,
        *,
        read_only: bool = False,
        timeout_s: float = 15.0,
        allowed_write_tables: Iterable[str] | None = None,
    ) -> None:
        self._conn = psycopg.connect(dsn, connect_timeout=max(2, int(timeout_s)))
        self._allowed = frozenset(t.lower() for t in allowed_write_tables) if allowed_write_tables is not None else None
        self._read_only = read_only
        with self._conn.cursor() as cur:
            cur.execute(f"SET statement_timeout = {int(timeout_s * 1000)}")
            if read_only:
                cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> CompatCursor:
        if self._read_only and _WRITE_TARGET_RE.match(sql):
            raise sqlite3.OperationalError("attempt to write a readonly database")
        enforce_write_scope(sql, self._allowed)
        pg_sql, ret_col = translate_sql(sql)
        try:
            with self._conn.cursor() as cur:
                cur.execute(pg_sql, tuple(params))
                rowcount = cur.rowcount if cur.rowcount >= 0 else 0
                lastrowid: int | None = None
                rows: list[CompatRow] = []
                if cur.description is not None:
                    cols = [d.name for d in cur.description]
                    raw_rows = cur.fetchall()
                    if ret_col and raw_rows:
                        lastrowid = int(raw_rows[0][0])
                    else:
                        rows = [CompatRow(cols, r) for r in raw_rows]
                return CompatCursor(rows, rowcount, lastrowid)
        except psycopg.IntegrityError as exc:
            raise sqlite3.IntegrityError(str(exc)) from exc
        except psycopg.Error as exc:
            raise sqlite3.DatabaseError(str(exc)) from exc

    def executemany(self, sql: str, seq_of_params: Iterable[Sequence[Any]]) -> None:
        for params in seq_of_params:
            self.execute(sql, params)

    def executescript(self, script: str) -> None:
        with self._conn.cursor() as cur:
            cur.execute(script)

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()


def postgres_ddl() -> str:
    ddl_path = Path(__file__).resolve().parents[2] / "scripts" / "init_db.sql"
    return ddl_path.read_text(encoding="utf-8")
