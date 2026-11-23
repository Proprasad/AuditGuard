"""
PostgreSQL (`psycopg` + `psycopg_pool`) compatibility backend mirroring the `sqlite3` contract.

Enables shared relational state across multi-process deployments when `USE_POSTGRES=true`:
  - Lifespan-managed `ConnectionPool` eliminates per-query TCP/auth handshake churn.
  - Positional `?` placeholders outside single-quoted literals translate cleanly to `%s`.
  - `INSERT OR IGNORE` / `INSERT OR REPLACE` translate to deterministic `ON CONFLICT (<pk>)` clauses.
  - Read-only connections enforce `SET TRANSACTION READ ONLY`, `statement_timeout`, and `SET ROLE auditguard_ro`
    (when provisioned); scoped writers enforce `SET ROLE auditguard_case_writer` + multi-statement/CTE SQL guards.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any

import psycopg
from psycopg_pool import ConnectionPool

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
    "thread_checkpoints": "thread_id",
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
_ANY_WRITE_CLAUSE_RE = re.compile(
    r"\b(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|DELETE\s+FROM|"
    r"CREATE\s+(?:UNIQUE\s+)?(?:TABLE|INDEX|ROLE|VIEW|FUNCTION|TRIGGER)|"
    r"DROP\s+(?:TABLE|INDEX|ROLE|VIEW|SCHEMA)|ALTER\s+(?:TABLE|ROLE|DEFAULT)|"
    r"TRUNCATE(?:\s+TABLE)?|GRANT|REVOKE|COPY)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?([a-zA-Z0-9_]+)?",
    re.IGNORECASE,
)
_DDL_OR_ADMIN_RE = re.compile(
    r"\b(?:CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|COPY|SET\s+ROLE|RESET\s+ROLE)\b",
    re.IGNORECASE,
)

_POOL_LOCK = threading.Lock()
_PG_POOL: ConnectionPool[Any] | None = None
_PG_POOL_DSN: str = ""
_KNOWN_ROLES: set[str] | None = None


def open_postgres_pool(dsn: str, min_size: int = 1, max_size: int = 10) -> None:
    global _PG_POOL, _PG_POOL_DSN, _KNOWN_ROLES
    with _POOL_LOCK:
        if _PG_POOL is not None and _PG_POOL_DSN == dsn:
            return
        if _PG_POOL is not None:
            _PG_POOL.close()
        _PG_POOL = ConnectionPool(conninfo=dsn, min_size=min_size, max_size=max_size, open=True)
        _PG_POOL_DSN = dsn
        _KNOWN_ROLES = None


def close_postgres_pool() -> None:
    global _PG_POOL, _PG_POOL_DSN, _KNOWN_ROLES
    with _POOL_LOCK:
        if _PG_POOL is not None:
            _PG_POOL.close()
            _PG_POOL = None
            _PG_POOL_DSN = ""
            _KNOWN_ROLES = None


def _strip_quoted_literals(sql: str) -> str:
    return re.sub(r"'(?:''|[^'])*'", "''", sql)


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
            sql_ig = f"INSERT INTO {table} ({cols_raw}) VALUES ({vals_raw}) ON CONFLICT ({pk}) DO NOTHING"  # noqa: S608
            return sql_ig, None
        updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in cols if c != pk)
        conflict = f"DO UPDATE SET {updates}" if updates else "DO NOTHING"
        sql_up = f"INSERT INTO {table} ({cols_raw}) VALUES ({vals_raw}) ON CONFLICT ({pk}) {conflict}"  # noqa: S608
        return sql_up, None

    sm = _INSERT_SERIAL_RE.match(converted)
    if sm and "RETURNING " not in converted.upper():
        tbl = sm.group(1).lower()
        col = _SERIAL_PK[tbl]
        return f"{converted.rstrip(';')} RETURNING {col}", col
    return converted, None


def enforce_write_scope(sql: str, allowed: frozenset[str] | None) -> None:
    """Deny multi-statement SQL, DDL/privilege escalation, and any write/CTE targeting non-allowed tables."""
    if allowed is None:
        return
    scrubbed = _strip_quoted_literals(sql).strip().rstrip(";").strip()
    if ";" in scrubbed:
        raise sqlite3.DatabaseError("multi-statement SQL denied on scoped connection")
    if _DDL_OR_ADMIN_RE.search(scrubbed):
        raise sqlite3.DatabaseError("DDL or role mutation denied on scoped connection")
    for match in _ANY_WRITE_CLAUSE_RE.finditer(scrubbed):
        target = (match.group(1) or "").lower()
        if target not in allowed:
            raise sqlite3.DatabaseError(f"write denied to table {target!r} outside allowed scope")


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


def _available_roles(conn: psycopg.Connection[Any]) -> set[str]:
    global _KNOWN_ROLES
    if _KNOWN_ROLES is not None:
        return _KNOWN_ROLES
    with conn.cursor() as cur:
        rows = cur.execute(
            "SELECT rolname FROM pg_roles WHERE rolname IN ('auditguard_ro', 'auditguard_case_writer')"
        ).fetchall()
    _KNOWN_ROLES = {str(r[0]) for r in rows}
    return _KNOWN_ROLES


class PostgresCompatConnection:
    """Pooled `psycopg` connection wrapper enforcing read-only / scoped DB roles and statement timeouts."""

    def __init__(
        self,
        dsn: str,
        *,
        read_only: bool = False,
        timeout_s: float = 15.0,
        allowed_write_tables: Iterable[str] | None = None,
    ) -> None:
        self._pool = _PG_POOL if (_PG_POOL is not None and _PG_POOL_DSN == dsn) else None
        self._conn = (
            self._pool.getconn(timeout=max(2.0, timeout_s))
            if self._pool is not None
            else psycopg.connect(dsn, connect_timeout=max(2, int(timeout_s)))
        )
        self._allowed = frozenset(t.lower() for t in allowed_write_tables) if allowed_write_tables is not None else None
        self._read_only = read_only
        self._role_applied = False
        roles = _available_roles(self._conn)
        with self._conn.cursor() as cur:
            cur.execute(f"SET statement_timeout = {int(timeout_s * 1000)}")
            if read_only:
                cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
                if "auditguard_ro" in roles:
                    cur.execute("SET ROLE auditguard_ro")
                    self._role_applied = True
            elif self._allowed is not None and "auditguard_case_writer" in roles:
                cur.execute("SET ROLE auditguard_case_writer")
                self._role_applied = True

    def execute(self, sql: str, params: Sequence[Any] = ()) -> CompatCursor:
        scrubbed = _strip_quoted_literals(sql)
        if self._read_only and (_ANY_WRITE_CLAUSE_RE.search(scrubbed) or ";" in scrubbed.rstrip(";").strip()):
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
        if self._pool is None:
            self._conn.close()
            return
        try:
            self._conn.rollback()
            with self._conn.cursor() as cur:
                if self._role_applied:
                    cur.execute("RESET ROLE")
                if self._read_only:
                    cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE")
            self._conn.commit()
        except psycopg.Error:
            pass
        self._pool.putconn(self._conn)


def postgres_ddl() -> str:
    ddl_path = Path(__file__).resolve().parents[2] / "scripts" / "init_db.sql"
    return ddl_path.read_text(encoding="utf-8")
