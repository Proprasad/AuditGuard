"""
MCP Server: bank-records (READ-ONLY)

Parameterised, read-only SQL against the operational database. Connections are opened with `mode=ro` +
`PRAGMA query_only` and a statement deadline (`get_ro_db`); every query is capped (`LIMIT <= 200`).
There are NO fallbacks: unknown alerts/accounts return structured errors (`INVALID_ALERT_ID`, `ACCOUNT_NOT_FOUND`).
Seeding is a startup/CLI concern and never happens inside a read tool.

Held-out isolation: this server never reads `eval/held_out/`. Evaluation runs inject a scoped, per-case in-memory
overlay (`set_eval_case_overlay`) instead of mounting held-out data into the database.

Tools: get_alert_context, get_account_transactions, get_kyc_profile, get_counterparty_history, check_commercial_registry
"""

from __future__ import annotations

import asyncio
import contextvars
from datetime import timedelta
from decimal import Decimal
import json
import os
from typing import Any, Optional

from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from src.core.canonical import dec_str, parse_utc_timestamp, to_money
from src.db.database import DbConn, get_ro_db
from src.mcp_servers.http_auth import serve_mcp_http

MAX_ROWS = 200

mcp = FastMCP(
    name="bank-records",
    instructions="Read-only parameterized SQL access to multi-bank alerts, transactions, "
    "KYC profiles, counterparty history, and commercial registry records.",
)

_eval_case_ctx: contextvars.ContextVar[Optional[dict[str, Any]]] = contextvars.ContextVar(
    "_eval_case_ctx", default=None
)


def set_eval_case_overlay(case: Optional[dict[str, Any]]) -> contextvars.Token[Optional[dict[str, Any]]]:
    return _eval_case_ctx.set(case)


def reset_eval_case_overlay(token: contextvars.Token[Optional[dict[str, Any]]]) -> None:
    _eval_case_ctx.reset(token)


def _error(code: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_code": code, "message": message}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GetAlertContextInput(_Strict):
    alert_id: str


class GetAccountTransactionsInput(_Strict):
    account_id: str
    days_back: int = Field(default=30, ge=1, le=365)
    limit: int = Field(default=50, ge=1, le=MAX_ROWS)


class GetKYCProfileInput(_Strict):
    account_id: str


class GetCounterpartyHistoryInput(_Strict):
    account_id: str
    counterparty_id: str
    days_back: int = Field(default=90, ge=1, le=365)


class CheckCommercialRegistryInput(_Strict):
    entity_name: str
    account_id: Optional[str] = None
    pan: Optional[str] = None
    gstin: Optional[str] = None


def _tx_dict(row: Any) -> dict[str, Any]:
    return {
        "tx_id": row["txn_id"],
        "sender_account": row["from_account_id"],
        "receiver_account": row["to_account_id"],
        "amount_inr": dec_str(to_money(row["amount_inr"])),
        "currency": "INR",
        "timestamp": row["txn_timestamp"],
        "channel": row["channel"],
        "memo": row["memo_text"],
    }


_TX_COLUMNS = "txn_id, from_account_id, to_account_id, amount_inr, txn_timestamp, channel, memo_text"


def _alert_transactions(conn: DbConn, seed: str, network: list[str]) -> list[dict[str, Any]]:
    accounts = [seed, *network]
    marks = ",".join("?" for _ in accounts)
    rows = conn.execute(
        f"SELECT DISTINCT {_TX_COLUMNS} FROM transactions "  # noqa: S608 - only '?' placeholders are interpolated
        f"WHERE from_account_id IN ({marks}) OR to_account_id IN ({marks}) "
        f"OR from_account_id IN (SELECT to_account_id FROM transactions WHERE from_account_id = ?) "
        f"ORDER BY txn_timestamp ASC LIMIT {MAX_ROWS}",
        (*accounts, *accounts, seed),
    ).fetchall()
    return [_tx_dict(r) for r in rows]


def get_alert_record(alert_id: str) -> Optional[dict[str, Any]]:
    """Trusted alert lookup (None if the alert does not exist)."""
    with get_ro_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if row is None:
        return None
    return {
        "alert_id": row["alert_id"],
        "rule_name": row["rule_triggered"],
        "root_account": row["seed_account_id"],
        "network_accounts": json.loads(row["network_accounts_json"] or "[]"),
        "total_amount_inr": to_money(row["initial_amount_inr"]),
        "triggered_at": row["triggered_at"],
        "status": row["status"],
    }


def _sync_alert_context(alert_id: str) -> dict[str, Any]:
    with get_ro_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if row is None:
            return _error("INVALID_ALERT_ID", f"Alert {alert_id} not found")
        network = json.loads(row["network_accounts_json"] or "[]")
        txs = _alert_transactions(conn, row["seed_account_id"], network)
    return {
        "status": "ok",
        "alert_id": row["alert_id"],
        "rule_name": row["rule_triggered"],
        "triggered_at": row["triggered_at"],
        "root_account": row["seed_account_id"],
        "network_accounts": network,
        "total_amount_inr": dec_str(to_money(row["initial_amount_inr"])),
        "transactions": txs,
        "alert_status": row["status"],
        "risk_level": "high",
    }


@mcp.tool()
async def get_alert_context(params: GetAlertContextInput) -> dict[str, Any]:
    """Alert metadata, seed account and multi-bank network transactions."""
    overlay = _eval_case_ctx.get()
    if overlay and overlay.get("alert_id") == params.alert_id:
        return {
            "status": "ok",
            "alert_id": overlay["alert_id"],
            "case_id": overlay.get("case_id"),
            "rule_name": overlay.get("rule_name", "SCATTER_GATHER"),
            "triggered_at": overlay["triggered_at"],
            "root_account": overlay["root_account"],
            "network_accounts": overlay["network_accounts"],
            "total_amount_inr": dec_str(to_money(overlay["total_amount_inr"])),
            "transactions": overlay["transactions"],
            "risk_level": "high",
        }
    return await asyncio.to_thread(_sync_alert_context, params.alert_id)


def _filter_by_days_back(txs: list[dict[str, Any]], days_back: int) -> list[dict[str, Any]]:
    if not txs:
        return []
    stamps = [parse_utc_timestamp(t["timestamp"]) for t in txs if t.get("timestamp")]
    if not stamps:
        return txs
    cutoff = max(stamps) - timedelta(days=days_back)
    return [t for t in txs if t.get("timestamp") and parse_utc_timestamp(t["timestamp"]) >= cutoff]


def _sync_account_txs(account_id: str, days_back: int, limit: int) -> list[dict[str, Any]]:
    with get_ro_db() as conn:
        max_row = conn.execute(
            "SELECT MAX(txn_timestamp) FROM transactions WHERE from_account_id = ? OR to_account_id = ?",
            (account_id, account_id),
        ).fetchone()
        latest_raw = max_row[0] if max_row else None
        if not latest_raw:
            return []
        cutoff_iso = (parse_utc_timestamp(latest_raw) - timedelta(days=days_back)).isoformat()
        rows = conn.execute(
            f"SELECT {_TX_COLUMNS} FROM transactions "  # noqa: S608
            "WHERE (from_account_id = ? OR to_account_id = ?) AND txn_timestamp >= ? "
            "ORDER BY txn_timestamp DESC LIMIT ?",
            (account_id, account_id, cutoff_iso, min(limit, MAX_ROWS)),
        ).fetchall()
    return [_tx_dict(r) for r in rows]


@mcp.tool()
async def get_account_transactions(params: GetAccountTransactionsInput) -> dict[str, Any]:
    """Transaction history for an account within `days_back` (hard cap: 200 rows)."""
    overlay = _eval_case_ctx.get()
    if overlay:
        matched = [
            t
            for t in overlay.get("transactions", [])
            if params.account_id in (t.get("sender_account"), t.get("receiver_account"))
        ]
        txs = _filter_by_days_back(matched, params.days_back)[: params.limit]
    else:
        txs = await asyncio.to_thread(_sync_account_txs, params.account_id, params.days_back, params.limit)
    return {
        "status": "ok",
        "account_id": params.account_id,
        "period_days": params.days_back,
        "total_transactions": len(txs),
        "transactions": txs,
    }


def _sync_kyc(account_id: str) -> dict[str, Any]:
    with get_ro_db() as conn:
        row = conn.execute(
            "SELECT a.account_id, a.account_type, b.bank_name, c.customer_id, c.full_name, c.kyc_tier, c.occupation, "
            "c.declared_annual_income_inr, c.risk_rating, c.kyc_notes, "
            "cr.entity_type AS registry_type, cr.status AS registry_status "
            "FROM accounts a JOIN customers c ON a.customer_id = c.customer_id "
            "LEFT JOIN banks b ON a.bank_id = b.bank_id "
            "LEFT JOIN commercial_registry cr ON c.customer_id = cr.customer_id WHERE a.account_id = ?",
            (account_id,),
        ).fetchone()
    if row is None:
        return _error("ACCOUNT_NOT_FOUND", f"No KYC record for account {account_id}")
    return {
        "status": "ok",
        "evidence_id": f"KYC-{account_id}",
        "account_id": row["account_id"],
        "customer_id": row["customer_id"],
        "entity_name": row["full_name"],
        "entity_type": row["occupation"],
        "bank_name": row["bank_name"],
        "kyc_tier": row["kyc_tier"],
        "risk_category": str(row["risk_rating"]).lower(),
        "declared_annual_income_inr": dec_str(to_money(row["declared_annual_income_inr"])),
        "is_commercially_registered": row["registry_status"] == "ACTIVE",
        "registry_type": row["registry_type"],
        "kyc_notes": row["kyc_notes"] or "",
        "pep_flag": False,
        "sanctions_flag": False,
    }


@mcp.tool()
async def get_kyc_profile(params: GetKYCProfileInput) -> dict[str, Any]:
    """KYC profile & risk tier for an account (`ACCOUNT_NOT_FOUND` if unknown - nothing is fabricated)."""
    overlay = _eval_case_ctx.get()
    if overlay and params.account_id in overlay.get("kyc_profiles", {}):
        return {
            "status": "ok",
            "evidence_id": f"KYC-{params.account_id}",
            **overlay["kyc_profiles"][params.account_id],
        }
    return await asyncio.to_thread(_sync_kyc, params.account_id)


def _sync_counterparty_txs(account_id: str, counterparty_id: str, days_back: int) -> list[dict[str, Any]]:
    with get_ro_db() as conn:
        max_row = conn.execute(
            "SELECT MAX(txn_timestamp) FROM transactions "
            "WHERE (from_account_id = ? AND to_account_id = ?) OR (from_account_id = ? AND to_account_id = ?)",
            (account_id, counterparty_id, counterparty_id, account_id),
        ).fetchone()
        latest_raw = max_row[0] if max_row else None
        if not latest_raw:
            return []
        cutoff_iso = (parse_utc_timestamp(latest_raw) - timedelta(days=days_back)).isoformat()
        rows = conn.execute(
            f"SELECT {_TX_COLUMNS} FROM transactions "  # noqa: S608
            "WHERE ((from_account_id = ? AND to_account_id = ?) OR (from_account_id = ? AND to_account_id = ?)) "
            f"AND txn_timestamp >= ? ORDER BY txn_timestamp DESC LIMIT {MAX_ROWS}",
            (account_id, counterparty_id, counterparty_id, account_id, cutoff_iso),
        ).fetchall()
    return [_tx_dict(r) for r in rows]


@mcp.tool()
async def get_counterparty_history(params: GetCounterpartyHistoryInput) -> dict[str, Any]:
    """Historical transfers between two accounts within `days_back` (hard cap: 200 rows)."""
    overlay = _eval_case_ctx.get()
    if overlay:
        pair = {params.account_id, params.counterparty_id}
        matched = [
            t for t in overlay.get("transactions", []) if {t.get("sender_account"), t.get("receiver_account")} == pair
        ]
        txs = _filter_by_days_back(matched, params.days_back)
    else:
        txs = await asyncio.to_thread(
            _sync_counterparty_txs, params.account_id, params.counterparty_id, params.days_back
        )
    total = sum((to_money(t.get("amount_inr", "0")) for t in txs), Decimal("0.00"))
    return {
        "status": "ok",
        "evidence_id": f"CP-{params.account_id}-{params.counterparty_id}",
        "account_id": params.account_id,
        "counterparty_id": params.counterparty_id,
        "period_days": params.days_back,
        "total_transactions": len(txs),
        "total_amount_inr": dec_str(total),
        "transactions": txs,
    }


def _registered(entity: str, kind: str, number: str, status: str, since: str, evidence: str) -> dict[str, Any]:
    return {
        "status": "ok",
        "evidence_id": evidence,
        "entity_name": entity,
        "is_registered": True,
        "registry_type": kind,
        "registration_number": number,
        "registry_status": status,
        "registered_since": since,
    }


def _sync_registry(entity_name: str, account_id: Optional[str], not_found: dict[str, Any]) -> dict[str, Any]:
    columns = "cr.registry_id, cr.entity_type, cr.registration_number, cr.status, cr.registered_since, c.full_name"
    with get_ro_db() as conn:
        row = None
        if account_id:
            row = conn.execute(
                f"SELECT {columns} FROM accounts a JOIN customers c ON a.customer_id = c.customer_id "  # noqa: S608
                "JOIN commercial_registry cr ON c.customer_id = cr.customer_id WHERE a.account_id = ?",
                (account_id,),
            ).fetchone()
        if row is None:
            row = conn.execute(
                f"SELECT {columns} FROM customers c JOIN commercial_registry cr ON c.customer_id = cr.customer_id "  # noqa: S608
                "WHERE c.full_name = ?",
                (entity_name,),
            ).fetchone()
    if row and row["status"] == "ACTIVE":
        return _registered(
            row["full_name"],
            row["entity_type"],
            row["registration_number"],
            row["status"],
            row["registered_since"],
            row["registry_id"],
        )
    return not_found


@mcp.tool()
async def check_commercial_registry(params: CheckCommercialRegistryInput) -> dict[str, Any]:
    """GST / MCA / Section 80G / Chit registration lookup (a clean NOT_FOUND is a legitimate answer)."""
    overlay = _eval_case_ctx.get()
    not_found = {
        "status": "ok",
        "evidence_id": f"REGISTRY-NONE-{params.entity_name}",
        "entity_name": params.entity_name,
        "is_registered": False,
        "registry_status": "NOT_FOUND",
    }
    if overlay:
        profiles = overlay.get("kyc_profiles", {})
        kyc = (
            profiles.get(params.account_id)
            if params.account_id in profiles
            else next((r for r in profiles.values() if r.get("entity_name") == params.entity_name), None)
        )
        if kyc and kyc.get("is_commercially_registered"):
            return {
                "status": "ok",
                "evidence_id": f"REGISTRY-{kyc['account_id']}",
                "entity_name": params.entity_name,
                "is_registered": True,
                "registry_type": kyc.get("registry_type", "MERCHANT"),
                "registry_status": "ACTIVE",
            }
        return not_found
    return await asyncio.to_thread(_sync_registry, params.entity_name, params.account_id, not_found)


def list_queued_alerts(limit: int = 30) -> list[dict[str, Any]]:
    """Alerts for the workbench queue (status reflects any committed case)."""
    with get_ro_db() as conn:
        rows = conn.execute(
            "SELECT a.alert_id, a.seed_account_id, a.triggered_at, a.rule_triggered, a.initial_amount_inr, "
            "a.network_accounts_json, COALESCE((SELECT UPPER(k.disposition) "
            "FROM cases k WHERE k.alert_id = a.alert_id), a.status) AS status, "
            "c.customer_id, c.full_name, c.risk_rating FROM alerts a "
            "LEFT JOIN accounts acc ON a.seed_account_id = acc.account_id "
            "LEFT JOIN customers c ON acc.customer_id = c.customer_id "
            "ORDER BY a.triggered_at DESC, a.alert_id ASC LIMIT ?",
            (min(limit, MAX_ROWS),),
        ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["network_accounts"] = json.loads(item.pop("network_accounts_json", "[]") or "[]")
        out.append(item)
    return out


if __name__ == "__main__":
    port = int(os.getenv("MCP_BANK_RECORDS_PORT", "8012"))
    serve_mcp_http(mcp, port=port)
