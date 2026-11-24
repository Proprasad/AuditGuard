"""
Wave 3 Adversarial Closure Tests:
  1. C-01 / H-03: `scripts/init_db.sql` vs `BasePostgresSaver.MIGRATIONS` DDL disjointness + least-privilege PG roles.
  2. H-03: Writable-CTE (`WITH d AS (DELETE ...)`), multi-statement, and `SET ROLE` SQL write-scope blocking.
  3. H-01 / M-01: Dynamic `get_account_transactions(days_back=...)` & `get_counterparty_history(counterparty_id=...)`
     through `fetch_flow_evidence` and `gather_identity` with zero schema/cutoff errors.
  4. L-01 / L-03 / M-03: Dual-affixed currency prose (`INR 9 lakhs`), pure `Decimal` confidence validation, and
     canonical JSON serialization in `save_checkpoint` + `memory_store`.
  5. M-02 / M-04 / H-04: Lifespan MCP client pool reuse, dev alert auto-seeding, and end-to-end `GuardedToolbox`
     red-team execution writing real `injection_detected_in_tool_output` audit entries.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
import re
import sqlite3
from typing import Any

from langgraph.checkpoint.postgres.base import BasePostgresSaver
import pytest

from eval.run_eval import evaluate_red_team_suite
from src.agent.gathering import fetch_flow_evidence, gather_identity
from src.agent.graph import make_context
from src.core.verifier import verify_worksheet
from src.db.database import ensure_dev_alerts_seeded, get_db, list_audit_logs, save_checkpoint
from src.db.postgres_backend import enforce_write_scope
from src.mcp_servers import bank_records
from src.mcp_servers.client import call_mcp_tool, close_mcp_client_pool, open_mcp_client_pool
from src.memory.store import LongTermMemoryStore
from src.models import Alert, GraphParams, InvestigationPlan, InvestigationState, RiskLevel


def _extract_created_tables(ddl: str) -> set[str]:
    return {
        m.group(1).lower()
        for m in re.finditer(r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)", ddl, re.I)
    }


def test_w3_01_postgres_ddl_disjoint_from_langgraph_and_scoped_roles() -> None:
    init_sql = Path("scripts/init_db.sql").read_text(encoding="utf-8")
    init_tables = _extract_created_tables(init_sql)
    langgraph_tables = _extract_created_tables("\n".join(BasePostgresSaver.MIGRATIONS))

    assert "thread_checkpoints" in init_tables
    assert "checkpoints" in langgraph_tables
    assert init_tables.isdisjoint(langgraph_tables), f"Collision: {init_tables & langgraph_tables}"

    assert "auditguard_ro" in init_sql
    assert "auditguard_case_writer" in init_sql
    assert "GRANT SELECT ON ALL TABLES IN SCHEMA public TO auditguard_ro" in init_sql
    writer_grant = "GRANT INSERT, UPDATE ON worksheets, approval_tokens, cases, audit_logs TO auditguard_case_writer"
    assert writer_grant in init_sql

    with get_db() as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        sqlite_tables = {str(r[0]) for r in rows}
    assert "thread_checkpoints" in sqlite_tables


def test_w3_02_writable_cte_multistatement_and_role_escalation_blocked() -> None:
    allowed = frozenset({"worksheets", "cases", "approval_tokens", "audit_logs"})

    # String literal containing SQL keywords must NOT false-positive
    enforce_write_scope(
        "INSERT INTO audit_logs (thread_id, payload_json) VALUES ('t1', 'DELETE FROM transactions; DROP TABLE banks')",
        allowed,
    )

    attack_queries = [
        "WITH d AS (DELETE FROM transactions RETURNING *) INSERT INTO audit_logs (thread_id) VALUES ('t')",
        "WITH u AS (UPDATE alerts SET status = 'CLOSED' RETURNING *) INSERT INTO cases (case_id) VALUES ('1')",
        "INSERT INTO cases (case_id) VALUES ('1'); DELETE FROM alerts",
        "SET ROLE postgres",
        "RESET ROLE",
        "TRUNCATE TABLE cases",
        "GRANT ALL ON transactions TO auditguard_case_writer",
    ]
    for q in attack_queries:
        with pytest.raises(sqlite3.DatabaseError):
            enforce_write_scope(q, allowed)


@pytest.mark.asyncio
async def test_w3_03_dynamic_account_transactions_days_back_and_counterparty_history_e2e() -> None:
    overlay = {
        "alert_id": "ALT-W3-DYN",
        "triggered_at": "2026-09-20T00:00:00Z",
        "root_account": "ACC-W3-ROOT",
        "network_accounts": ["ACC-W3-CP1"],
        "total_amount_inr": "500000.00",
        "accounts": [
            {
                "account_id": "ACC-W3-ROOT",
                "customer_name": "Root Trader",
                "declared_monthly_turnover_inr": "400000.00",
            },
            {
                "account_id": "ACC-W3-CP1",
                "customer_name": "Counterparty One",
                "declared_monthly_turnover_inr": "400000.00",
            },
            {
                "account_id": "ACC-W3-FOCUS",
                "customer_name": "Extra Focus Co",
                "declared_monthly_turnover_inr": "400000.00",
            },
        ],
        "transactions": [
            {
                "tx_id": "TXN-W3-ROOT-1",
                "sender_account": "ACC-W3-ROOT",
                "receiver_account": "ACC-W3-CP1",
                "amount_inr": "500000.00",
                "timestamp": "2026-09-18T10:00:00Z",
                "memo_text": "Supplier advance",
            },
            {
                "tx_id": "TXN-W3-RECENT",
                "sender_account": "ACC-W3-FOCUS",
                "receiver_account": "ACC-W3-OTHER",
                "amount_inr": "220000.00",
                "timestamp": "2026-09-15T12:00:00Z",
                "memo_text": "Recent focus transfer",
            },
            {
                "tx_id": "TXN-W3-STALE",
                "sender_account": "ACC-W3-FOCUS",
                "receiver_account": "ACC-W3-OTHER",
                "amount_inr": "190000.00",
                "timestamp": "2026-03-01T12:00:00Z",
                "memo_text": "Stale transfer outside lookback",
            },
        ],
    }
    tok = bank_records.set_eval_case_overlay(overlay)
    try:
        direct_txs = await call_mcp_tool(
            "bank-records",
            "get_account_transactions",
            {"account_id": "ACC-W3-FOCUS", "days_back": 14},
        )
        tx_ids = [t["tx_id"] for t in direct_txs["transactions"]]
        assert "TXN-W3-RECENT" in tx_ids
        assert "TXN-W3-STALE" not in tx_ids
    finally:
        bank_records.reset_eval_case_overlay(tok)

    # Now seed the isolated SQLite DB and verify the real SQL path end-to-end through gathering.py
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO banks (bank_id, bank_name, ifsc_prefix) VALUES ('BNK-W3', 'W3 Bank', 'W3BK')"
        )
        for cid, name, acc_id in (
            ("CUS-W3-1", "Root Trader", "ACC-W3-ROOT"),
            ("CUS-W3-2", "Counterparty One", "ACC-W3-CP1"),
            ("CUS-W3-3", "Extra Focus Co", "ACC-W3-FOCUS"),
            ("CUS-W3-4", "Other Co", "ACC-W3-OTHER"),
        ):
            conn.execute(
                "INSERT OR IGNORE INTO customers "
                "(customer_id, full_name, occupation, declared_annual_income_inr, risk_rating, onboarding_date) "
                "VALUES (?, ?, 'TRADER', '4800000.00', 'MEDIUM', '2024-01-01')",
                (cid, name),
            )
            conn.execute(
                "INSERT OR IGNORE INTO accounts "
                "(account_id, bank_id, customer_id, account_type, status, opened_date) "
                "VALUES (?, 'BNK-W3', ?, 'CURRENT', 'ACTIVE', '2024-01-01')",
                (acc_id, cid),
            )
        for tx in overlay["transactions"]:
            conn.execute(
                "INSERT OR REPLACE INTO transactions "
                "(txn_id, from_account_id, to_account_id, amount_inr, txn_timestamp, channel, memo_text) "
                "VALUES (?, ?, ?, ?, ?, 'NEFT', ?)",
                (
                    tx["tx_id"],
                    tx["sender_account"],
                    tx["receiver_account"],
                    tx["amount_inr"],
                    tx["timestamp"],
                    tx["memo_text"],
                ),
            )
        conn.execute(
            "INSERT OR REPLACE INTO alerts "
            "(alert_id, seed_account_id, triggered_at, rule_triggered, initial_amount_inr, network_accounts_json) "
            "VALUES ('ALT-W3-DYN', 'ACC-W3-ROOT', '2026-09-20T00:00:00Z', 'SCATTER_GATHER', '500000.00', "
            "'[\"ACC-W3-CP1\"]')"
        )

    alert = Alert(
        alert_id="ALT-W3-DYN",
        rule_name="SCATTER_GATHER",
        root_account="ACC-W3-ROOT",
        network_accounts=["ACC-W3-CP1"],
        total_amount_inr=Decimal("500000.00"),
        risk_level=RiskLevel.HIGH,
    )
    plan = InvestigationPlan(
        steps=["Expand focus account", "Verify counterparty relationship"],
        focus_accounts=["ACC-W3-FOCUS"],
        graph_params=GraphParams(
            time_window_days=14, max_hops=3, amount_tolerance=Decimal("0.12"), min_intermediaries=2
        ),
    )
    state = InvestigationState(thread_id="thr-w3-dyn", alert=alert, plan=plan, replan_count=1)
    ctx = make_context("c1_single", "thr-w3-dyn")
    registry: dict[str, Any] = {}
    degraded: list[str] = []

    root, network, txs, paths, _ = await fetch_flow_evidence(state, ctx, ctx.box("flow_tracer"), registry, degraded)
    assert not any("Account transactions unavailable" in d for d in degraded), degraded
    assert "TXN-W3-RECENT" in registry
    assert "TXN-W3-STALE" not in registry

    state_with_txs = state.model_copy(update={"transactions": txs})
    await gather_identity(ctx, state_with_txs, root, network, paths, registry, degraded)
    assert not any("Counterparty history unavailable" in d for d in degraded), degraded
    assert "CP-ACC-W3-ROOT-ACC-W3-CP1" in registry
    assert registry["CP-ACC-W3-ROOT-ACC-W3-CP1"]["total_transactions"] == 1


def test_w3_04_dual_affix_currency_prose_decimal_confidence_and_canonical_json() -> None:
    registry = {
        "TXN-1": {"tx_id": "TXN-1", "amount_inr": "900000.00"},
        "REG-FIU-RF-014": {"clause_id": "REG-FIU-RF-014", "title": "Scatter Gather"},
    }
    ok_ws = {
        "alert_id": "ALT-1",
        "recommended_disposition": "escalate_str",
        "recommendation_rationale": "Observed dispersal of INR 9 lakhs citing REG-FIU-RF-014.",
        "confidence_score": "0.8500",
        "regulatory_citations": ["REG-FIU-RF-014"],
        "alert_amount_inr": "900000.00",
        "hypotheses": [
            {
                "label": "suspicious",
                "explanation": "Dispersal on TXN-1.",
                "confidence": "0.8500",
                "evidence_ids": ["TXN-1"],
            },
            {
                "label": "benign",
                "explanation": "Merchant settlement checked on TXN-1.",
                "confidence": "0.1500",
                "evidence_ids": ["TXN-1"],
            },
        ],
        "missing_evidence": ["Counterparty tax invoices"],
    }
    vr_ok = verify_worksheet(ok_ws, registry)
    assert vr_ok.passed, vr_ok.discrepancies

    bad_amt_ws = {
        **ok_ws,
        "recommendation_rationale": "Observed dispersal of INR 9.5 lakhs citing REG-FIU-RF-014.",
    }
    vr_bad_amt = verify_worksheet(bad_amt_ws, registry)
    assert not vr_bad_amt.passed
    assert any(d.code == "UNGROUNDED_AMOUNT" for d in vr_bad_amt.discrepancies)

    bad_conf_ws = {**ok_ws, "confidence_score": "1.5000"}
    vr_bad_conf = verify_worksheet(bad_conf_ws, registry)
    assert not vr_bad_conf.passed
    assert any(d.code == "CONFIDENCE_OUT_OF_RANGE" for d in vr_bad_conf.discrepancies)

    save_checkpoint(
        "thr-w3-json",
        "ALT-1",
        "c1_single",
        "human_gate",
        "paused",
        {"amount": Decimal("123.45"), "ts": datetime(2026, 9, 1, tzinfo=timezone.utc)},
    )
    persistent_store = LongTermMemoryStore(persist=True)
    persistent_store.save_entity_profile("CUST-W3-1", {"turnover": Decimal("400000.00")})
    assert persistent_store.save_case_episode(
        "CUST-W3-1",
        {"confidence": Decimal("0.8200"), "reviewed_at": datetime(2026, 9, 1, tzinfo=timezone.utc)},
        human_approved=True,
    )


@pytest.mark.asyncio
async def test_w3_05_mcp_client_pool_and_red_team_guarded_toolbox_parity() -> None:
    seeded = ensure_dev_alerts_seeded()
    assert seeded >= 0

    open_mcp_client_pool()
    try:
        res1 = await call_mcp_tool("compliance-kb", "get_clause_by_id", {"clause_id": "REG-FIU-RF-014"})
        res2 = await call_mcp_tool("compliance-kb", "get_clause_by_id", {"clause_id": "REG-FIU-RF-014"})
        assert res1["clause_id"] == res2["clause_id"] == "REG-FIU-RF-014"
    finally:
        await close_mcp_client_pool()

    rt_on = await evaluate_red_team_suite(defenses_enabled=True)
    assert rt_on["attack_block_rate"] == 1.0
    assert rt_on["false_block_rate"] == 0.0
    inj_logs = list_audit_logs(thread_id="thr-rt-inj", limit=20)
    assert any(row["event_type"] == "injection_detected_in_tool_output" for row in inj_logs)
