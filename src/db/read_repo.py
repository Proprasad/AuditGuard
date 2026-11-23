"""Read-only repository queries backing Workbench navigation & analytics endpoints (zero SQL in FastAPI routes)."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from src.core.canonical import to_money
from src.db.database import get_ro_db, init_db


def fetch_cases_and_worksheets(limit: int = 50) -> dict[str, Any]:
    init_db()
    with get_ro_db() as conn:
        committed = [
            dict(r)
            for r in conn.execute(
                "SELECT case_id, alert_id, worksheet_id, disposition, payload_hash, approver_id, committed_at "
                "FROM cases ORDER BY committed_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        ]
        worksheets = [
            dict(r)
            for r in conn.execute(
                "SELECT worksheet_id, alert_id, payload_hash, status, "
                "reviewer_id, reviewer_decision, created_at, updated_at "
                "FROM worksheets ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        ]
    return {"cases": committed, "worksheets": worksheets, "total_committed": len(committed)}


def fetch_customers(limit: int = 100) -> dict[str, Any]:
    init_db()
    with get_ro_db() as conn:
        rows = conn.execute(
            "SELECT c.customer_id, c.full_name, c.kyc_tier, c.occupation, "
            "c.declared_annual_income_inr, c.risk_rating, c.onboarding_date, c.kyc_notes, "
            "a.account_id, a.account_type, b.bank_name, "
            "cr.registry_id, cr.entity_type AS registry_type, cr.status AS registry_status, "
            "(SELECT COUNT(*) FROM case_episodes ce WHERE ce.customer_id = c.customer_id) AS episodes_count "
            "FROM customers c "
            "LEFT JOIN accounts a ON a.customer_id = c.customer_id "
            "LEFT JOIN banks b ON a.bank_id = b.bank_id "
            "LEFT JOIN commercial_registry cr ON cr.customer_id = c.customer_id "
            "ORDER BY CASE c.risk_rating WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END, c.customer_id ASC "
            "LIMIT ?",
            (limit,),
        ).fetchall()
    return {"customers": [dict(r) for r in rows], "total": len(rows)}


def fetch_analytics() -> dict[str, Any]:
    init_db()
    with get_ro_db() as conn:
        alert_counts = {
            str(r["status"]): int(r["c"])
            for r in conn.execute("SELECT status, COUNT(*) AS c FROM alerts GROUP BY status").fetchall()
        }
        disp_counts = {
            str(r["disposition"]): int(r["c"])
            for r in conn.execute("SELECT disposition, COUNT(*) AS c FROM cases GROUP BY disposition").fetchall()
        }
        totals = conn.execute(
            "SELECT (SELECT COUNT(*) FROM alerts) AS total_alerts, "
            "(SELECT COUNT(*) FROM transactions) AS total_transactions, "
            "(SELECT COUNT(*) FROM cases) AS total_committed_cases, "
            "(SELECT COUNT(*) FROM audit_logs) AS total_audit_events, "
            "(SELECT COUNT(*) FROM thread_checkpoints) AS total_threads"
        ).fetchone()
        volume = sum(
            (to_money(r[0]) for r in conn.execute("SELECT amount_inr FROM transactions").fetchall()),
            Decimal("0.00"),
        )
    summary = dict(totals) if totals else {}
    summary["total_tx_volume_inr"] = format(volume, "f")
    return {"summary": summary, "alerts_by_status": alert_counts, "cases_by_disposition": disp_counts}
