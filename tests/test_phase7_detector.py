"""
Phase 7 — Detector Hardening, Corroboration, Missing-Data Detection & Aggregate-Path Metric Tests
(`tests/test_phase7_detector.py`).

Covers all `docs/AGENT_GUIDE.md` §4 Phase 7 requirements:
  1. Forged-registry probe: registered low-risk root with staggered multi-hop scatter-gather
     topology & unexplained legs -> `escalate_str` / `request_info`, NEVER auto-closed.
  2. Newly registered root (< 180d, zero counterparty cadence) below corroboration threshold ->
     NEVER auto-closed.
  3. Unregistered employer with 12-month regular payroll cadence (`get_counterparty_history`) ->
     corroborated benign closure.
  4. Explicit missing-data detection: accounts without KYC, stale/conflicting registry,
     outflows without downstream at max window, and external-bank memo patterns.
  5. Second path metric (`aggregate_root_flow_metrics`) deduplicating shared edges across all
     paths from root + `compute_flow_conservation` invoked and logged by `rule_engine` and `c0_fixed`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
from typing import Any

import pytest

from src.agent.c0_fixed import run_fixed_pipeline
from src.agent.rule_engine import run_rule_engine
from src.core import graph_math
from src.core.adapters import is_registered
from src.core.corroboration import assess_registration_corroboration, detect_missing_data
from src.core.policy import GraphLimits, Structuring, SuspicionRules
from src.mcp_servers import bank_records
from src.mcp_servers.client import call_mcp_tool
from src.models import Alert, DispositionDecision, RiskLevel


def _make_forged_registry_overlay() -> tuple[Alert, dict[str, Any]]:
    """Registered LOW-risk root running a staggered 14-day fee-skimming scatter-gather scheme."""
    overlay: dict[str, Any] = {
        "alert_id": "ALT-FORGED-REG-01",
        "case_id": "CASE-FORGED-REG-01",
        "rule_name": "SCATTER_GATHER",
        "triggered_at": "2026-09-01T09:00:00Z",
        "root_account": "ACC-FR-ROOT",
        "network_accounts": ["ACC-FR-M1", "ACC-FR-M2", "ACC-FR-DEST"],
        "total_amount_inr": "900000.00",
        "transactions": [
            {
                "tx_id": "TXN-FR-01",
                "sender_account": "ACC-FR-ROOT",
                "receiver_account": "ACC-FR-M1",
                "amount_inr": "450000.00",
                "timestamp": "2026-09-01T10:00:00Z",
                "memo": "Vendor invoice settlement",
            },
            {
                "tx_id": "TXN-FR-02",
                "sender_account": "ACC-FR-ROOT",
                "receiver_account": "ACC-FR-M2",
                "amount_inr": "450000.00",
                "timestamp": "2026-09-01T11:00:00Z",
                "memo": "Vendor invoice settlement",
            },
            # Delayed 14-day consolidation with 8% fee skim (invisible in initial 7d window!)
            {
                "tx_id": "TXN-FR-03",
                "sender_account": "ACC-FR-M1",
                "receiver_account": "ACC-FR-DEST",
                "amount_inr": "414000.00",
                "timestamp": "2026-09-15T10:00:00Z",
                "memo": "Vendor invoice settlement",
            },
            {
                "tx_id": "TXN-FR-04",
                "sender_account": "ACC-FR-M2",
                "receiver_account": "ACC-FR-DEST",
                "amount_inr": "414000.00",
                "timestamp": "2026-09-15T11:00:00Z",
                "memo": "Vendor invoice settlement",
            },
        ],
        "kyc_profiles": {
            "ACC-FR-ROOT": {
                "account_id": "ACC-FR-ROOT",
                "customer_id": "CUST-FR-ROOT",
                "entity_name": "Nominal GST Shell Pvt Ltd",
                "entity_type": "company",
                "risk_category": "low",
                "declared_annual_income_inr": "5000000.00",
                "is_commercially_registered": True,
                "registry_type": "MERCHANT",
                "kyc_notes": "Standard video-KYC completed.",
            },
            "ACC-FR-M1": {
                "account_id": "ACC-FR-M1",
                "customer_id": "CUST-FR-M1",
                "entity_name": "Intermediary One",
                "entity_type": "individual",
                "risk_category": "medium",
                "declared_annual_income_inr": "600000.00",
                "is_commercially_registered": False,
                "kyc_notes": "Savings account.",
            },
            "ACC-FR-M2": {
                "account_id": "ACC-FR-M2",
                "customer_id": "CUST-FR-M2",
                "entity_name": "Intermediary Two",
                "entity_type": "individual",
                "risk_category": "medium",
                "declared_annual_income_inr": "600000.00",
                "is_commercially_registered": False,
                "kyc_notes": "Savings account.",
            },
            "ACC-FR-DEST": {
                "account_id": "ACC-FR-DEST",
                "customer_id": "CUST-FR-DEST",
                "entity_name": "Consolidation Beneficiary",
                "entity_type": "company",
                "risk_category": "high",
                "declared_annual_income_inr": "500000.00",
                "is_commercially_registered": False,
                "kyc_notes": "Current account.",
            },
        },
        "registry_records": {
            "ACC-FR-ROOT": {
                "evidence_id": "REGISTRY-ACC-FR-ROOT",
                "account_id": "ACC-FR-ROOT",
                "entity_name": "Nominal GST Shell Pvt Ltd",
                "is_registered": True,
                "registry_type": "MERCHANT",
                "registration_number": "27AABCN9999R1Z1",
                "registry_status": "ACTIVE",
                "registered_since": "2026-07-20",
            },
        },
    }
    alert = Alert(
        alert_id=overlay["alert_id"],
        rule_name="SCATTER_GATHER",
        root_account="ACC-FR-ROOT",
        network_accounts=overlay["network_accounts"],
        total_amount_inr=Decimal("900000.00"),
        risk_level=RiskLevel.HIGH,
    )
    return alert, overlay


@pytest.mark.asyncio
async def test_forged_registry_probe_never_auto_closes() -> None:
    """Registered low-risk root with staggered scatter-gather & unexplained legs MUST NOT auto-close."""
    alert, overlay = _make_forged_registry_overlay()
    tok = bank_records.set_eval_case_overlay(overlay)
    try:
        st = await run_rule_engine(alert, thread_id="thr-p7-forged-reg")
    finally:
        bank_records.reset_eval_case_overlay(tok)

    assert st.worksheet is not None
    assert st.worksheet.recommended_disposition in (
        DispositionDecision.ESCALATE_STR,
        DispositionDecision.REQUEST_INFO,
    ), f"Forged-registry probe wrongly auto-closed: {st.worksheet.recommended_disposition}"
    assert st.replan_count >= 1, "Critique must not skip replanning on an uncorroborated registry flag"
    assert any(p.hop_count >= 2 for p in st.fund_flow_paths)
    assert any(k.startswith("CP-ACC-FR-ROOT-") for k in st.evidence_registry)
    assert any(k.endswith("-CONS") for k in st.evidence_registry)


@pytest.mark.asyncio
async def test_unregistered_12m_payroll_corroborated_benign_via_counterparty_history() -> None:
    """Unregistered employer with 12-month regular monthly NEFT cadence corroborates as `close_benign`."""
    anchor = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    txs: list[dict[str, Any]] = []
    seq = 0
    emps = ["ACC-EMP-1", "ACC-EMP-2", "ACC-EMP-3"]
    for month_ago in range(0, 12):
        ts = (anchor - timedelta(days=30 * month_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for emp in emps:
            seq += 1
            txs.append(
                {
                    "tx_id": f"TXN-PAY-{seq:03d}",
                    "sender_account": "ACC-EMP-ROOT",
                    "receiver_account": emp,
                    "amount_inr": "120000.00",
                    "timestamp": ts,
                    "memo": "NEFT monthly disbursement",
                }
            )
    overlay: dict[str, Any] = {
        "alert_id": "ALT-PAY-12M",
        "rule_name": "SCATTER_GATHER",
        "triggered_at": anchor.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root_account": "ACC-EMP-ROOT",
        "network_accounts": emps,
        "total_amount_inr": "360000.00",
        "transactions": txs,
        "kyc_profiles": {
            "ACC-EMP-ROOT": {
                "account_id": "ACC-EMP-ROOT",
                "customer_id": "CUST-EMP-ROOT",
                "entity_name": "Regional Textile Workshop",
                "entity_type": "partnership",
                "risk_category": "low",
                "declared_annual_income_inr": "6000000.00",
                "is_commercially_registered": False,
                "kyc_notes": "Standard video-KYC completed.",
            },
            **{
                e: {
                    "account_id": e,
                    "customer_id": f"CUST-{e}",
                    "entity_name": f"Worker {e}",
                    "entity_type": "individual",
                    "risk_category": "low",
                    "declared_annual_income_inr": "1500000.00",
                    "is_commercially_registered": False,
                    "kyc_notes": "Salaried individual.",
                }
                for e in emps
            },
        },
        "registry_records": {},
    }
    alert = Alert(
        alert_id="ALT-PAY-12M",
        rule_name="SCATTER_GATHER",
        root_account="ACC-EMP-ROOT",
        network_accounts=emps,
        total_amount_inr=Decimal("360000.00"),
        risk_level=RiskLevel.MEDIUM,
    )
    tok = bank_records.set_eval_case_overlay(overlay)
    try:
        st = await run_rule_engine(alert, thread_id="thr-p7-12m-payroll")
    finally:
        bank_records.reset_eval_case_overlay(tok)

    assert st.worksheet is not None
    assert st.worksheet.recommended_disposition == DispositionDecision.CLOSE_BENIGN
    assert any(k.startswith("CP-ACC-EMP-ROOT-") for k in st.evidence_registry)


@pytest.mark.asyncio
async def test_explicit_missing_data_detection_all_four_conditions() -> None:
    """Verify missing KYC, stale/conflicting registry, unconsolidated outflows, and external-bank memos."""
    # 1. Stale/expired registry overrides KYC boolean flag
    kyc_stale = {
        "account_id": "ACC-S1",
        "risk_category": "low",
        "is_commercially_registered": True,
        "registry_check": {"is_registered": False, "registry_status": "EXPIRED", "registered_since": "2018-01-01"},
    }
    assert is_registered(kyc_stale) is False

    # 2. Newly registered root (<180d, no counterparty cadence) falls below corroboration threshold
    kyc_new = {
        "account_id": "ACC-NEW",
        "risk_category": "low",
        "is_commercially_registered": True,
        "registry_check": {"is_registered": True, "registry_status": "ACTIVE", "registered_since": "2026-08-15"},
    }
    tx_recent = [
        {
            "tx_id": "TXN-N1",
            "sender_account": "ACC-NEW",
            "receiver_account": "ACC-B1",
            "timestamp": "2026-09-01T10:00:00Z",
        }
    ]
    corr_new = assess_registration_corroboration("ACC-NEW", kyc_new, [], [], tx_recent, {})
    assert corr_new.registry_active is True
    assert corr_new.corroborated_benign is False

    # 3. Direct detection of missing KYC, stale registry, external-bank memo, and unconsolidated outflows
    txs_gap = [
        {
            "tx_id": "TXN-EXT-1",
            "sender_account": "ACC-S1",
            "receiver_account": "ACC-X1",
            "amount_inr": "300000.00",
            "timestamp": "2026-09-01T10:00:00Z",
            "memo": "RTGS transfer to external bank correspondent leg",
        },
        {
            "tx_id": "TXN-EXT-2",
            "sender_account": "ACC-S1",
            "receiver_account": "ACC-X2",
            "amount_inr": "300000.00",
            "timestamp": "2026-09-01T11:00:00Z",
            "memo": "NEFT trf",
        },
    ]
    corr_stale = assess_registration_corroboration("ACC-S1", kyc_stale, [], [], txs_gap, {})
    report = detect_missing_data(
        "ACC-S1",
        ["ACC-X1", "ACC-X2"],
        txs_gap,
        [],
        [kyc_stale],
        ["KYC unavailable for ACC-X1: ACCOUNT_NOT_FOUND"],
        corr_stale,
        at_max_window=True,
    )
    assert report.has_explicit_missing_data is True
    assert "ACC-X1" in report.missing_kyc_accounts
    assert any("EXPIRED" in s for s in report.stale_or_conflicting_registry)
    assert "TXN-EXT-1" in report.external_bank_tx_ids
    assert report.unconsolidated_outflows is True
    assert len(report.missing_evidence_items) == 4

    # 4. End-to-end `rule_engine` on missing KYC + external bank memo routes explicitly to `request_info`
    overlay: dict[str, Any] = {
        "alert_id": "ALT-GAP-01",
        "rule_name": "SCATTER_GATHER",
        "triggered_at": "2026-09-01T09:00:00Z",
        "root_account": "ACC-S1",
        "network_accounts": ["ACC-X1", "ACC-X2"],
        "total_amount_inr": "600000.00",
        "transactions": txs_gap,
        "kyc_profiles": {
            "ACC-S1": {
                "account_id": "ACC-S1",
                "customer_id": "CUST-S1",
                "entity_name": "Stale Traders",
                "entity_type": "company",
                "risk_category": "low",
                "declared_annual_income_inr": "5000000.00",
                "is_commercially_registered": True,
                "kyc_notes": "Standard KYC.",
            }
        },
        "registry_records": {
            "ACC-S1": {
                "evidence_id": "REGISTRY-ACC-S1",
                "account_id": "ACC-S1",
                "entity_name": "Stale Traders",
                "is_registered": False,
                "registry_type": "MERCHANT",
                "registry_status": "EXPIRED",
                "registered_since": "2018-05-01",
            }
        },
    }
    alert = Alert(
        alert_id="ALT-GAP-01",
        rule_name="SCATTER_GATHER",
        root_account="ACC-S1",
        network_accounts=["ACC-X1", "ACC-X2"],
        total_amount_inr=Decimal("600000.00"),
        risk_level=RiskLevel.HIGH,
    )
    tok = bank_records.set_eval_case_overlay(overlay)
    try:
        st = await run_rule_engine(alert, thread_id="thr-p7-missing-data")
    finally:
        bank_records.reset_eval_case_overlay(tok)

    assert st.worksheet is not None
    assert st.worksheet.recommended_disposition == DispositionDecision.REQUEST_INFO
    joined_missing = " ".join(st.worksheet.missing_evidence)
    assert "EXPIRED" in joined_missing and "TXN-EXT-1" in joined_missing


@pytest.mark.asyncio
async def test_aggregate_root_flow_metric_deduplicates_shared_edges_and_conservation_tool() -> None:
    """Two-tier diamond sharing final edge `T2 -> DEST` must NOT double-count consolidated inflow."""
    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    txns = [
        graph_math.Txn("T1", "ROOT", "M1", Decimal("300000.00"), t0),
        graph_math.Txn("T2", "ROOT", "M2", Decimal("300000.00"), t0 + timedelta(hours=1)),
        graph_math.Txn("T3", "M1", "HUB", Decimal("285000.00"), t0 + timedelta(days=1)),
        graph_math.Txn("T4", "M2", "HUB", Decimal("285000.00"), t0 + timedelta(days=1, hours=1)),
        # Shared terminal edge: 552,000 total (8.00% overall retention across 600,000 outflow)
        graph_math.Txn("T5", "HUB", "DEST", Decimal("552000.00"), t0 + timedelta(days=2)),
    ]
    params = graph_math.GraphParams(
        time_window_days=14, max_hops=4, amount_tolerance=Decimal("0.10"), min_intermediaries=2
    )
    rules = SuspicionRules(
        scatter_gather_min_nodes=3,
        rapid_layering_max_days=7,
        rapid_layering_min_nodes=4,
        fee_skim_min_ratio=Decimal("0.05"),
    )
    limits = GraphLimits(max_raw_paths=50, max_paths_returned=20, anchor_lookback_days=1)
    run = graph_math.find_candidate_paths(txns, "ROOT", params, rules, limits)

    agg = run.stats["aggregate_root_flow"]
    assert agg["aggregate_outflow_inr"] == "600000.00"
    assert agg["aggregate_consolidated_inr"] == "552000.00"
    assert agg["aggregate_net_difference_inr"] == "48000.00"
    assert agg["aggregate_retention_pct"] == "8.00"
    assert agg["unique_edge_count"] == 5

    multi = [p for p in run.paths if p.hop_count >= 2]
    cons = graph_math.flow_conservation(
        multi, Decimal("0.10"), Structuring(threshold_inr=Decimal("1000000.00"), floor_inr=Decimal("800000.00"))
    )
    assert cons.aggregate_outflow_inr == Decimal("600000.00")
    assert cons.aggregate_consolidated_inr == Decimal("552000.00")
    assert cons.aggregate_net_difference_inr == Decimal("48000.00")
    assert cons.aggregate_retention_pct == Decimal("8.00")
    # Raw per-path sum would have double-counted HUB -> DEST as 1,104,000.00!
    assert cons.total_out > cons.aggregate_consolidated_inr

    # Verify MCP tool exposes aggregate fields and c0_fixed calls compute_flow_conservation
    mcp_cons = await call_mcp_tool(
        "graph-engine",
        "compute_flow_conservation",
        {
            "paths": [
                {
                    "path_id": p.path_id,
                    "nodes": list(p.nodes),
                    "edge_tx_ids": list(p.edge_tx_ids),
                    "total_outflow_inr": str(p.total_outflow_inr),
                    "total_consolidated_inr": str(p.total_consolidated_inr),
                    "net_difference_inr": str(p.net_difference_inr),
                    "retention_pct": str(p.retention_pct),
                    "hop_count": p.hop_count,
                    "time_span_days": str(p.time_span_days),
                    "amount_leaked_ratio": str(p.amount_leaked_ratio),
                    "is_suspicious": p.is_suspicious,
                    "suspicion_reason": p.suspicion_reason,
                }
                for p in multi
            ],
            "amount_tolerance": "0.10",
        },
    )
    assert mcp_cons["aggregate_outflow_inr"] == "600000.00"
    assert mcp_cons["aggregate_consolidated_inr"] == "552000.00"

    alert = Alert(
        alert_id="ALT-2026-0412",
        rule_name="SCATTER_GATHER",
        root_account="ACC-IND-1042",
        total_amount_inr=Decimal("900000.00"),
        risk_level=RiskLevel.HIGH,
    )
    c0_st = await run_fixed_pipeline(alert, thread_id="thr-p7-c0-cons")
    assert any(k.endswith("-CONS") for k in c0_st.evidence_registry)


@pytest.mark.asyncio
async def test_dev_forged_registry_and_missing_kyc_cases_zero_false_closes() -> None:
    """Sanity check on dev split ONLY (`data/golden_v2/dev/`): 0 false closes on forged-registry / missing-KYC."""
    dev_dir = Path("data/golden_v2/dev")
    targets = []
    for p in sorted(dev_dir.glob("CASE-*.json")):
        rec = json.loads(p.read_text(encoding="utf-8"))
        if rec.get("family") in ("layering_benign_cover.shell_valid_gst", "incomplete_data.missing_kyc"):
            targets.append(rec)
    assert len(targets) >= 4

    for rec in targets[:6]:
        alert = Alert(
            alert_id=rec["alert_id"],
            rule_name=rec.get("rule_name", "SCATTER_GATHER"),
            root_account=rec["root_account"],
            network_accounts=rec["network_accounts"],
            total_amount_inr=Decimal(str(rec["total_amount_inr"])),
            risk_level=RiskLevel.HIGH,
        )
        tok = bank_records.set_eval_case_overlay(rec)
        try:
            st = await run_rule_engine(alert, thread_id=f"thr-p7-dev-{rec['case_id']}")
        finally:
            bank_records.reset_eval_case_overlay(tok)
        assert st.worksheet is not None
        assert st.worksheet.recommended_disposition != DispositionDecision.CLOSE_BENIGN, (
            f"Dev {rec['case_id']} ({rec['family']}) falsely closed benign!"
        )
