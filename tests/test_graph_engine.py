"""T1: Graph determinism & Decimal accuracy via the real graph-engine MCP tool (exact Decimal I/O)."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from src.mcp_servers.client import call_mcp_tool
from src.mcp_servers.graph_engine import FindCandidateFlowsInput, FlowConservationInput, TransactionEdge

BASE = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)


async def _call(tool: str, model) -> dict:
    """Invoke the graph-engine tool through the real MCP protocol (Decimals travel as exact strings)."""
    return await call_mcp_tool("graph-engine", tool, model.model_dump(mode="json"))


def _edge(tx_id: str, sender: str, receiver: str, amount: str, days: int) -> TransactionEdge:
    return TransactionEdge(
        tx_id=tx_id,
        sender=sender,
        receiver=receiver,
        amount_inr=amount,
        timestamp=(BASE + timedelta(days=days)).isoformat(),
    )


@pytest.mark.asyncio
async def test_staggered_day11_recovery():
    """Initial 7-day scan misses Day-11 consolidation; expanding to 14 days recovers the full path."""
    txs = [
        _edge("TXN-8801", "ACC-IND-1042", "ACC-IND-2011", "900000.00", 0),
        _edge("TXN-8891", "ACC-IND-2011", "ACC-IND-9001", "828000.00", 11),
    ]
    common = {"root_account": "ACC-IND-1042", "transactions": txs, "anchor_date": BASE.isoformat()}

    run_7d = await _call(
        "find_candidate_fund_flows",
        FindCandidateFlowsInput(**common, time_window_days=7, max_hops=3, amount_tolerance=Decimal("0.10")),
    )
    assert run_7d["status"] == "ok"
    assert all(p["hop_count"] == 1 for p in run_7d["paths"])

    run_14d = await _call(
        "find_candidate_fund_flows",
        FindCandidateFlowsInput(**common, time_window_days=14, max_hops=4, amount_tolerance=Decimal("0.15")),
    )
    two_hop = [p for p in run_14d["paths"] if p["hop_count"] == 2]
    assert len(two_hop) == 1
    assert Decimal(two_hop[0]["total_outflow_inr"]) == Decimal("900000.00")
    assert Decimal(two_hop[0]["total_consolidated_inr"]) == Decimal("828000.00")
    assert Decimal(two_hop[0]["net_difference_inr"]) == Decimal("72000.00")
    assert Decimal(two_hop[0]["retention_pct"]) == Decimal("8.00")
    assert run_14d["calc_id"].startswith("CALC-") and two_hop[0]["path_id"].startswith("PATH-")


@pytest.mark.asyncio
async def test_policy_bounds_rejection():
    res = await _call(
        "find_candidate_fund_flows",
        FindCandidateFlowsInput(
            root_account="ACC-IND-1042",
            transactions=[],
            time_window_days=14,
            max_hops=6,
            amount_tolerance=Decimal("0.10"),
        ),
    )
    assert res["status"] == "error" and res["error_code"] == "POLICY_BOUNDS_EXCEEDED"


@pytest.mark.asyncio
async def test_flow_conservation_decimal_accuracy():
    txs = [_edge("TX-1", "A", "B", "900000.00", 0), _edge("TX-2", "B", "C", "828000.00", 2)]
    res = await _call(
        "find_candidate_fund_flows",
        FindCandidateFlowsInput(
            root_account="A",
            transactions=txs,
            time_window_days=7,
            max_hops=3,
            amount_tolerance=Decimal("0.10"),
        ),
    )
    two_hop = [p for p in res["paths"] if p["hop_count"] == 2]
    cons = await _call(
        "compute_flow_conservation", FlowConservationInput(paths=two_hop, amount_tolerance=Decimal("0.10"))
    )
    assert Decimal(cons["total_in_inr"]) == Decimal("900000.00")
    assert Decimal(cons["total_out_inr"]) == Decimal("828000.00")
    assert Decimal(cons["net_difference_inr"]) == Decimal("72000.00")
    assert cons["conservation_satisfied"] is True
