"""T1: Graph Determinism & Decimal Accuracy Tests"""
import pytest
from datetime import datetime, timedelta
from src.mcp_servers.graph_engine import (
    FindCandidateFlowsInput,
    FlowConservationInput,
    CompareGraphRunsInput,
    TransactionEdge,
    find_candidate_fund_flows,
    compute_flow_conservation,
    compare_graph_runs,
)


def _fn(tool):
    return getattr(tool, "fn", tool)


@pytest.mark.asyncio
async def test_staggered_day11_recovery():
    """Initial 7-day scan misses Day-11 consolidation; expanding to 14 days recovers full path."""
    base = datetime(2026, 9, 1, 10, 0, 0)
    txs = [
        TransactionEdge(
            tx_id="TXN-8801",
            sender="ACC-IND-1042",
            receiver="ACC-IND-2011",
            amount_inr=900000.00,
            timestamp=base.isoformat() + "Z",
        ),
        TransactionEdge(
            tx_id="TXN-8891",
            sender="ACC-IND-2011",
            receiver="ACC-IND-9001",
            amount_inr=828000.00,
            timestamp=(base + timedelta(days=11)).isoformat() + "Z",
        ),
    ]

    run_7d = await _fn(find_candidate_fund_flows)(
        FindCandidateFlowsInput(
            root_account="ACC-IND-1042",
            transactions=txs,
            time_window_days=7,
            max_hops=3,
            amount_tolerance=0.10,
            anchor_date=base.isoformat() + "Z",
        )
    )
    assert run_7d.status == "ok"
    # Only 1-hop outbound leg visible in 7-day window
    assert all(p.hop_count == 1 for p in run_7d.paths)

    run_14d = await _fn(find_candidate_fund_flows)(
        FindCandidateFlowsInput(
            root_account="ACC-IND-1042",
            transactions=txs,
            time_window_days=14,
            max_hops=4,
            amount_tolerance=0.15,
            anchor_date=base.isoformat() + "Z",
        )
    )
    assert run_14d.status == "ok"
    two_hop = [p for p in run_14d.paths if p.hop_count == 2]
    assert len(two_hop) == 1
    assert two_hop[0].total_outflow_inr == "900000.00"
    assert two_hop[0].total_consolidated_inr == "828000.00"
    assert two_hop[0].net_difference_inr == "72000.00"
    assert two_hop[0].retention_pct == "8.00"


@pytest.mark.asyncio
async def test_policy_bounds_rejection():
    """Rejects max_hops=6 or time_window_days=365 with POLICY_BOUNDS_EXCEEDED."""
    res = await _fn(find_candidate_fund_flows)(
        FindCandidateFlowsInput(
            root_account="ACC-IND-1042",
            transactions=[],
            time_window_days=14,
            max_hops=6,
            amount_tolerance=0.10,
        )
    )
    assert res.status == "error"
    assert res.error_code == "POLICY_BOUNDS_EXCEEDED"


@pytest.mark.asyncio
async def test_flow_conservation_decimal_accuracy():
    base = datetime(2026, 9, 1, 10, 0, 0)
    txs = [
        TransactionEdge(tx_id="TX-1", sender="A", receiver="B", amount_inr=900000.00, timestamp=base.isoformat() + "Z"),
        TransactionEdge(tx_id="TX-2", sender="B", receiver="C", amount_inr=828000.00, timestamp=(base + timedelta(days=2)).isoformat() + "Z"),
    ]
    res = await _fn(find_candidate_fund_flows)(
        FindCandidateFlowsInput(root_account="A", transactions=txs, time_window_days=7, max_hops=3, amount_tolerance=0.10)
    )
    two_hop = [p for p in res.paths if p.hop_count == 2]
    cons = await _fn(compute_flow_conservation)(FlowConservationInput(paths=two_hop, amount_tolerance=0.10))
    assert cons.total_in_inr == "900000.00"
    assert cons.total_out_inr == "828000.00"
    assert cons.net_difference_inr == "72000.00"
    assert cons.conservation_satisfied is True
