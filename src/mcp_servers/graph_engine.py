"""
MCP Server: graph-engine (COMPUTE)
Deterministic NetworkX fund-flow analysis with Python Decimal arithmetic.
Tools: find_candidate_fund_flows, compute_flow_conservation, compare_graph_runs
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Optional

import networkx as nx
from fastmcp import FastMCP
from pydantic import BaseModel, Field

mcp = FastMCP(
    name="graph-engine",
    instructions="Compute-only server for deterministic fund-flow graph analysis. "
                 "Finds candidate layering paths, computes Decimal flow conservation, "
                 "and compares graph runs for replanning.",
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class TransactionEdge(BaseModel):
    tx_id: str
    sender: str
    receiver: str
    amount_inr: float
    timestamp: str
    memo: Optional[str] = None


class FindCandidateFlowsInput(BaseModel):
    root_account: str
    transactions: list[TransactionEdge]
    time_window_days: int = 14
    max_hops: int = 5
    amount_tolerance: float = 0.05
    min_intermediaries: int = 2
    anchor_date: Optional[str] = None


class FundFlowPathResult(BaseModel):
    path_id: str
    nodes: list[str]
    edge_tx_ids: list[str]
    total_amount: float
    total_outflow_inr: str
    total_consolidated_inr: str
    net_difference_inr: str
    retention_pct: str
    hop_count: int
    time_span_days: float
    amount_leaked_pct: float
    is_suspicious: bool
    suspicion_reason: str


class FindCandidateFlowsOutput(BaseModel):
    status: str = "ok"
    calc_id: str = Field(default_factory=lambda: f"CALC-{uuid.uuid4().hex[:8].upper()}")
    error_code: Optional[str] = None
    message: Optional[str] = None
    paths: list[FundFlowPathResult] = Field(default_factory=list)
    graph_stats: dict[str, Any] = Field(default_factory=dict)
    params_used: dict[str, Any] = Field(default_factory=dict)


class FlowConservationInput(BaseModel):
    paths: list[FundFlowPathResult]
    amount_tolerance: float = 0.05


class FlowConservationOutput(BaseModel):
    conservation_satisfied: bool
    total_in: float
    total_out: float
    total_in_inr: str
    total_out_inr: str
    net_difference_inr: str
    leakage_pct: float
    structuring_detected: bool
    structuring_reason: str


class CompareGraphRunsInput(BaseModel):
    run_a: FindCandidateFlowsOutput
    run_b: FindCandidateFlowsOutput


class CompareGraphRunsOutput(BaseModel):
    new_paths_in_b: list[str]
    dropped_paths_from_a: list[str]
    param_delta: dict[str, Any]
    recommendation: str


# ---------------------------------------------------------------------------
# Policy Bounds Validation
# ---------------------------------------------------------------------------
def _validate_bounds(params: FindCandidateFlowsInput) -> tuple[bool, str]:
    if not (1 <= params.time_window_days <= 30):
        return False, f"time_window_days={params.time_window_days} outside [1, 30]"
    if not (2 <= params.max_hops <= 5):
        return False, f"max_hops={params.max_hops} outside [2, 5]"
    if not (0.01 <= params.amount_tolerance <= 0.25):
        return False, f"amount_tolerance={params.amount_tolerance} outside [0.01, 0.25]"
    if not (2 <= params.min_intermediaries <= 10):
        return False, f"min_intermediaries={params.min_intermediaries} outside [2, 10]"
    return True, ""


# ---------------------------------------------------------------------------
# Graph Analysis Engine (Decimal-accurate)
# ---------------------------------------------------------------------------
def _parse_ts(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return datetime.utcnow()


def _build_graph(
    transactions: list[TransactionEdge],
    time_window_days: int,
    anchor_date: Optional[str] = None,
) -> nx.DiGraph:
    G = nx.DiGraph()
    anchor = _parse_ts(anchor_date) if anchor_date else None
    if anchor is None and transactions:
        anchor = min(_parse_ts(tx.timestamp) for tx in transactions)
    if anchor is None:
        anchor = datetime.utcnow()

    upper_bound = anchor + timedelta(days=time_window_days)

    for tx in transactions:
        ts = _parse_ts(tx.timestamp)
        if anchor - timedelta(days=1) <= ts <= upper_bound:
            G.add_edge(
                tx.sender,
                tx.receiver,
                weight=Decimal(str(tx.amount_inr)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
                tx_id=tx.tx_id,
                timestamp=tx.timestamp,
                memo=tx.memo or "",
            )
    return G


def _compute_path_metrics(
    G: nx.DiGraph,
    path: list[str],
    amount_tolerance: float,
) -> FundFlowPathResult:
    edge_tx_ids: list[str] = []
    amounts: list[Decimal] = []
    timestamps: list[datetime] = []

    for i in range(len(path) - 1):
        u, v = path[i], path[i + 1]
        if G.has_edge(u, v):
            edge_data = G[u][v]
            edge_tx_ids.append(edge_data.get("tx_id", ""))
            amounts.append(edge_data.get("weight", Decimal("0.00")))
            ts_str = edge_data.get("timestamp", "")
            if ts_str:
                timestamps.append(_parse_ts(ts_str))

    if not amounts:
        return FundFlowPathResult(
            path_id=uuid.uuid4().hex[:8],
            nodes=path,
            edge_tx_ids=[],
            total_amount=0.0,
            total_outflow_inr="0.00",
            total_consolidated_inr="0.00",
            net_difference_inr="0.00",
            retention_pct="0.00",
            hop_count=len(path) - 1,
            time_span_days=0.0,
            amount_leaked_pct=0.0,
            is_suspicious=False,
            suspicion_reason="no_transactions",
        )

    outflow = amounts[0]
    consolidated = amounts[-1]
    net_diff = (outflow - consolidated).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    if outflow > Decimal("0"):
        retention_pct = ((net_diff / outflow) * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        leaked_ratio = float(abs(net_diff) / outflow)
    else:
        retention_pct = Decimal("0.00")
        leaked_ratio = 0.0

    time_span_days = float((max(timestamps) - min(timestamps)).days) if len(timestamps) >= 2 else 0.0

    is_suspicious = False
    reason = "none"
    if leaked_ratio <= amount_tolerance and len(path) >= 3:
        is_suspicious = True
        reason = f"scatter_gather: {len(path)-1} hops, {retention_pct}% retained"
    elif time_span_days <= 7 and len(path) >= 4:
        is_suspicious = True
        reason = f"rapid_layering: {len(path)-1} hops in {time_span_days:.0f} days"
    elif leaked_ratio > 0.05 and len(path) >= 3:
        is_suspicious = True
        reason = f"fee_skimming: {retention_pct}% retained across chain"

    return FundFlowPathResult(
        path_id=uuid.uuid4().hex[:8],
        nodes=path,
        edge_tx_ids=edge_tx_ids,
        total_amount=float(outflow),
        total_outflow_inr=str(outflow),
        total_consolidated_inr=str(consolidated),
        net_difference_inr=str(net_diff),
        retention_pct=str(retention_pct),
        hop_count=len(path) - 1,
        time_span_days=time_span_days,
        amount_leaked_pct=leaked_ratio,
        is_suspicious=is_suspicious,
        suspicion_reason=reason,
    )


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------
@mcp.tool()
async def find_candidate_fund_flows(params: FindCandidateFlowsInput) -> FindCandidateFlowsOutput:
    """
    Build a directed transaction graph and find candidate layering paths
    from the root account within policy-bounded parameters.
    """
    ok, err_msg = _validate_bounds(params)
    if not ok:
        return FindCandidateFlowsOutput(
            status="error",
            error_code="POLICY_BOUNDS_EXCEEDED",
            message=err_msg,
        )

    G = _build_graph(params.transactions, params.time_window_days, params.anchor_date)
    if params.root_account not in G.nodes():
        return FindCandidateFlowsOutput(
            status="ok",
            paths=[],
            graph_stats={"nodes": G.number_of_nodes(), "edges": G.number_of_edges(), "note": "root_account_not_in_window"},
            params_used=params.model_dump(exclude={"transactions"}),
        )

    raw_paths: list[list[str]] = []
    for target in G.nodes():
        if target == params.root_account:
            continue
        try:
            for path in nx.all_simple_paths(G, params.root_account, target, cutoff=params.max_hops):
                raw_paths.append(path)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass

    path_results = [_compute_path_metrics(G, p, params.amount_tolerance) for p in raw_paths[:50]]
    path_results.sort(key=lambda p: (-int(p.is_suspicious), -p.hop_count))

    return FindCandidateFlowsOutput(
        status="ok",
        paths=path_results[:20],
        graph_stats={
            "nodes": G.number_of_nodes(),
            "edges": G.number_of_edges(),
            "total_paths_found": len(path_results),
            "suspicious_paths": sum(1 for p in path_results if p.is_suspicious),
            "accounts": list(G.nodes()),
        },
        params_used={
            "time_window_days": params.time_window_days,
            "max_hops": params.max_hops,
            "amount_tolerance": params.amount_tolerance,
            "min_intermediaries": params.min_intermediaries,
        },
    )


@mcp.tool()
async def compute_flow_conservation(params: FlowConservationInput) -> FlowConservationOutput:
    """Test whether fund amounts are conserved across candidate paths using Decimal math."""
    if not params.paths:
        return FlowConservationOutput(
            conservation_satisfied=True,
            total_in=0.0,
            total_out=0.0,
            total_in_inr="0.00",
            total_out_inr="0.00",
            net_difference_inr="0.00",
            leakage_pct=0.0,
            structuring_detected=False,
            structuring_reason="no_paths",
        )

    total_in = sum((Decimal(p.total_outflow_inr) for p in params.paths), Decimal("0.00"))
    total_out = sum((Decimal(p.total_consolidated_inr) for p in params.paths), Decimal("0.00"))
    net_diff = abs(total_in - total_out).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    leakage_pct = float(net_diff / total_in) if total_in > 0 else 0.0

    threshold = Decimal("1000000.00")
    suspicious_amounts = [
        p.total_outflow_inr
        for p in params.paths
        if Decimal("800000.00") <= Decimal(p.total_outflow_inr) < threshold
    ]

    return FlowConservationOutput(
        conservation_satisfied=leakage_pct <= params.amount_tolerance,
        total_in=float(total_in),
        total_out=float(total_out),
        total_in_inr=str(total_in),
        total_out_inr=str(total_out),
        net_difference_inr=str(net_diff),
        leakage_pct=leakage_pct,
        structuring_detected=bool(suspicious_amounts),
        structuring_reason=(
            f"{len(suspicious_amounts)} paths just below INR 10,00,000 threshold"
            if suspicious_amounts
            else "none"
        ),
    )


@mcp.tool()
async def compare_graph_runs(params: CompareGraphRunsInput) -> CompareGraphRunsOutput:
    """Compare two graph analysis runs to evaluate replanning improvement."""
    ids_a = {p.path_id for p in params.run_a.paths}
    ids_b = {p.path_id for p in params.run_b.paths}

    param_delta = {
        k: {"before": params.run_a.params_used.get(k), "after": params.run_b.params_used.get(k)}
        for k in set(params.run_a.params_used) | set(params.run_b.params_used)
        if params.run_a.params_used.get(k) != params.run_b.params_used.get(k)
    }

    suspicious_b = sum(1 for p in params.run_b.paths if p.is_suspicious)
    suspicious_a = sum(1 for p in params.run_a.paths if p.is_suspicious)

    if suspicious_b > suspicious_a:
        recommendation = "accept_replan: wider parameters reveal more suspicious paths"
    elif suspicious_b == suspicious_a and len(ids_b - ids_a) > 0:
        recommendation = "accept_replan: different paths found, review for coverage"
    else:
        recommendation = "reject_replan: no improvement in suspicious path detection"

    return CompareGraphRunsOutput(
        new_paths_in_b=list(ids_b - ids_a),
        dropped_paths_from_a=list(ids_a - ids_b),
        param_delta=param_delta,
        recommendation=recommendation,
    )


if __name__ == "__main__":
    port = int(os.getenv("MCP_GRAPH_ENGINE_PORT", "8011"))
    mcp.run(transport="streamable-http", host="0.0.0.0", port=port)
