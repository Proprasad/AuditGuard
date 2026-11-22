"""
MCP Server: graph-engine (COMPUTE). Thin FastMCP adapter over the pure `src.core.graph_math` engine.
Tools: find_candidate_fund_flows, compute_flow_conservation, compare_graph_runs
"""
from __future__ import annotations

import os
from typing import Any, Optional

from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from src.config import get_policy
from src.core import graph_math
from src.core.adapters import txn_from_record
from src.core.canonical import Money, Ratio, parse_utc_timestamp
from src.models import FundFlowPath

mcp = FastMCP(
    name="graph-engine",
    instructions="Compute-only server for deterministic fund-flow graph analysis. "
                 "Finds candidate layering paths, computes Decimal flow conservation, "
                 "and compares graph runs for replanning.",
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TransactionEdge(_Strict):
    tx_id: str
    sender: str
    receiver: str
    amount_inr: Money
    timestamp: str
    memo: Optional[str] = None


class FindCandidateFlowsInput(_Strict):
    root_account: str
    transactions: list[TransactionEdge]
    time_window_days: Optional[int] = None
    max_hops: Optional[int] = None
    amount_tolerance: Optional[Ratio] = None
    min_intermediaries: Optional[int] = None
    anchor_date: Optional[str] = None


class FindCandidateFlowsOutput(_Strict):
    status: str = "ok"
    calc_id: str = ""
    error_code: Optional[str] = None
    message: Optional[str] = None
    paths: list[FundFlowPath] = Field(default_factory=list)
    graph_stats: dict[str, Any] = Field(default_factory=dict)
    params_used: dict[str, Any] = Field(default_factory=dict)


class FlowConservationInput(_Strict):
    paths: list[FundFlowPath]
    amount_tolerance: Optional[Ratio] = None


class FlowConservationOutput(_Strict):
    status: str = "ok"
    conservation_satisfied: bool
    total_in_inr: Money
    total_out_inr: Money
    net_difference_inr: Money
    leakage_ratio: Ratio
    structuring_detected: bool
    structuring_reason: str


class CompareGraphRunsInput(_Strict):
    run_a: FindCandidateFlowsOutput
    run_b: FindCandidateFlowsOutput


class CompareGraphRunsOutput(_Strict):
    status: str = "ok"
    new_paths_in_b: list[str]
    dropped_paths_from_a: list[str]
    param_delta: dict[str, Any]
    recommendation: str


def _resolved_params(params: FindCandidateFlowsInput) -> graph_math.GraphParams:
    defaults = get_policy().default_graph_params()
    return graph_math.GraphParams(
        time_window_days=params.time_window_days if params.time_window_days is not None else defaults["time_window_days"],
        max_hops=params.max_hops if params.max_hops is not None else defaults["max_hops"],
        amount_tolerance=params.amount_tolerance if params.amount_tolerance is not None else defaults["amount_tolerance"],
        min_intermediaries=params.min_intermediaries if params.min_intermediaries is not None else defaults["min_intermediaries"],
        anchor=parse_utc_timestamp(params.anchor_date) if params.anchor_date else None,
    )


def _path_to_model(metrics: graph_math.PathMetrics) -> FundFlowPath:
    return FundFlowPath(
        path_id=metrics.path_id,
        nodes=list(metrics.nodes),
        edge_tx_ids=list(metrics.edge_tx_ids),
        total_outflow_inr=metrics.total_outflow_inr,
        total_consolidated_inr=metrics.total_consolidated_inr,
        net_difference_inr=metrics.net_difference_inr,
        retention_pct=metrics.retention_pct,
        hop_count=metrics.hop_count,
        time_span_days=metrics.time_span_days,
        amount_leaked_ratio=metrics.amount_leaked_ratio,
        is_suspicious=metrics.is_suspicious,
        suspicion_reason=metrics.suspicion_reason,
    )


def _metrics_from_model(path: FundFlowPath) -> graph_math.PathMetrics:
    return graph_math.PathMetrics(
        path_id=path.path_id, nodes=tuple(path.nodes), edge_tx_ids=tuple(path.edge_tx_ids),
        total_outflow_inr=path.total_outflow_inr, total_consolidated_inr=path.total_consolidated_inr,
        net_difference_inr=path.net_difference_inr, retention_pct=path.retention_pct,
        amount_leaked_ratio=path.amount_leaked_ratio, hop_count=path.hop_count,
        time_span_days=path.time_span_days, is_suspicious=path.is_suspicious, suspicion_reason=path.suspicion_reason,
    )


@mcp.tool()
async def find_candidate_fund_flows(params: FindCandidateFlowsInput) -> FindCandidateFlowsOutput:
    """Build a directed transaction multigraph and find candidate layering paths within policy bounds."""
    policy = get_policy()
    supplied = {
        k: getattr(params, k)
        for k in ("time_window_days", "max_hops", "amount_tolerance", "min_intermediaries")
        if getattr(params, k) is not None
    }
    violations = policy.validate_graph_params(supplied)
    if violations:
        return FindCandidateFlowsOutput(status="error", error_code="POLICY_BOUNDS_EXCEEDED", message="; ".join(violations))
    try:
        txns = [txn_from_record(t.model_dump()) for t in params.transactions]
        resolved = _resolved_params(params)
    except ValueError as exc:
        return FindCandidateFlowsOutput(status="error", error_code="INVALID_INPUT", message=str(exc))

    run = graph_math.find_candidate_paths(txns, params.root_account, resolved, policy.suspicion, policy.graph_limits)
    return FindCandidateFlowsOutput(
        status="ok",
        calc_id=run.calc_id,
        paths=[_path_to_model(p) for p in run.paths],
        graph_stats=run.stats,
        params_used=run.params_used,
    )


@mcp.tool()
async def compute_flow_conservation(params: FlowConservationInput) -> FlowConservationOutput:
    """Test whether fund amounts are conserved across candidate paths using Decimal math."""
    policy = get_policy()
    tolerance = params.amount_tolerance if params.amount_tolerance is not None else policy.graph_bounds.amount_tolerance.default
    result = graph_math.flow_conservation([_metrics_from_model(p) for p in params.paths], tolerance, policy.structuring)
    return FlowConservationOutput(
        conservation_satisfied=result.conservation_satisfied,
        total_in_inr=result.total_in,
        total_out_inr=result.total_out,
        net_difference_inr=result.net_difference,
        leakage_ratio=result.leakage_ratio,
        structuring_detected=result.structuring_detected,
        structuring_reason=result.structuring_reason,
    )


def _run_from_output(out: FindCandidateFlowsOutput) -> graph_math.GraphRun:
    return graph_math.GraphRun(
        calc_id=out.calc_id,
        paths=tuple(_metrics_from_model(p) for p in out.paths),
        stats=out.graph_stats,
        params_used=out.params_used,
    )


@mcp.tool()
async def compare_graph_runs(params: CompareGraphRunsInput) -> CompareGraphRunsOutput:
    """Compare two graph analysis runs to evaluate replanning improvement."""
    diff = graph_math.compare_runs(_run_from_output(params.run_a), _run_from_output(params.run_b))
    return CompareGraphRunsOutput(
        new_paths_in_b=diff["new_paths_in_b"],
        dropped_paths_from_a=diff["dropped_paths_from_a"],
        param_delta=diff["param_delta"],
        recommendation=diff["recommendation"],
    )


if __name__ == "__main__":
    port = int(os.getenv("MCP_GRAPH_ENGINE_PORT", "8011"))
    mcp.run(transport="streamable-http", host="0.0.0.0", port=port)  # noqa: S104 - container bind
