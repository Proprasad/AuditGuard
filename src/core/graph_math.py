"""
Deterministic fund-flow graph mathematics (pure, `decimal.Decimal` only, `nx.MultiDiGraph`).

Parallel transfers between the same account pair are preserved individually as multigraph edges and
aggregated per hop with exact Decimal sums and complete tx-ID lists. Path / calculation identifiers are
SHA-256 derived from sorted transaction IDs so identical evidence always yields identical IDs.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

import networkx as nx

from src.core.canonical import CENT, RATIO_Q, canonical_json, canonical_sha256, dec_str, to_decimal, to_money
from src.core.policy import GraphLimits, Structuring, SuspicionRules

_DAY_SECONDS = Decimal(86400)
_DAYS_Q = Decimal("0.01")
_HUNDRED = Decimal(100)


@dataclass(frozen=True)
class Txn:
    tx_id: str
    sender: str
    receiver: str
    amount: Decimal
    timestamp: datetime
    memo: str | None = None


@dataclass(frozen=True)
class GraphParams:
    time_window_days: int
    max_hops: int
    amount_tolerance: Decimal
    min_intermediaries: int
    anchor: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "time_window_days": self.time_window_days,
            "max_hops": self.max_hops,
            "amount_tolerance": dec_str(self.amount_tolerance),
            "min_intermediaries": self.min_intermediaries,
            "anchor": self.anchor.isoformat() if self.anchor else None,
        }


@dataclass(frozen=True)
class PathMetrics:
    path_id: str
    nodes: tuple[str, ...]
    edge_tx_ids: tuple[str, ...]
    total_outflow_inr: Decimal
    total_consolidated_inr: Decimal
    net_difference_inr: Decimal
    retention_pct: Decimal
    amount_leaked_ratio: Decimal
    hop_count: int
    time_span_days: Decimal
    is_suspicious: bool
    suspicion_reason: str


@dataclass(frozen=True)
class GraphRun:
    calc_id: str
    paths: tuple[PathMetrics, ...]
    stats: dict[str, Any]
    params_used: dict[str, Any]


@dataclass(frozen=True)
class Conservation:
    conservation_satisfied: bool
    total_in: Decimal
    total_out: Decimal
    net_difference: Decimal
    leakage_ratio: Decimal
    structuring_detected: bool
    structuring_reason: str


# --------------------------------------------------------------------------------------------------
def build_multigraph(
    txns: Iterable[Txn], window_days: int, anchor: datetime | None, lookback_days: int
) -> nx.MultiDiGraph:
    graph: nx.MultiDiGraph = nx.MultiDiGraph()
    ordered = sorted(txns, key=lambda t: (t.timestamp, t.tx_id))
    if not ordered:
        return graph
    base = anchor or ordered[0].timestamp
    lower = base - timedelta(days=lookback_days)
    upper = base + timedelta(days=window_days)
    for txn in ordered:
        if lower <= txn.timestamp <= upper:
            graph.add_edge(txn.sender, txn.receiver, key=txn.tx_id, tx=txn)
    return graph


def hop_transactions(graph: nx.MultiDiGraph, sender: str, receiver: str) -> list[Txn]:
    data = graph.get_edge_data(sender, receiver) or {}
    return sorted((attrs["tx"] for attrs in data.values()), key=lambda t: (t.timestamp, t.tx_id))


def _sum(items: Iterable[Txn]) -> Decimal:
    return sum((t.amount for t in items), Decimal("0.00"))


def _span_days(items: Sequence[Txn]) -> Decimal:
    if len(items) < 2:
        return Decimal("0.00")
    stamps = [t.timestamp for t in items]
    seconds = Decimal(int((max(stamps) - min(stamps)).total_seconds()))
    return (seconds / _DAY_SECONDS).quantize(_DAYS_Q)


def _classify(
    leaked: Decimal,
    span: Decimal,
    node_count: int,
    fan_in: int,
    params: GraphParams,
    rules: SuspicionRules,
    retention: Decimal,
) -> tuple[bool, str]:
    hops = node_count - 1
    if (
        leaked <= params.amount_tolerance
        and node_count >= rules.scatter_gather_min_nodes
        and fan_in >= params.min_intermediaries
    ):
        return True, f"scatter_gather: {hops} hops, {retention}% retained"
    if span <= Decimal(rules.rapid_layering_max_days) and node_count >= rules.rapid_layering_min_nodes:
        return True, f"rapid_layering: {hops} hops in {span} days"
    if leaked > rules.fee_skim_min_ratio and node_count >= rules.scatter_gather_min_nodes:
        return True, f"fee_skimming: {retention}% retained across chain"
    return False, "none"


def compute_path_metrics(
    graph: nx.MultiDiGraph,
    path: Sequence[str],
    params: GraphParams,
    rules: SuspicionRules,
    fan_in: int,
) -> PathMetrics:
    hops = [hop_transactions(graph, u, v) for u, v in zip(path, path[1:], strict=False)]
    outflow = _sum(hops[0])
    consolidated = _sum(hops[-1])
    net = (outflow - consolidated).quantize(CENT)
    all_txns = [t for hop in hops for t in hop]
    if outflow > 0:
        leaked = (abs(net) / outflow).quantize(RATIO_Q)
        retention = (net / outflow * _HUNDRED).quantize(CENT)
    else:
        leaked, retention = Decimal("0.0000"), Decimal("0.00")
    span = _span_days(all_txns)
    suspicious, reason = _classify(leaked, span, len(path), fan_in, params, rules, retention)
    path_id = "PATH-" + canonical_sha256({"nodes": list(path), "tx": sorted(t.tx_id for t in all_txns)})[:12].upper()
    return PathMetrics(
        path_id=path_id,
        nodes=tuple(path),
        edge_tx_ids=tuple(t.tx_id for t in all_txns),
        total_outflow_inr=outflow,
        total_consolidated_inr=consolidated,
        net_difference_inr=net,
        retention_pct=retention,
        amount_leaked_ratio=leaked,
        hop_count=len(path) - 1,
        time_span_days=span,
        is_suspicious=suspicious,
        suspicion_reason=reason,
    )


def _enumerate_paths(graph: nx.MultiDiGraph, root: str, max_hops: int, max_raw: int) -> list[list[str]]:
    simple = nx.DiGraph()
    simple.add_edges_from(graph.edges())
    raw: list[list[str]] = []
    for target in sorted(n for n in simple.nodes if n != root):
        for path in nx.all_simple_paths(simple, root, target, cutoff=max_hops):
            raw.append(path)
            if len(raw) >= max_raw:
                return raw
    return raw


def find_candidate_paths(
    txns: Sequence[Txn],
    root: str,
    params: GraphParams,
    rules: SuspicionRules,
    limits: GraphLimits,
) -> GraphRun:
    graph = build_multigraph(txns, params.time_window_days, params.anchor, limits.anchor_lookback_days)
    params_used = params.as_dict()
    tx_ids = sorted(k for _, _, k in graph.edges(keys=True))
    calc_id = "CALC-" + canonical_sha256({"root": root, "tx": tx_ids, "params": params_used})[:12].upper()
    stats: dict[str, Any] = {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "accounts": sorted(graph.nodes()),
    }
    if root not in graph:
        stats.update({"total_paths_found": 0, "suspicious_paths": 0, "note": "root_account_not_in_window"})
        return GraphRun(calc_id, (), stats, params_used)

    raw_paths = _enumerate_paths(graph, root, params.max_hops, limits.max_raw_paths)
    intermediaries: dict[str, set[str]] = defaultdict(set)
    for path in raw_paths:
        if len(path) >= 3:
            intermediaries[path[-1]].update(path[1:-1])
    metrics = [compute_path_metrics(graph, p, params, rules, len(intermediaries.get(p[-1], ()))) for p in raw_paths]
    metrics.sort(key=lambda m: (-int(m.is_suspicious), -m.hop_count, m.path_id))
    stats["total_paths_found"] = len(metrics)
    stats["suspicious_paths"] = sum(1 for m in metrics if m.is_suspicious)
    return GraphRun(calc_id, tuple(metrics[: limits.max_paths_returned]), stats, params_used)


def flow_conservation(paths: Sequence[PathMetrics], tolerance: Decimal, structuring: Structuring) -> Conservation:
    if not paths:
        zero = Decimal("0.00")
        return Conservation(True, zero, zero, zero, Decimal("0.0000"), False, "no_paths")
    total_in = to_money(_dsum(p.total_outflow_inr for p in paths))
    total_out = to_money(_dsum(p.total_consolidated_inr for p in paths))
    net = abs(total_in - total_out).quantize(CENT)
    leakage = (net / total_in).quantize(RATIO_Q) if total_in > 0 else Decimal("0.0000")
    near_threshold = [p for p in paths if structuring.floor_inr <= p.total_outflow_inr < structuring.threshold_inr]
    reason = (
        f"{len(near_threshold)} paths just below INR {structuring.threshold_inr:,.2f} threshold"
        if near_threshold
        else "none"
    )
    return Conservation(
        leakage <= to_decimal(tolerance, RATIO_Q),
        total_in,
        total_out,
        net,
        leakage,
        bool(near_threshold),
        reason,
    )


def _dsum(values: Iterable[Decimal]) -> Decimal:
    return sum(values, Decimal("0.00"))


def compare_runs(run_a: GraphRun, run_b: GraphRun) -> dict[str, Any]:
    ids_a = {p.path_id for p in run_a.paths}
    ids_b = {p.path_id for p in run_b.paths}
    keys = set(run_a.params_used) | set(run_b.params_used)
    delta = {
        k: {"before": run_a.params_used.get(k), "after": run_b.params_used.get(k)}
        for k in sorted(keys)
        if run_a.params_used.get(k) != run_b.params_used.get(k)
    }
    susp_a = sum(1 for p in run_a.paths if p.is_suspicious)
    susp_b = sum(1 for p in run_b.paths if p.is_suspicious)
    new_paths = sorted(ids_b - ids_a)
    if susp_b > susp_a:
        recommendation = "accept_replan: wider parameters reveal more suspicious paths"
    elif susp_b == susp_a and new_paths:
        recommendation = "accept_replan: different paths found, review for coverage"
    else:
        recommendation = "reject_replan: no improvement in suspicious path detection"
    return {
        "new_paths_in_b": new_paths,
        "dropped_paths_from_a": sorted(ids_a - ids_b),
        "param_delta": delta,
        "recommendation": recommendation,
        "signature": canonical_json(delta),
    }
