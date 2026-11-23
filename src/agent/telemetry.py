"""
Deterministic network flow summary (exact `Decimal` math, no floats, no silent date fallbacks).

Decomposed into small pure helpers; money/percent values are returned as fixed-point strings.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from src.core.adapters import is_registered
from src.core.canonical import CENT, dec_str, parse_utc_timestamp, to_money
from src.models import FundFlowPath

_ZERO = Decimal("0.00")
_PCT_Q = Decimal("0.1")
_HUNDRED = Decimal(100)
_MAX_TICKS_STEP_DIVISOR = 8


@dataclass(frozen=True)
class Roles:
    sources: frozenset[str]
    intermediaries: frozenset[str]
    destinations: frozenset[str]
    all_accounts: tuple[str, ...]

    def label(self, account: str) -> str:
        if account in self.sources:
            return "source"
        if account in self.intermediaries:
            return "intermediary"
        if account in self.destinations:
            return "destination"
        return "unknown"


def _amount(tx: Mapping[str, Any]) -> Decimal:
    return to_money(tx.get("amount_inr", "0"))


def _classify_roles(root: str, txns: Sequence[Mapping[str, Any]]) -> Roles:
    senders = {t["sender_account"] for t in txns if t.get("sender_account")}
    receivers = {t["receiver_account"] for t in txns if t.get("receiver_account")}
    accounts = sorted(senders | receivers | ({root} if root else set()))
    sources: set[str] = set()
    intermediaries: set[str] = set()
    destinations: set[str] = set()
    for acc in accounts:
        is_s, is_r = acc in senders, acc in receivers
        if is_s and is_r:
            intermediaries.add(acc)
        elif is_r:
            destinations.add(acc)
        else:
            sources.add(acc)
    if root in intermediaries and not sources:
        sources.add(root)
    return Roles(frozenset(sources), frozenset(intermediaries), frozenset(destinations), tuple(accounts))


def _sum_where(txns: Sequence[Mapping[str, Any]], predicate: Any) -> Decimal:
    return sum((_amount(t) for t in txns if predicate(t)), _ZERO)


def _flow_totals(
    root: str,
    txns: Sequence[Mapping[str, Any]],
    paths: Sequence[FundFlowPath],
    kyc_by_acc: Mapping[str, Mapping[str, Any]],
    roles: Roles,
) -> tuple[Decimal, Decimal, frozenset[str]]:
    out_from_root = _sum_where(txns, lambda t: t.get("sender_account") == root)
    in_to_root = _sum_where(txns, lambda t: t.get("receiver_account") == root)
    total_outflow = out_from_root if out_from_root > 0 else in_to_root

    multi_hop_dests = frozenset(p.nodes[-1] for p in paths if p.hop_count >= 2 and len(p.nodes) >= 3)
    if multi_hop_dests:
        consolidated = _sum_where(txns, lambda t: t.get("receiver_account") in multi_hop_dests)
    elif roles.destinations:
        consolidated = _sum_where(
            txns,
            lambda t: t.get("receiver_account") in roles.destinations and t.get("sender_account") != root,
        )
        if consolidated == 0 and is_registered(kyc_by_acc.get(root, {})):
            consolidated = out_from_root
    else:
        consolidated = _ZERO
    if total_outflow > 0 and consolidated > total_outflow:
        consolidated = total_outflow
    return total_outflow, consolidated, multi_hop_dests


def _timeline(
    root: str,
    txns: Sequence[Mapping[str, Any]],
    roles: Roles,
    multi_hop_dests: frozenset[str],
    consolidated: Decimal,
) -> tuple[int, list[dict[str, Any]]]:
    if not txns:
        return 0, []
    parsed = [(t, parse_utc_timestamp(t.get("timestamp"))) for t in txns]
    first_day = min(dt for _, dt in parsed).date()
    span_days = max(0, (max(dt for _, dt in parsed).date() - first_day).days)

    daily_out: dict[int, Decimal] = defaultdict(lambda: _ZERO)
    daily_cons: dict[int, Decimal] = defaultdict(lambda: _ZERO)
    for tx, dt in parsed:
        day = max(0, (dt.date() - first_day).days)
        amt = _amount(tx)
        if tx.get("sender_account") == root or tx.get("sender_account") in roles.sources:
            daily_out[day] += amt
        receiver = tx.get("receiver_account")
        if (multi_hop_dests and receiver in multi_hop_dests) or (
            not multi_hop_dests and receiver in roles.destinations and consolidated > 0
        ):
            daily_cons[day] += amt

    horizon = max(span_days, 1)
    step = 1 if horizon <= 10 else max(1, round(horizon / _MAX_TICKS_STEP_DIVISOR))
    ticks = list(range(0, horizon + 1, step))
    if ticks[-1] != horizon:
        ticks.append(horizon)

    points: list[dict[str, Any]] = []
    cum_out, cum_cons, last = _ZERO, _ZERO, -1
    for tick in ticks:
        for day in range(last + 1, tick + 1):
            cum_out += daily_out[day]
            cum_cons += daily_cons[day]
        last = tick
        shown_cons = min(cum_cons, cum_out) if cum_out > 0 else cum_cons
        points.append(
            {
                "day": tick,
                "label": f"Day {tick}",
                "cumulative_outflow_inr": dec_str(cum_out),
                "cumulative_consolidated_inr": dec_str(shown_cons),
            }
        )
    return span_days, points


def _finding(fid: str, icon: str, title: str, summary: str, severity: str) -> dict[str, Any]:
    return {
        "id": fid,
        "type": "deterministic",
        "icon": icon,
        "title": title,
        "summary": summary,
        "severity": severity,
    }


def _findings(
    roles: Roles,
    multi_hop_dests: frozenset[str],
    cons_pct: Decimal,
    ret_pct: Decimal,
    consolidated: Decimal,
    retained: Decimal,
    span_days: int,
    tx_count: int,
    root_kyc: Mapping[str, Any],
) -> list[dict[str, Any]]:
    root_reg = is_registered(root_kyc)
    if 5 <= ret_pct <= 20 and multi_hop_dests:
        conservation_severity = "warning"
    else:
        conservation_severity = "success" if root_reg else "info"
    findings = [
        _finding(
            "FND-TOPOLOGY",
            "network",
            "Network Topology",
            (
                f"{len(roles.sources)} source → {len(roles.intermediaries)} "
                f"intermediary → {len(roles.destinations)} destination account(s)"
            ),
            "warning" if len(roles.intermediaries) >= 2 and multi_hop_dests else "info",
        ),
        _finding(
            "FND-CONSERVATION",
            "coins",
            "Decimal Flow Conservation",
            (
                f"{cons_pct}% consolidated (INR {consolidated:,.2f}); "
                f"{ret_pct}% retained/unconsolidated (INR {retained:,.2f})"
            ),
            conservation_severity,
        ),
        _finding(
            "FND-TEMPORAL",
            "clock",
            "Staggered Window Detected" if span_days > 7 else "Transfer Window",
            f"Activity spans {span_days} day(s) across {tx_count} transfer(s)"
            + (" (exceeds static 7-day rule window)" if span_days > 7 else " (within 7-day window)"),
            "warning" if span_days > 7 else "info",
        ),
    ]
    if root_reg:
        findings.append(
            _finding(
                "FND-REGISTRY",
                "shield-check",
                "Verified Commercial Registry",
                f"Seed account holds ACTIVE {root_kyc.get('registry_type') or 'COMMERCIAL'} registration",
                "success",
            )
        )
    elif not multi_hop_dests and tx_count:
        findings.append(
            _finding(
                "FND-GAP",
                "alert",
                "Missing Consolidation / External Gap",
                "Outbound legs show 0 downstream consolidation hops in internal bank records",
                "warning",
            )
        )
    return findings


def compute_network_flow_summary(
    root_account: str,
    transactions: Sequence[Mapping[str, Any]],
    candidate_paths: Sequence[FundFlowPath],
    kyc_profiles: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    roles = _classify_roles(root_account, transactions)
    kyc_by_acc = {k.get("account_id", ""): k for k in kyc_profiles}
    total_outflow, consolidated, multi_hop_dests = _flow_totals(
        root_account, transactions, candidate_paths, kyc_by_acc, roles
    )
    retained = max(_ZERO, (total_outflow - consolidated).quantize(CENT))
    if total_outflow > 0:
        cons_pct = (consolidated / total_outflow * _HUNDRED).quantize(_PCT_Q)
        ret_pct = max(Decimal("0.0"), _HUNDRED - cons_pct).quantize(_PCT_Q)
    else:
        cons_pct = ret_pct = Decimal("0.0")
    span_days, timeline = _timeline(root_account, transactions, roles, multi_hop_dests, consolidated)
    max_hops = max((p.hop_count for p in candidate_paths), default=(1 if transactions else 0))
    findings = _findings(
        roles,
        multi_hop_dests,
        cons_pct,
        ret_pct,
        consolidated,
        retained,
        span_days,
        len(transactions),
        kyc_by_acc.get(root_account, {}),
    )
    return {
        "total_outflow_inr": dec_str(total_outflow),
        "total_consolidated_inr": dec_str(consolidated),
        "total_retained_inr": dec_str(retained),
        "consolidated_pct": dec_str(cons_pct),
        "retained_pct": dec_str(ret_pct),
        "max_hops": max_hops,
        "paths_detected": len(candidate_paths),
        "accounts_involved": len(roles.all_accounts),
        "source_count": len(roles.sources),
        "intermediary_count": len(roles.intermediaries),
        "destination_count": len(roles.destinations),
        "span_days": span_days,
        "node_roles": {acc: roles.label(acc) for acc in roles.all_accounts},
        "timeline": timeline,
        "deterministic_findings": findings,
    }
