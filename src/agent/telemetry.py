"""
Deterministic Network Flow Summary & Evidence Formatting Helper
Computes 100% Python Decimal flow breakdowns, daily cumulative timelines,
and deterministic topological findings from actual backend transactions and paths.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

from src.models import FundFlowPath


def _parse_dt(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return datetime(2026, 9, 1, 9, 0, 0)


def _dec(val: Any) -> Decimal:
    try:
        return Decimal(str(val)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        return Decimal("0.00")


def compute_network_flow_summary(
    root_account: str,
    transactions: list[dict[str, Any]],
    candidate_paths: list[FundFlowPath],
    kyc_profiles: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Compute exact Decimal fund-flow metrics, node role classifications,
    cumulative timeline points, and deterministic key findings.
    """
    senders = {t.get("sender_account") for t in transactions if t.get("sender_account")}
    receivers = {t.get("receiver_account") for t in transactions if t.get("receiver_account")}
    all_accounts = sorted(senders | receivers | ({root_account} if root_account else set()))

    # Determine topological roles from directed edges
    sources: set[str] = set()
    intermediaries: set[str] = set()
    destinations: set[str] = set()

    for acc in all_accounts:
        is_s = acc in senders
        is_r = acc in receivers
        if acc == root_account and is_s and not is_r:
            sources.add(acc)
        elif is_s and not is_r:
            sources.add(acc)
        elif is_s and is_r:
            intermediaries.add(acc)
        elif is_r and not is_s:
            destinations.add(acc)
        else:
            sources.add(acc)

    # Ensure root_account has clear role if it receives & disburses (e.g. NGO / Chit pool)
    if root_account in intermediaries and not sources:
        sources.add(root_account)

    # Exact Decimal outflow & consolidation math
    # Outflow = transfers originating from root_account (or from sources into root if fan-in pool)
    out_from_root = sum(
        (_dec(t.get("amount_inr", 0)) for t in transactions if t.get("sender_account") == root_account),
        Decimal("0.00"),
    )
    in_to_root = sum(
        (_dec(t.get("amount_inr", 0)) for t in transactions if t.get("receiver_account") == root_account),
        Decimal("0.00"),
    )
    total_outflow = out_from_root if out_from_root > Decimal("0.00") else in_to_root

    # Consolidated = inflow reaching terminal destination accounts (if multi-hop exists),
    # otherwise direct settlement reaching recipients
    multi_hop_dests = {
        p.nodes[-1] for p in candidate_paths if p.hop_count >= 2 and len(p.nodes) >= 3
    }
    if multi_hop_dests:
        consolidated = sum(
            (_dec(t.get("amount_inr", 0)) for t in transactions if t.get("receiver_account") in multi_hop_dests),
            Decimal("0.00"),
        )
    elif destinations:
        consolidated = sum(
            (_dec(t.get("amount_inr", 0)) for t in transactions if t.get("receiver_account") in destinations and t.get("sender_account") != root_account),
            Decimal("0.00"),
        )
        # If 1-hop direct payouts (e.g., payroll / marketplace sellers / missing downstream hop)
        if consolidated == Decimal("0.00"):
            kyc_map = {k.get("account_id"): k for k in kyc_profiles}
            root_reg = bool(kyc_map.get(root_account, {}).get("is_commercially_registered"))
            if root_reg:
                consolidated = out_from_root
    else:
        consolidated = Decimal("0.00")

    if consolidated > total_outflow and total_outflow > Decimal("0.00"):
        consolidated = total_outflow

    retained = max(Decimal("0.00"), (total_outflow - consolidated).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    if total_outflow > Decimal("0.00"):
        cons_pct = float(((consolidated / total_outflow) * Decimal("100")).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))
        ret_pct = round(max(0.0, 100.0 - cons_pct), 1)
    else:
        cons_pct, ret_pct = 0.0, 0.0

    # Daily cumulative timeline (Day 0 .. Day Span)
    timeline: list[dict[str, Any]] = []
    span_days = 0
    if transactions:
        parsed = [(t, _parse_dt(t.get("timestamp", ""))) for t in transactions]
        min_dt = min(dt for _, dt in parsed)
        max_dt = max(dt for _, dt in parsed)
        span_days = max(0, (max_dt.date() - min_dt.date()).days)

        daily_out: dict[int, Decimal] = defaultdict(lambda: Decimal("0.00"))
        daily_cons: dict[int, Decimal] = defaultdict(lambda: Decimal("0.00"))

        for t, dt in parsed:
            day_idx = max(0, (dt.date() - min_dt.date()).days)
            amt = _dec(t.get("amount_inr", 0))
            if t.get("sender_account") == root_account or t.get("sender_account") in sources:
                daily_out[day_idx] += amt
            if (multi_hop_dests and t.get("receiver_account") in multi_hop_dests) or (
                not multi_hop_dests and t.get("receiver_account") in destinations and consolidated > Decimal("0.00")
            ):
                daily_cons[day_idx] += amt

        horizon = max(span_days, 1)
        # Sample up to 10 evenly spaced day ticks if span is wide, else every day
        step = 1 if horizon <= 10 else max(1, round(horizon / 8))
        ticks = list(range(0, horizon + 1, step))
        if ticks[-1] != horizon:
            ticks.append(horizon)

        cum_o = Decimal("0.00")
        cum_c = Decimal("0.00")
        last_d = -1
        for d in ticks:
            for k in range(last_d + 1, d + 1):
                cum_o += daily_out[k]
                cum_c += daily_cons[k]
            last_d = d
            timeline.append({
                "day": d,
                "label": f"Day {d}",
                "cumulative_outflow_inr": float(cum_o),
                "cumulative_consolidated_inr": float(min(cum_c, cum_o) if cum_o > 0 else cum_c),
            })

    max_hops = max((p.hop_count for p in candidate_paths), default=(1 if transactions else 0))

    # Deterministic Key Findings (strictly code-computed, never LLM-guessed)
    kyc_by_acc = {k.get("account_id"): k for k in kyc_profiles}
    root_kyc = kyc_by_acc.get(root_account, {})
    root_reg = bool(root_kyc.get("is_commercially_registered") or root_kyc.get("registry_check", {}).get("is_registered"))

    findings: list[dict[str, Any]] = [
        {
            "id": "FND-TOPOLOGY",
            "type": "deterministic",
            "icon": "network",
            "title": "Network Topology",
            "summary": f"{len(sources)} source → {len(intermediaries)} intermediary → {len(destinations)} destination account(s)",
            "severity": "warning" if len(intermediaries) >= 2 and len(multi_hop_dests) >= 1 else "info",
        },
        {
            "id": "FND-CONSERVATION",
            "type": "deterministic",
            "icon": "coins",
            "title": "Decimal Flow Conservation",
            "summary": (
                f"{cons_pct:.1f}% consolidated (INR {consolidated:,.2f}); "
                f"{ret_pct:.1f}% retained/unconsolidated (INR {retained:,.2f})"
            ),
            "severity": "warning" if 5.0 <= ret_pct <= 20.0 and multi_hop_dests else "success" if root_reg else "info",
        },
        {
            "id": "FND-TEMPORAL",
            "type": "deterministic",
            "icon": "clock",
            "title": "Staggered Window Detected" if span_days > 7 else "Transfer Window",
            "summary": (
                f"Activity spans {span_days} day(s) across {len(transactions)} transfer(s)"
                + (" (exceeds static 7-day rule window)" if span_days > 7 else " (within 7-day window)")
            ),
            "severity": "warning" if span_days > 7 else "info",
        },
    ]
    if root_reg:
        findings.append({
            "id": "FND-REGISTRY",
            "type": "deterministic",
            "icon": "shield-check",
            "title": "Verified Commercial Registry",
            "summary": f"Seed account holds ACTIVE {root_kyc.get('registry_type') or 'COMMERCIAL'} registration",
            "severity": "success",
        })
    elif not multi_hop_dests and transactions:
        findings.append({
            "id": "FND-GAP",
            "type": "deterministic",
            "icon": "alert",
            "title": "Missing Consolidation / External Gap",
            "summary": "Outbound legs show 0 downstream consolidation hops in internal bank records",
            "severity": "warning",
        })

    node_roles = {}
    for acc in all_accounts:
        if acc in sources:
            node_roles[acc] = "source"
        elif acc in intermediaries:
            node_roles[acc] = "intermediary"
        elif acc in destinations:
            node_roles[acc] = "destination"
        else:
            node_roles[acc] = "unknown"

    return {
        "total_outflow_inr": str(total_outflow),
        "total_outflow_num": float(total_outflow),
        "total_consolidated_inr": str(consolidated),
        "total_consolidated_num": float(consolidated),
        "total_retained_inr": str(retained),
        "total_retained_num": float(retained),
        "consolidated_pct": cons_pct,
        "retained_pct": ret_pct,
        "max_hops": max_hops,
        "paths_detected": len(candidate_paths),
        "accounts_involved": len(all_accounts),
        "source_count": len(sources),
        "intermediary_count": len(intermediaries),
        "destination_count": len(destinations),
        "span_days": span_days,
        "node_roles": node_roles,
        "timeline": timeline,
        "deterministic_findings": findings,
    }
