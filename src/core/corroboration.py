"""
Phase 7 — Registration Corroboration & Explicit Missing-Data Detection (`src/core/corroboration.py`).

Pure, deterministic compliance evidence analyzers used by `rule_engine`, `nodes.py`, and `gathering.py`:
  1. `assess_registration_corroboration(...)`: treats commercial registration as *evidence needing
     corroboration* (registry age, counterparty history length, cadence regularity via
     `get_counterparty_history`, absence of unexplained scatter-gather legs), NEVER a standalone
     verdict. A registered root with multi-hop scatter-gather topology and unexplained legs is NEVER
     auto-closed below the corroboration threshold (`CORROBORATION_THRESHOLD = Decimal("0.60")`).
  2. `detect_missing_data(...)`: explicitly detects (a) accounts without KYC, (b) stale/expired/
     revoked/conflicting registry records, (c) root outflows without downstream consolidation within
     the max window (when uncorroborated), and (d) external-bank / correspondent memo patterns.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
import re
from typing import Any

from src.core.adapters import is_registered
from src.core.canonical import parse_utc_timestamp
from src.guardrails.guardrails import unwrap_untrusted_data
from src.models import FundFlowPath

CORROBORATION_THRESHOLD = Decimal("0.60")
_MIN_MATURE_REGISTRY_DAYS = 180
_ESTABLISHED_REGISTRY_DAYS = 365
_EXTERNAL_BANK_MEMO_RE = re.compile(
    r"\b(?:external\s+bank|other\s+bank|correspondent\s+bank|correspondent\s+leg|"
    r"inter[\-\s]?bank\s+(?:gap|outflow|external)|off[\-\s]?book|nostro|vostro|"
    r"ext(?:ernal)?\s+correspondent|outside\s+bank|unobserved\s+beneficiary)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CorroborationAssessment:
    registry_active: bool
    registry_age_days: int | None
    counterparty_tx_count: int
    counterparty_span_days: int
    cadence_regular: bool
    recurring_payroll_12m: bool
    has_unexplained_multihop: bool
    corroboration_score: Decimal
    corroborated_benign: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class MissingDataReport:
    has_explicit_missing_data: bool
    missing_kyc_accounts: tuple[str, ...] = field(default_factory=tuple)
    stale_or_conflicting_registry: tuple[str, ...] = field(default_factory=tuple)
    unconsolidated_outflows: bool = False
    external_bank_tx_ids: tuple[str, ...] = field(default_factory=tuple)
    missing_evidence_items: tuple[str, ...] = field(default_factory=tuple)


def _parse_date_age_days(raw_since: Any, reference_ts: datetime) -> int | None:
    if not raw_since:
        return None
    s = str(raw_since).strip()
    if not s:
        return None
    try:
        dt = parse_utc_timestamp(f"{s}T00:00:00Z" if len(s) == 10 else s)
    except ValueError:
        return None
    return max(0, (reference_ts - dt).days)


def _reference_timestamp(transactions: Sequence[Mapping[str, Any]]) -> datetime:
    stamps: list[datetime] = []
    for tx in transactions:
        ts = tx.get("timestamp")
        if ts:
            try:
                stamps.append(parse_utc_timestamp(str(ts)))
            except ValueError:
                continue
    return max(stamps) if stamps else datetime(2026, 9, 1, tzinfo=timezone.utc)


def _eval_tx_cadence(tx_list: Sequence[Mapping[str, Any]]) -> tuple[int, int, bool, bool]:
    """Compute `(tx_count, span_days, cadence_regular, recurring_12m)` for a single counterparty series."""
    stamps: list[datetime] = []
    for t in tx_list:
        if t.get("timestamp"):
            try:
                stamps.append(parse_utc_timestamp(str(t["timestamp"])))
            except ValueError:
                continue
    stamps.sort()
    if len(stamps) < 2:
        return len(stamps), 0, False, False
    span_days = (stamps[-1] - stamps[0]).days
    distinct_months = {(d.year, d.month) for d in stamps}
    gaps = [(stamps[i + 1] - stamps[i]).days for i in range(len(stamps) - 1) if (stamps[i + 1] - stamps[i]).days > 0]
    regular = False
    if len(distinct_months) >= 3 and span_days >= 60 and gaps:
        mean_gap = sum(gaps) / len(gaps)
        if mean_gap >= 7.0:
            variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
            regular = ((variance**0.5) / mean_gap) <= 0.55
    return len(stamps), span_days, regular, bool(regular and len(distinct_months) >= 6 and span_days >= 150)


def _analyze_counterparty_cadence(
    registry: Mapping[str, Any],
    transactions: Sequence[Mapping[str, Any]],
    root: str,
) -> tuple[int, int, bool, bool]:
    """Extract `(max_tx_count, max_span_days, cadence_regular, recurring_12m)` from `CP-*` or root history."""
    series: list[Sequence[Mapping[str, Any]]] = [
        v["transactions"]
        for k, v in registry.items()
        if str(k).startswith("CP-") and isinstance(v, Mapping) and isinstance(v.get("transactions"), list)
    ]
    if not series and transactions and root:
        by_cp: dict[str, list[Mapping[str, Any]]] = {}
        for t in transactions:
            if t.get("sender_account") == root and t.get("receiver_account"):
                by_cp.setdefault(str(t["receiver_account"]), []).append(t)
        series = list(by_cp.values())

    best_count, best_span, cadence_regular, recurring_12m = 0, 0, False, False
    for tx_list in series:
        cnt, span, reg, rec12 = _eval_tx_cadence(tx_list)
        best_count = max(best_count, cnt)
        best_span = max(best_span, span)
        cadence_regular = cadence_regular or reg
        recurring_12m = recurring_12m or rec12
    return best_count, best_span, cadence_regular, recurring_12m


def assess_registration_corroboration(
    root: str,
    root_kyc: Mapping[str, Any],
    recipients: Sequence[Mapping[str, Any]],
    paths: Sequence[FundFlowPath],
    transactions: Sequence[Mapping[str, Any]],
    registry: Mapping[str, Any],
) -> CorroborationAssessment:
    """Evaluate whether commercial registration is genuinely corroborated or contradicted by flow topology."""
    ref_ts = _reference_timestamp(transactions)
    raw_check = root_kyc.get("registry_check")
    reg_check: Mapping[str, Any] = raw_check if isinstance(raw_check, Mapping) else {}
    reg_active = is_registered(root_kyc)
    age_days = _parse_date_age_days(
        reg_check.get("registered_since") or root_kyc.get("registered_since"), ref_ts
    )
    cp_count, cp_span, regular, recurring_12m = _analyze_counterparty_cadence(registry, transactions, root)

    multi_hop = [p for p in paths if p.hop_count >= 2]
    has_unexplained_multihop = bool(multi_hop)
    risk = str(root_kyc.get("risk_category", "")).lower()

    score = Decimal("0.00")
    reasons: list[str] = []
    if reg_active:
        score += Decimal("0.30")
        reasons.append("active_commercial_registry(+0.30)")
        if age_days is not None and age_days >= _ESTABLISHED_REGISTRY_DAYS:
            score += Decimal("0.30")
            reasons.append(f"established_registry_age_{age_days}d(+0.30)")
        elif age_days is not None and age_days >= _MIN_MATURE_REGISTRY_DAYS:
            score += Decimal("0.15")
            reasons.append(f"mature_registry_age_{age_days}d(+0.15)")
        elif age_days is not None:
            reasons.append(f"newly_registered_{age_days}d(+0.00)")
    if recurring_12m:
        score += Decimal("0.65")
        reasons.append(f"recurring_12m_cadence_{cp_count}tx_{cp_span}d(+0.65)")
    elif regular:
        score += Decimal("0.35")
        reasons.append(f"regular_counterparty_cadence_{cp_count}tx_{cp_span}d(+0.35)")
    if recipients and not has_unexplained_multihop:
        reg_recip = sum(1 for r in recipients if is_registered(r))
        if reg_recip / len(recipients) >= 0.5:
            score += Decimal("0.15")
            reasons.append(f"verified_recipients_{reg_recip}/{len(recipients)}(+0.15)")
    if risk == "high":
        score -= Decimal("0.25")
        reasons.append("high_kyc_risk_penalty(-0.25)")
    if has_unexplained_multihop:
        reasons.append(f"unexplained_multihop_scatter_gather_{len(multi_hop)}paths(blocks_auto_close)")

    clamped = max(Decimal("0.00"), min(Decimal("1.00"), score))
    corroborated = (not has_unexplained_multihop) and clamped >= CORROBORATION_THRESHOLD
    return CorroborationAssessment(
        registry_active=reg_active,
        registry_age_days=age_days,
        counterparty_tx_count=cp_count,
        counterparty_span_days=cp_span,
        cadence_regular=regular,
        recurring_payroll_12m=recurring_12m,
        has_unexplained_multihop=has_unexplained_multihop,
        corroboration_score=clamped,
        corroborated_benign=corroborated,
        reasons=tuple(reasons),
    )


def _registry_anomalies(profiles: Sequence[Mapping[str, Any]]) -> tuple[list[str], list[str]]:
    stale: list[str] = []
    notes: list[str] = []
    for kyc in profiles:
        acc = str(kyc.get("account_id", "unknown"))
        reg_check = kyc.get("registry_check")
        if not isinstance(reg_check, Mapping) or not reg_check:
            continue
        status = str(reg_check.get("registry_status") or "").upper()
        if status in ("EXPIRED", "REVOKED", "SUSPENDED"):
            stale.append(f"{acc}:{status}")
            notes.append(f"Commercial registry for {acc} is {status} (requires fresh verification)")
        elif bool(kyc.get("is_commercially_registered")) and not bool(reg_check.get("is_registered")):
            stale.append(f"{acc}:CONFLICTING_KYC_VS_REGISTRY")
            notes.append(f"KYC claims commercial registration for {acc} but registry returned {status or 'NOT_FOUND'}")
    return stale, notes


def _external_bank_memo_txs(transactions: Sequence[Mapping[str, Any]]) -> list[str]:
    found: list[str] = []
    for t in transactions:
        memo_raw = unwrap_untrusted_data(str(t.get("memo") or t.get("memo_text") or ""))
        tx_id = str(t.get("tx_id") or "")
        if tx_id and _EXTERNAL_BANK_MEMO_RE.search(memo_raw) and tx_id not in found:
            found.append(tx_id)
    return found


def detect_missing_data(
    root: str,
    network_accounts: Sequence[str],
    transactions: Sequence[Mapping[str, Any]],
    paths: Sequence[FundFlowPath],
    profiles: Sequence[Mapping[str, Any]],
    degraded: Sequence[str],
    corroboration: CorroborationAssessment,
    *,
    at_max_window: bool = False,
) -> MissingDataReport:
    """Explicitly detect missing KYC, stale/conflicting registry, unconsolidated outflows, and external-bank memos."""
    _ = network_accounts
    missing_kyc = list(
        dict.fromkeys(
            m.group(1)
            for note in degraded
            if (m := re.match(r"KYC unavailable for ([A-Za-z0-9\-_]+):", note)) is not None
        )
    )
    stale_or_conflict, reg_notes = _registry_anomalies(profiles)
    ext_tx_ids = _external_bank_memo_txs(transactions)
    items: list[str] = []
    if missing_kyc:
        items.append(f"Missing KYC profiles for account(s): {', '.join(missing_kyc)}")
    items.extend(reg_notes)
    if ext_tx_ids:
        items.append(
            f"External/correspondent bank memo pattern on transaction(s): {', '.join(ext_tx_ids[:4])} "
            "(inter-bank downstream logs required)"
        )

    outbound_targets = {
        str(t["receiver_account"])
        for t in transactions
        if t.get("sender_account") == root and t.get("receiver_account")
    }
    senders_with_downstream = {str(t.get("sender_account")) for t in transactions if t.get("sender_account")}
    unconsolidated = (
        at_max_window
        and len(outbound_targets) >= 2
        and not any(p.hop_count >= 2 for p in paths)
        and not corroboration.corroborated_benign
        and any(acc not in senders_with_downstream for acc in outbound_targets)
    )
    if unconsolidated:
        items.append(
            f"Root {root} dispersed funds to {len(outbound_targets)} counterparties with no downstream "
            "consolidation visible within max scan window"
        )

    return MissingDataReport(
        has_explicit_missing_data=bool(missing_kyc or stale_or_conflict or ext_tx_ids or unconsolidated),
        missing_kyc_accounts=tuple(missing_kyc),
        stale_or_conflicting_registry=tuple(stale_or_conflict),
        unconsolidated_outflows=unconsolidated,
        external_bank_tx_ids=tuple(ext_tx_ids),
        missing_evidence_items=tuple(items),
    )
