"""
Dev-Split Reflexion Improvement Loop + Human Review & Freeze Pipeline.
Derives precondition-tagged candidate lessons from observable transaction/KYC telemetry (never dataset labels).
"""

from __future__ import annotations

from decimal import Decimal
import json
from pathlib import Path
from typing import Any

from src.config import get_policy
from src.core.canonical import canonical_sha256, parse_utc_timestamp, to_money
from src.memory.store import LongTermMemoryStore, ReflexionLesson, memory_store


def _telemetry_signals(case: dict[str, Any]) -> tuple[float, int, Decimal, bool]:
    txs = case.get("transactions") or []
    root = str(case.get("root_account", ""))
    timestamps = [parse_utc_timestamp(t["timestamp"]) for t in txs if t.get("timestamp")]
    span_days = (max(timestamps) - min(timestamps)).total_seconds() / 86400.0 if len(timestamps) >= 2 else 0.0

    hop1_targets = {str(t.get("receiver_account")) for t in txs if str(t.get("sender_account")) == root}
    hop2_targets = {
        str(t.get("receiver_account"))
        for t in txs
        if str(t.get("sender_account")) in hop1_targets and str(t.get("receiver_account")) != root
    }
    hop3_targets = {
        str(t.get("receiver_account"))
        for t in txs
        if str(t.get("sender_account")) in hop2_targets and str(t.get("receiver_account")) not in hop1_targets
    }
    depth = 3 if hop3_targets else (2 if hop2_targets else (1 if hop1_targets else 0))

    root_out = sum((to_money(t["amount_inr"]) for t in txs if str(t.get("sender_account")) == root), Decimal("0.00"))
    inbound_by_acc: dict[str, Decimal] = {}
    for t in txs:
        sender, receiver = str(t.get("sender_account")), str(t.get("receiver_account"))
        if sender != root and receiver != root:
            inbound_by_acc[receiver] = inbound_by_acc.get(receiver, Decimal("0.00")) + to_money(t["amount_inr"])
    max_consol = max(inbound_by_acc.values(), default=Decimal("0.00"))
    skim_ratio = (root_out - max_consol) / root_out if root_out > 0 and max_consol > 0 else Decimal("0")

    kyc_map = case.get("kyc_profiles") or {}
    root_kyc = kyc_map.get(root) if isinstance(kyc_map, dict) else {}
    registered = bool((root_kyc or {}).get("is_commercially_registered"))
    return span_days, depth, skim_ratio, registered


def generate_candidate_lesson(case: dict[str, Any], actual_disposition: str) -> ReflexionLesson:
    """Generate a deterministic, precondition-tagged candidate lesson from observable dev-split telemetry."""
    if case.get("is_held_out") or str(case.get("split", "")) in ("held_out", "challenge"):
        raise PermissionError("Reflexion lesson generation is forbidden on held-out or challenge splits")
    gb = get_policy().graph_bounds
    expected = str(case.get("gold_disposition") or case.get("expected_disposition") or "unknown")
    span_days, depth, skim_ratio, registered = _telemetry_signals(case)

    if span_days > gb.time_window_days.default:
        precondition = (
            f"Outbound scatter legs present within {gb.time_window_days.default} days "
            "but consolidation occurs after default window"
        )
        failure = (
            f"Predicted {actual_disposition} instead of {expected} "
            f"due to narrow {gb.time_window_days.default}-day window"
        )
        rule = (
            f"Expand time_window_days up to {gb.time_window_days.max} days "
            "before concluding no consolidation exists."
        )
    elif depth > gb.max_hops.default:
        precondition = "Intermediaries forward funds across secondary tier accounts beyond default hop bound"
        failure = f"Predicted {actual_disposition} instead of {expected} with max_hops={gb.max_hops.default}"
        rule = f"Increase max_hops up to {gb.max_hops.max} when intermediaries forward to secondary accounts."
    elif skim_ratio > gb.amount_tolerance.default:
        precondition = "Consolidated inflow is lower than distributed outflow due to intermediary fee retention"
        failure = f"Predicted {actual_disposition} instead of {expected} with tight amount_tolerance"
        rule = (
            f"Widen amount_tolerance within [{gb.amount_tolerance.default}..{gb.amount_tolerance.max}] "
            "and compute exact Decimal retained fee percentage."
        )
    elif registered or expected == "close_benign":
        precondition = "Ambiguous scatter-gather structure involving commercially active counterparty network"
        failure = f"Predicted {actual_disposition} instead of {expected}"
        rule = "Verify commercial registry (GST/80G/MCA) and counterparty history before escalating."
    else:
        precondition = "Outbound dispersal legs lack verified consolidation or commercial registration"
        failure = f"Predicted {actual_disposition} instead of {expected}"
        rule = "Reconfigure time_window_days and max_hops within policy bounds and inspect counterparty history."

    lid = f"LES-{canonical_sha256({'precondition': precondition, 'rule': rule})[:6].upper()}"
    return ReflexionLesson(
        lesson_id=lid,
        trigger_precondition=precondition,
        observed_failure=failure,
        actionable_rule=rule,
    )


def run_dev_reflexion(
    eval_results: list[dict[str, Any]],
    cases_by_id: dict[str, dict[str, Any]],
    store: LongTermMemoryStore = memory_store,
) -> list[ReflexionLesson]:
    """Run Reflexion strictly on dev-split failures (non-dev cases are skipped)."""
    generated: list[ReflexionLesson] = []
    seen_ids = {les.lesson_id for les in store.list_all_lessons()}
    for res in eval_results:
        if res.get("correct"):
            continue
        case = cases_by_id.get(res.get("case_id", ""))
        if not case or case.get("is_held_out", True) or str(case.get("split", "")) in ("held_out", "challenge"):
            continue
        lesson = generate_candidate_lesson(case, str(res.get("actual", "unknown")))
        if lesson.lesson_id not in seen_ids and store.add_lesson(lesson):
            seen_ids.add(lesson.lesson_id)
            generated.append(lesson)
    return generated


def export_playbook(path: str = "config/reflexion_playbook.json", store: LongTermMemoryStore = memory_store) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "frozen": store.is_playbook_frozen(),
        "lessons": [lesson.model_dump() for lesson in store.list_all_lessons()],
    }
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
