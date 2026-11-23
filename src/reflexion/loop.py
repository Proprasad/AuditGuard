"""
Dev-Split Reflexion Improvement Loop + Human Review & Freeze Pipeline.
Generates precondition-tagged lessons strictly from dev-split failures; requires human review before freeze.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.core.canonical import canonical_sha256
from src.memory.store import LongTermMemoryStore, ReflexionLesson, memory_store


def generate_candidate_lesson(case: dict[str, Any], actual_disposition: str) -> ReflexionLesson:
    """Generate a deterministic, precondition-tagged candidate lesson from a dev-split failure."""
    category = case.get("category", "unknown")
    expected = case.get("expected_disposition", "unknown")

    if category == "staggered_timing":
        precondition = "Outbound scatter legs present within 7 days but zero consolidation legs"
        failure = f"Predicted {actual_disposition} instead of {expected} due to narrow 7-day window"
        rule = "Expand time_window_days to 14-30 days before concluding no consolidation exists."
    elif category == "two_tier_layered":
        precondition = "Intermediaries transfer funds to secondary accounts instead of final beneficiary"
        failure = f"Predicted {actual_disposition} instead of {expected} with max_hops=3"
        rule = "Increase max_hops to 4-5 when intermediaries forward to secondary accounts."
    elif category == "fee_skimming":
        precondition = "Consolidated inflow is 5-12% lower than distributed outflow"
        failure = f"Predicted {actual_disposition} instead of {expected} with tight amount_tolerance"
        rule = "Widen amount_tolerance to 0.15 and compute exact Decimal retained fee percentage."
    else:
        precondition = f"Alert category '{category}' with ambiguous scatter-gather structure"
        failure = f"Predicted {actual_disposition} instead of {expected}"
        rule = "Verify commercial registry (GST/80G/MCA) and counterparty history before escalating."

    lid = f"LES-{canonical_sha256({'category': category, 'rule': rule})[:6].upper()}"
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
    """Run Reflexion strictly on dev-split failures (held-out cases are skipped)."""
    generated: list[ReflexionLesson] = []
    seen_ids = {les.lesson_id for les in store.list_all_lessons()}
    for res in eval_results:
        if res.get("correct"):
            continue
        case = cases_by_id.get(res.get("case_id", ""))
        if not case or case.get("is_held_out", True):
            continue
        lesson = generate_candidate_lesson(case, res.get("actual", "unknown"))
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
