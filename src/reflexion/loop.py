"""
Dev-Split Reflexion Improvement Loop + Human Review CLI
Generates precondition-tagged lessons from dev-split failures.
Requires human review before promotion to frozen playbook.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from src.memory.store import LongTermMemoryStore, ReflexionLesson, memory_store


def generate_candidate_lesson(case: dict[str, Any], actual_disposition: str) -> ReflexionLesson:
    """
    Generate a structured candidate lesson from a dev-split failure or missed replan.
    """
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

    return ReflexionLesson(
        lesson_id=f"LES-{uuid.uuid4().hex[:6].upper()}",
        trigger_precondition=precondition,
        observed_failure=failure,
        actionable_rule=rule,
    )


def run_dev_reflexion(
    eval_results: list[dict[str, Any]],
    cases_by_id: dict[str, dict[str, Any]],
    store: LongTermMemoryStore = memory_store,
) -> list[ReflexionLesson]:
    """
    Run Reflexion only on dev-split failures (never held-out).
    """
    generated = []
    for res in eval_results:
        if res.get("correct"):
            continue
        case = cases_by_id.get(res.get("case_id", ""))
        if not case or case.get("is_held_out", True):
            continue  # Strictly enforce dev-split only
        lesson = generate_candidate_lesson(case, res.get("actual", "unknown"))
        if store.add_lesson(lesson):
            generated.append(lesson)
    return generated


def export_playbook(path: str = "config/reflexion_playbook.json", store: LongTermMemoryStore = memory_store) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    data = {
        "frozen": store.is_playbook_frozen(),
        "lessons": [l.model_dump() for l in store.list_all_lessons()],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
