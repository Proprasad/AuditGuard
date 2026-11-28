"""
E3 lesson accounting (audit AG-32 / AG-37): playbook hash, lesson prompt cost, and per-lesson ablation.

With `lesson_ablation: true` in an experiment YAML, every approved lesson gets an extra variant
`playbook_on_minus_<ID>` that runs with that one lesson hidden. A lesson is reported **harmful** for a mode when
removing it raises accuracy, or keeps accuracy equal while lowering weighted error cost.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
import json
from pathlib import Path
from typing import Any

from src.memory.store import LongTermMemoryStore, playbook_sha256

ABLATION_PREFIX = "playbook_on_minus_"
REFERENCE_VARIANT = "playbook_on_memory_on"


def approved_lesson_ids(playbook_path: str = "config/reflexion_playbook.json") -> list[str]:
    data = json.loads(Path(playbook_path).read_text(encoding="utf-8"))
    return [str(les["lesson_id"]) for les in data.get("lessons", []) if les.get("status") == "approved"]


def expand_lesson_ablation(exp_config: dict[str, Any], lesson_ids: Sequence[str]) -> dict[str, Any]:
    """Return a copy of `exp_config` with one `playbook_on_minus_<ID>` variant per lesson (if enabled)."""
    if not exp_config.get("lesson_ablation"):
        return exp_config
    extra = [
        {"name": f"{ABLATION_PREFIX}{lid}", "reflexion_enabled": True, "memory_enabled": True,
         "exclude_lessons": [lid]}
        for lid in lesson_ids
    ]
    return {**exp_config, "variants": [*exp_config.get("variants", []), *extra]}


def ablation_label_map(exp_config: dict[str, Any]) -> dict[str, list[str]]:
    """`{result label: [lesson ids hidden while it runs]}` for the expanded variants."""
    modes = list(exp_config.get("modes", []))
    return {
        f"{m}_{v['name']}": list(v["exclude_lessons"])
        for m in modes
        for v in exp_config.get("variants", [])
        if v.get("exclude_lessons")
    }


@contextmanager
def lesson_ablation(store: LongTermMemoryStore, lesson_ids: Sequence[str]) -> Iterator[None]:
    """Hide `lesson_ids` from retrieval inside the block (status `ablated`), restoring their status afterwards."""
    previous = {les.lesson_id: les.status for les in store.list_all_lessons() if les.lesson_id in set(lesson_ids)}
    try:
        for lid in previous:
            store.set_status_for_ablation(lid, "ablated")
        yield
    finally:
        for lid, status in previous.items():
            store.set_status_for_ablation(lid, status)


def harmful_lessons(results: dict[str, dict[str, Any]], exp_config: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for label, hidden in ablation_label_map(exp_config).items():
        mode = label.split(f"_{ABLATION_PREFIX}")[0]
        ref, abl = results.get(f"{mode}_{REFERENCE_VARIANT}"), results.get(label)
        if ref is None or abl is None:
            continue
        d_acc = float(abl["metrics"]["disposition_accuracy"]) - float(ref["metrics"]["disposition_accuracy"])
        d_cost = float(abl["metrics"]["weighted_error_cost"]) - float(ref["metrics"]["weighted_error_cost"])
        rows.append(
            {
                "lesson_id": hidden[0],
                "mode": mode,
                "delta_accuracy": round(d_acc, 6),
                "delta_weighted_error_cost": round(d_cost, 6),
                "harmful": d_acc > 1e-9 or (abs(d_acc) <= 1e-9 and d_cost < -1e-9),
            }
        )
    return rows


def lesson_report(
    results: dict[str, dict[str, Any]],
    exp_config: dict[str, Any],
    playbook_path: str = "config/reflexion_playbook.json",
) -> dict[str, Any]:
    """Summary block for E3: which playbook ran, what lessons cost in tokens/USD, and which lessons hurt."""
    data = json.loads(Path(playbook_path).read_text(encoding="utf-8"))
    approved = [les for les in data.get("lessons", []) if les.get("status") == "approved"]
    cost_delta: dict[str, dict[str, float]] = {}
    for mode in exp_config.get("modes", []):
        on, off = results.get(f"{mode}_{REFERENCE_VARIANT}"), results.get(f"{mode}_playbook_off_memory_on")
        if on and off:
            cost_delta[mode] = {
                key: round(float(on["metrics"].get(key, 0.0)) - float(off["metrics"].get(key, 0.0)), 6)
                for key in ("cost_usd", "tokens")
            }
    return {
        "playbook_sha256": playbook_sha256(list(data.get("lessons", []))),
        "playbook_frozen": bool(data.get("frozen")),
        "approved_lessons": [les["lesson_id"] for les in approved],
        "lessons_without_human_reviewer": [les["lesson_id"] for les in approved if not les.get("reviewer")],
        "lesson_prompt_chars": sum(
            len(f"[{les['lesson_id']}] IF {les['trigger_precondition']} THEN {les['actionable_rule']}")
            for les in approved
        ),
        "lesson_cost_delta_per_case": cost_delta,
        "ablation": harmful_lessons(results, exp_config),
    }
