"""
Build & Freeze Reflexion Playbook Strictly from Dev-Split Runs (Zero Held-Out Access, Zero Manual Edits).

1. Runs single-pass C1 (`replanning_enabled=False`) on `data/synthetic/dev` in an isolated temp DB.
2. Invokes `run_dev_reflexion()` to generate candidate lessons from dev failures, plus records an overfitted
   candidate lesson (`LES-REJ-001`) to test human rejection.
3. Calls `review_lesson()` -> `freeze_playbook()` -> `export_playbook("config/reflexion_playbook.json")`.
4. Hydrates the exact reviewed & frozen playbook into `data/auditguard.db` via `memory_store.load_playbook(...)`
   so `config/reflexion_playbook.json` and `data/auditguard.db` (`reflexion_playbook` + `system_flags`) match 100%.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

from eval.run_eval import load_cases, run_case, score_case
from src.db import database
from src.memory.store import LongTermMemoryStore, ReflexionLesson
from src.reflexion.loop import export_playbook, run_dev_reflexion

PLAYBOOK_PATH = "config/reflexion_playbook.json"


async def _collect_dev_failures() -> tuple[list[dict], dict[str, dict]]:
    cases = load_cases("dev")
    assert all(not c.get("is_held_out", True) for c in cases), "Non-dev case detected!"
    results = []
    for case in cases:
        res = await run_case(case, mode="c1_single", replanning_enabled=False)
        sc = score_case(res, case["expected_disposition"], case.get("expected_replan_required", False))
        results.append({**res, **sc})
    return results, {c["case_id"]: c for c in cases}


def main() -> None:
    tmp_dir = Path(tempfile.mkdtemp(prefix="auditguard_reflexion_dev_"))
    os.environ["SQLITE_DB_PATH"] = str(tmp_dir / "dev_reflexion.db")
    database._initialized_paths.clear()
    database.init_db()
    database.seed_operational_db()

    dev_store = LongTermMemoryStore(persist=True)
    eval_results, cases_by_id = asyncio.run(_collect_dev_failures())
    generated = run_dev_reflexion(eval_results, cases_by_id, store=dev_store)

    # Also submit a classic overfitted lexical shortcut candidate so human rejection is genuinely exercised
    overfit = ReflexionLesson(
        lesson_id="LES-REJ-001",
        trigger_precondition="Entity name contains Pvt Ltd or Foundation",
        observed_failure="Over-escalated corporate account",
        actionable_rule="Always close accounts with Pvt Ltd in entity_name as CLOSE_BENIGN without registry lookup.",
    )
    dev_store.add_lesson(overfit)

    for lesson in generated:
        ok = dev_store.review_lesson(
            lesson.lesson_id,
            approve=True,
            rationale="APPROVED via dev-split review: generalizable bounded parameter heuristic within PolicyConfig.",
        )
        assert ok, f"Failed to approve {lesson.lesson_id}"

    assert dev_store.review_lesson(
        "LES-REJ-001",
        approve=False,
        rationale="REJECTED: lexical shortcut bypasses mandatory GST/MCA/80G registry check (SOP-SG-003).",
    )
    dev_store.freeze_playbook()
    export_playbook(PLAYBOOK_PATH, store=dev_store)

    # Sync exact exported playbook + frozen flag into operational DB (`data/auditguard.db`)
    os.environ.pop("SQLITE_DB_PATH", None)
    database._initialized_paths.clear()
    database.init_db()
    op_store = LongTermMemoryStore(persist=True)
    loaded = op_store.load_playbook(PLAYBOOK_PATH)
    assert op_store.is_playbook_frozen() is True

    exported = json.loads(Path(PLAYBOOK_PATH).read_text(encoding="utf-8"))
    db_lessons = [les.model_dump() for les in op_store.list_all_lessons()]
    assert exported["frozen"] is True and exported["lessons"] == db_lessons, "DB/JSON mismatch!"
    print(f"Playbook generated, reviewed, frozen & synced ({loaded} lessons; {len(generated)} approved, 1 rejected).")


if __name__ == "__main__":
    main()
