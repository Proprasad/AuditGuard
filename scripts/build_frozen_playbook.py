"""
Generate CANDIDATE Reflexion lessons strictly from dev-split runs (zero held-out access). Audit AG-04.

1. Runs single-pass C1 (`replanning_enabled=False`) on the dev split in an isolated temp DB.
2. Invokes `run_dev_reflexion()` to draft candidate lessons from dev failures.
3. Writes them to the playbook JSON as `pending`, unfrozen. Nothing is approved here, and the operational DB is
   not touched: approval is a human decision.

Then a human reviews each lesson and freezes the playbook:
    auditguard lessons list --status pending
    auditguard lessons accept LES-XXXX --reviewer <name> --reason "<why it generalises>"
    auditguard lessons reject LES-YYYY --reviewer <name> --reason "<why not>"
    auditguard lessons freeze --reviewer <name>
Evaluation loads the frozen file and refuses it if the lessons changed after freezing (sha256 check).
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

from eval.run_eval import load_cases, run_case, score_case
from src.db import database
from src.memory.store import LongTermMemoryStore
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
    export_playbook(PLAYBOOK_PATH, store=dev_store)

    exported = json.loads(Path(PLAYBOOK_PATH).read_text(encoding="utf-8"))
    assert exported["frozen"] is False, "a freshly generated playbook must not be frozen"
    assert all(les["status"] == "pending" for les in exported["lessons"]), "generated lessons must await review"
    print(  # noqa: T201 - operator script output
        f"Wrote {len(generated)} pending candidate lesson(s) to {PLAYBOOK_PATH}. "
        "Review them with `auditguard lessons list --status pending`, then accept/reject and freeze."
    )


if __name__ == "__main__":
    main()
