"""
Human review of Reflexion lessons (audit AG-04 / AG-32), driven by `auditguard lessons ...`.

The reviewed artifact is the playbook JSON (default `config/reflexion_playbook.json`), so every decision is a
reviewable diff. Rules:
  * every decision records the reviewer, a reason and a UTC timestamp;
  * approving runs the gold-label leak check on the prompt-facing fields (`label_leak_findings`);
  * editing a lesson sends it back to `pending`, so an edit is never self-approved by the edit itself;
  * freezing needs zero `pending` lessons and stores `frozen_sha256` over the lessons, which
    `LongTermMemoryStore.load_playbook` verifies before any lesson can reach a prompt;
  * a frozen playbook refuses changes until it is explicitly unfrozen (also recorded).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from src.db.database import utc_now_iso
from src.memory.store import ReflexionLesson, playbook_sha256
from src.reflexion.loop import PROMPT_FACING_LESSON_FIELDS, label_leak_findings

DEFAULT_PLAYBOOK = "config/reflexion_playbook.json"
DECISIONS = ("approved", "rejected")
__all__ = ["DEFAULT_PLAYBOOK", "ReviewError", "decide", "edit", "freeze", "list_lessons", "load", "playbook_sha256",
           "unfreeze"]


class ReviewError(ValueError):
    """A review action was refused; the message says why."""


def load(path: str | Path = DEFAULT_PLAYBOOK) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise ReviewError(f"playbook not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("lessons"), list):
        raise ReviewError(f"not a playbook file: {p}")
    return data


def _save(path: str | Path, data: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _require(reviewer: str, reason: str) -> tuple[str, str]:
    who, why = reviewer.strip(), reason.strip()
    if not who:
        raise ReviewError("a reviewer name is required (--reviewer)")
    if not why:
        raise ReviewError("a reason is required (--reason)")
    return who, why


def _find(data: dict[str, Any], lesson_id: str) -> dict[str, Any]:
    if data.get("frozen"):
        raise ReviewError("playbook is frozen; run `auditguard lessons unfreeze` first")
    for lesson in data["lessons"]:
        if lesson.get("lesson_id") == lesson_id:
            return dict(lesson)
    raise ReviewError(f"unknown lesson {lesson_id!r}")


def _replace(data: dict[str, Any], lesson: dict[str, Any]) -> None:
    data["lessons"] = [lesson if x.get("lesson_id") == lesson["lesson_id"] else x for x in data["lessons"]]


def list_lessons(path: str | Path = DEFAULT_PLAYBOOK, status: Optional[str] = None) -> list[dict[str, Any]]:
    lessons = load(path)["lessons"]
    return [les for les in lessons if status in (None, "all") or les.get("status", "pending") == status]


def decide(path: str | Path, lesson_id: str, status: str, *, reviewer: str, reason: str) -> dict[str, Any]:
    if status not in DECISIONS:
        raise ReviewError(f"status must be one of {DECISIONS}")
    who, why = _require(reviewer, reason)
    data = load(path)
    lesson = _find(data, lesson_id)
    leaks = label_leak_findings(ReflexionLesson.model_validate(lesson), fields=PROMPT_FACING_LESSON_FIELDS)
    if status == "approved" and leaks:
        raise ReviewError(f"refusing to approve: gold-label leak in prompt-facing text: {leaks}")
    lesson.update(status=status, reviewer=who, reviewed_at=utc_now_iso(), reviewer_rationale=why)
    _replace(data, lesson)
    _save(path, data)
    return lesson


def edit(
    path: str | Path,
    lesson_id: str,
    *,
    reviewer: str,
    reason: str,
    trigger_precondition: Optional[str] = None,
    observed_failure: Optional[str] = None,
    actionable_rule: Optional[str] = None,
) -> dict[str, Any]:
    who, why = _require(reviewer, reason)
    changes = {
        k: v.strip()
        for k, v in (
            ("trigger_precondition", trigger_precondition),
            ("observed_failure", observed_failure),
            ("actionable_rule", actionable_rule),
        )
        if v is not None and v.strip()
    }
    if not changes:
        raise ReviewError("nothing to edit: pass --precondition, --failure or --rule")
    data = load(path)
    lesson = _find(data, lesson_id)
    lesson.update(changes, status="pending", reviewer=who, reviewed_at=utc_now_iso())
    lesson["reviewer_rationale"] = f"edited: {why}"
    _replace(data, lesson)
    _save(path, data)
    return lesson


def freeze(path: str | Path, *, reviewer: str) -> str:
    who, _ = _require(reviewer, "freeze")
    data = load(path)
    if data.get("frozen"):
        raise ReviewError("playbook is already frozen")
    pending = [les["lesson_id"] for les in data["lessons"] if les.get("status", "pending") == "pending"]
    if pending:
        raise ReviewError(f"cannot freeze with pending lessons: {pending}")
    digest = playbook_sha256(data["lessons"])
    data.update(frozen=True, frozen_sha256=digest, frozen_by=who, frozen_at=utc_now_iso())
    _save(path, data)
    return digest


def unfreeze(path: str | Path, *, reviewer: str, reason: str) -> None:
    who, why = _require(reviewer, reason)
    data = load(path)
    if not data.get("frozen"):
        raise ReviewError("playbook is not frozen")
    for key in ("frozen_sha256", "frozen_by", "frozen_at"):
        data.pop(key, None)
    data.update(frozen=False, unfrozen_by=who, unfrozen_at=utc_now_iso(), unfreeze_reason=why)
    _save(path, data)
