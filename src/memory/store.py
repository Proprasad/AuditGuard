"""
Short-Term & Long-Term Memory Layer (Durable SQL Persistence + Isolated Test Store Support)
- Short-term: Rolling 12-message window + deterministic tool-output summary
- Long-term: Namespace-isolated store (`entity_profiles`, `case_episodes`, `reflexion_playbook`)
  persisted in SQLite/PostgreSQL when `persist=True` (default for global singleton),
  or isolated in-memory when instantiated directly in unit tests (`LongTermMemoryStore(persist=False)`).
- Forget API: `forget_customer(customer_id)` wipes profiles & episodes on demand.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
import json
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from src.core.canonical import canonical_sha256, dumps_json
from src.db.database import DbConn, get_db, init_db, utc_now_iso


class ReflexionLesson(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lesson_id: str
    trigger_precondition: str
    observed_failure: str
    actionable_rule: str
    status: str = "pending"  # pending | approved | rejected
    reviewer_rationale: str = ""
    created_at: str = Field(default_factory=utc_now_iso)
    # Human review record (`auditguard lessons ...`); kept in the playbook JSON, the reviewed artifact.
    reviewer: str = ""
    reviewed_at: str = ""


class PlaybookIntegrityError(RuntimeError):
    """A frozen playbook's lessons do not match its recorded `frozen_sha256` (edited after freezing)."""


def playbook_sha256(lessons: list[dict[str, Any]]) -> str:
    """Canonical hash of a playbook's lessons (order-independent, every field included)."""
    return canonical_sha256(sorted(lessons, key=lambda les: str(les.get("lesson_id", ""))))


def trim_messages_with_summary(
    messages: list[dict[str, Any]],
    rolling_summary: str = "",
    window_size: int = 12,
) -> tuple[list[dict[str, Any]], str]:
    """
    Pin leading `system` messages, keep the most recent `window_size` conversational messages without
    splitting an `assistant` tool-call message from its paired `tool` response, and fold evicted messages
    into `rolling_summary`.
    """
    sys_end = 0
    while sys_end < len(messages) and messages[sys_end].get("role") == "system":
        sys_end += 1
    pinned = messages[:sys_end]
    rest = messages[sys_end:]
    budget = max(1, window_size - len(pinned))
    if len(rest) <= budget:
        return messages, rolling_summary

    cut = len(rest) - budget
    while cut > 0 and rest[cut].get("role") == "tool":
        cut -= 1
    overflow = rest[:cut]
    recent = rest[cut:]

    summary_parts = [rolling_summary] if rolling_summary else []
    for msg in overflow:
        role = msg.get("role", "unknown")
        content = str(msg.get("content", ""))[:120]
        summary_parts.append(f"[{role}] {content}")
    return [*pinned, *recent], " | ".join(summary_parts)[-2000:]


def trim_live_context(messages: list[dict[str, Any]], window: int) -> list[dict[str, Any]]:
    """
    Copy of `messages` that fits `window` for the next LLM call (audit AG-11). Pins leading `system` messages and
    the first `user` message (the alert), keeps the most recent turns without orphaning a `tool` reply, and puts a
    summary of the evicted turns (wrapped as untrusted, since it quotes tool output) right after the pinned part.
    """
    from src.guardrails.guardrails import wrap_untrusted_data

    if len(messages) <= window:
        return messages
    head = 0
    while head < len(messages) and messages[head].get("role") == "system":
        head += 1
    if head < len(messages) and messages[head].get("role") == "user":
        head += 1
    pinned, rest = messages[:head], messages[head:]
    keep = max(1, window - len(pinned) - 1)
    cut = max(0, len(rest) - keep)
    while cut < len(rest) and rest[cut].get("role") == "tool":
        cut += 1
    summary = " | ".join(f"[{m.get('role', 'unknown')}] {str(m.get('content', ''))[:120]}" for m in rest[:cut])[-2000:]
    note = {
        "role": "user",
        "content": "Earlier turns were trimmed to fit the context window. Summary of trimmed turns:\n"
        + wrap_untrusted_data(summary, "memory:trimmed_turns"),
    }
    return [*pinned, note, *rest[cut:]]


class LongTermMemoryStore:
    """
    Namespace-isolated long-term memory store.
    `persist=True` stores records durably in the SQLite/PostgreSQL database;
    `persist=False` (default for fresh test instances) keeps isolated per-instance state.
    """

    def __init__(self, persist: bool = False) -> None:
        self._persist = persist
        self._entity_profiles: dict[str, dict[str, Any]] = {}
        self._case_episodes: dict[str, list[dict[str, Any]]] = {}
        self._reflexion_playbook: dict[str, ReflexionLesson] = {}
        self._playbook_frozen: bool = False

    def _db(self) -> AbstractContextManager[DbConn]:
        """Lazily initialised DB context (importing this module never touches disk)."""
        init_db()
        return get_db()

    def reset_in_memory_cache(self) -> None:
        """Clear in-memory caches between isolated test runs."""
        self._entity_profiles.clear()
        self._case_episodes.clear()
        self._reflexion_playbook.clear()
        self._playbook_frozen = False

    def evict_customer_cache(self, customer_id: str) -> tuple[bool, int]:
        """Evict a customer's cached profile and episodes without touching private attributes from callers."""
        profile_removed = self._entity_profiles.pop(customer_id, None) is not None
        episodes_removed = len(self._case_episodes.pop(customer_id, []))
        return profile_removed, episodes_removed

    # ── Entity Profiles ───────────────────────────────────────────────────────
    def save_entity_profile(self, customer_id: str, profile: dict[str, Any]) -> None:
        now = utc_now_iso()
        rec = {**profile, "customer_id": customer_id, "updated_at": now}
        self._entity_profiles[customer_id] = rec
        if self._persist:
            with self._db() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO entity_profiles (customer_id, profile_json, updated_at) VALUES (?, ?, ?)",
                    (customer_id, dumps_json(rec), now),
                )

    def get_entity_profile(self, customer_id: str) -> Optional[dict[str, Any]]:
        if self._persist:
            with self._db() as conn:
                row = conn.execute(
                    "SELECT profile_json FROM entity_profiles WHERE customer_id = ?", (customer_id,)
                ).fetchone()
                return json.loads(row["profile_json"]) if row else None
        return self._entity_profiles.get(customer_id)

    # ── Case Episodes (Human-Approval Gated) ──────────────────────────────────
    def save_case_episode(self, customer_id: str, episode: dict[str, Any], human_approved: bool) -> bool:
        """Writes occur ONLY after human approval."""
        if not human_approved:
            return False
        now = utc_now_iso()
        rec = {**episode, "archived_at": now}
        self._case_episodes.setdefault(customer_id, []).append(rec)
        if self._persist:
            with self._db() as conn:
                conn.execute(
                    "INSERT INTO case_episodes (customer_id, episode_json, archived_at) VALUES (?, ?, ?)",
                    (customer_id, dumps_json(rec), now),
                )
        return True

    def get_case_episodes(self, customer_id: str) -> list[dict[str, Any]]:
        if self._persist:
            with self._db() as conn:
                rows = conn.execute(
                    "SELECT episode_json FROM case_episodes WHERE customer_id = ? ORDER BY episode_id ASC",
                    (customer_id,),
                ).fetchall()
                return [json.loads(r["episode_json"]) for r in rows]
        return list(self._case_episodes.get(customer_id, []))

    # ── Reflexion Playbook ────────────────────────────────────────────────────
    def is_playbook_frozen(self) -> bool:
        if self._persist:
            with self._db() as conn:
                row = conn.execute("SELECT flag_value FROM system_flags WHERE flag_key = 'playbook_frozen'").fetchone()
                return bool(row and row["flag_value"] == "true")
        return self._playbook_frozen

    def freeze_playbook(self) -> None:
        self._playbook_frozen = True
        if self._persist:
            with self._db() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO system_flags (flag_key, flag_value) VALUES ('playbook_frozen', 'true')"
                )

    def add_lesson(self, lesson: ReflexionLesson) -> bool:
        if self.is_playbook_frozen():
            return False
        self._reflexion_playbook[lesson.lesson_id] = lesson
        if self._persist:
            with self._db() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO reflexion_playbook
                    (lesson_id, trigger_precondition, observed_failure, actionable_rule, status, reviewer_rationale,
                    created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        lesson.lesson_id,
                        lesson.trigger_precondition,
                        lesson.observed_failure,
                        lesson.actionable_rule,
                        lesson.status,
                        lesson.reviewer_rationale,
                        lesson.created_at,
                    ),
                )
        return True

    def review_lesson(self, lesson_id: str, approve: bool, rationale: str = "") -> bool:
        if self.is_playbook_frozen():
            return False
        status = "approved" if approve else "rejected"
        if self._persist:
            with self._db() as conn:
                cur = conn.execute(
                    "UPDATE reflexion_playbook SET status = ?, reviewer_rationale = ? WHERE lesson_id = ?",
                    (status, rationale, lesson_id),
                )
                if cur.rowcount == 0:
                    return False
        else:
            if lesson_id not in self._reflexion_playbook:
                return False
            self._reflexion_playbook[lesson_id].status = status
            self._reflexion_playbook[lesson_id].reviewer_rationale = rationale
        return True

    def set_status_for_ablation(self, lesson_id: str, status: str) -> None:
        """Evaluation-only (E3 per-lesson ablation): flip a lesson's status even when frozen, then restore it."""
        if lesson_id in self._reflexion_playbook:
            self._reflexion_playbook[lesson_id].status = status
        if self._persist:
            with self._db() as conn:
                conn.execute("UPDATE reflexion_playbook SET status = ? WHERE lesson_id = ?", (status, lesson_id))

    def list_all_lessons(self) -> list[ReflexionLesson]:
        if self._persist:
            with self._db() as conn:
                rows = conn.execute("SELECT * FROM reflexion_playbook ORDER BY created_at ASC").fetchall()
                return [ReflexionLesson(**dict(r)) for r in rows]
        return list(self._reflexion_playbook.values())

    def load_playbook(self, path: str = "config/reflexion_playbook.json") -> int:
        """Hydrate reviewed Reflexion lessons + frozen flag from an exported playbook artifact."""
        from pathlib import Path

        p = Path(path)
        if not p.exists():
            return 0
        raw = json.loads(p.read_text(encoding="utf-8"))
        if raw.get("frozen") and raw.get("frozen_sha256") != playbook_sha256(list(raw.get("lessons", []))):
            raise PlaybookIntegrityError(f"{p}: lessons changed after freezing (frozen_sha256 mismatch); refusing")
        # Temporarily unfreeze in target store to load exact exported rows, then restore exact frozen state
        self._playbook_frozen = False
        if self._persist:
            with self._db() as conn:
                conn.execute("DELETE FROM system_flags WHERE flag_key = 'playbook_frozen'")
                conn.execute("DELETE FROM reflexion_playbook")
        count = 0
        for item in raw.get("lessons", []):
            lesson = ReflexionLesson(**item)
            self._reflexion_playbook[lesson.lesson_id] = lesson
            if self._persist:
                with self._db() as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO reflexion_playbook "
                        "(lesson_id, trigger_precondition, observed_failure, actionable_rule, "
                        "status, reviewer_rationale, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            lesson.lesson_id,
                            lesson.trigger_precondition,
                            lesson.observed_failure,
                            lesson.actionable_rule,
                            lesson.status,
                            lesson.reviewer_rationale,
                            lesson.created_at,
                        ),
                    )
            count += 1
        if raw.get("frozen"):
            self.freeze_playbook()
        return count

    def retrieve_top_lessons(self, query: str, top_k: int = 3) -> list[ReflexionLesson]:
        approved = [les for les in self.list_all_lessons() if les.status == "approved"]
        words = set(query.lower().split())
        scored = []
        for lesson in approved:
            text = f"{lesson.trigger_precondition} {lesson.observed_failure} {lesson.actionable_rule}".lower()
            overlap = sum(1 for w in words if w in text)
            scored.append((overlap, lesson))
        scored.sort(key=lambda x: -x[0])
        return [les for _, les in scored[:top_k]]

    # ── Forget API (Section 11.1) ─────────────────────────────────────────────
    def forget_customer(self, customer_id: str) -> dict[str, Any]:
        profile_removed = self._entity_profiles.pop(customer_id, None) is not None
        episodes_removed = len(self._case_episodes.pop(customer_id, []))
        if self._persist:
            with self._db() as conn:
                c1 = conn.execute("DELETE FROM entity_profiles WHERE customer_id = ?", (customer_id,))
                c2 = conn.execute("DELETE FROM case_episodes WHERE customer_id = ?", (customer_id,))
                profile_removed = profile_removed or (c1.rowcount > 0)
                episodes_removed = max(episodes_removed, c2.rowcount)
        return {
            "customer_id": customer_id,
            "profile_removed": profile_removed,
            "episodes_removed": episodes_removed,
            "deleted_at": utc_now_iso(),
        }


# Durable SQL-backed singleton used by FastAPI & runtime agents
memory_store = LongTermMemoryStore(persist=True)
