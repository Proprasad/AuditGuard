"""
Lesson retrieval keyed on observed case features (audit AG-06).

A lesson is offered only when its trigger precondition shares at least `lesson_retrieval.min_overlap` content
words with a plain-language description of what the investigation has actually observed, capped at
`lesson_retrieval.top_k` (config/models.yaml). Before any evidence is gathered, only the alert's rule name is
known, so observation-gated lessons are normally offered after the first graph scan instead.
"""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal
import re
from typing import Any

from src.core.policy import PolicyConfig
from src.mcp_servers.retrieval_lexicon import _STOPWORDS
from src.memory.store import LongTermMemoryStore
from src.models import Alert, FundFlowPath

_TOKEN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def _content_words(text: str) -> set[str]:
    return {t for t in _TOKEN.findall(text.lower()) if t not in _STOPWORDS and len(t) > 1}


def format_lesson(lesson_id: str, precondition: str, rule: str) -> str:
    return f"[{lesson_id}] IF {precondition} THEN {rule}"


def observed_feature_text(alert: Alert, paths: Sequence[FundFlowPath], transactions: Sequence[dict[str, Any]]) -> str:
    """Describe the observed flow in fixed typology vocabulary (no case IDs, amounts or labels)."""
    words = [alert.rule_name.replace("_", " ").lower()]
    outbound = any(str(t.get("sender_account")) == alert.root_account for t in transactions)
    multi = [p for p in paths if p.hop_count >= 2]
    if outbound and not multi:
        words.append("outbound scatter legs present zero consolidation legs")
    if multi:
        max_ret = max(Decimal(str(p.retention_pct)) for p in multi)
        if max_ret > Decimal("0"):
            words.append("consolidated inflow lower than distributed outflow retained fee")
        if max(p.hop_count for p in multi) >= 4:
            words.append("multi tier hop depth layering")
    return " ".join(words)


def select_lessons(store: LongTermMemoryStore, feature_text: str, policy: PolicyConfig) -> list[str]:
    cfg = policy.lesson_retrieval
    query = _content_words(feature_text)
    scored = []
    for les in store.list_all_lessons():
        if les.status != "approved":
            continue
        overlap = len(query & _content_words(les.trigger_precondition))
        if overlap >= cfg.min_overlap:
            scored.append((-overlap, les.lesson_id, les))
    scored.sort(key=lambda x: (x[0], x[1]))
    top = [les for _, _, les in scored[: cfg.top_k]]
    return [format_lesson(les.lesson_id, les.trigger_precondition, les.actionable_rule) for les in top]
