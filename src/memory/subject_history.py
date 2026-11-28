"""
Subject history read (audit AG-05): prior human-approved dispositions for the alert's own customer.

Scope: only the customer who holds the alert's root account, never network counterparties (no cross-subject
leakage), and never an earlier episode of this same alert (that would hand the agent its own previous answer).
The block is labelled as possibly stale context, reaches LLM prompts only inside `<untrusted_data>`, and is off
when `memory_enabled` is False. Episodes exist only after a human approval commit (`save_case_episode`).
"""

from __future__ import annotations

from typing import Any, Optional

from src.config import get_policy
from src.db.database import get_ro_db
from src.guardrails.guardrails import wrap_untrusted_data
from src.memory.store import memory_store
from src.models import Alert

STALE_NOTE = (
    "Prior human-approved disposition(s) for this customer. They may be stale and are context only, "
    "not evidence for this alert: decide from the current transactions and records."
)


def _customer_of(account_id: str) -> Optional[str]:
    with get_ro_db() as conn:
        row = conn.execute("SELECT customer_id FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
    return str(row[0]) if row is not None else None


def subject_history(alert: Alert, *, memory_enabled: bool) -> Optional[dict[str, Any]]:
    if not memory_enabled:
        return None
    customer_id = _customer_of(alert.root_account)
    if customer_id is None:
        return None
    episodes = [e for e in memory_store.get_case_episodes(customer_id) if e.get("alert_id") != alert.alert_id]
    if not episodes:
        return None
    recent = episodes[-get_policy().memory.subject_history_max_episodes :]
    return {
        "scope": "holder of the alert's root account",
        "prior_dispositions": [
            {"alert_id": e.get("alert_id"), "disposition": e.get("disposition"), "reviewed_at": e.get("archived_at")}
            for e in recent
        ],
        "note": STALE_NOTE,
    }


def render_subject_history(history: Optional[dict[str, Any]]) -> str:
    """Prompt block for `history`, or `""` (so prompts are unchanged when there is no history)."""
    if not history:
        return ""
    import json

    payload = json.dumps(history, sort_keys=True)
    return f"\n\nSubject history from long-term memory:\n{wrap_untrusted_data(payload, 'memory:subject_history')}"
