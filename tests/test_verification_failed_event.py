"""verification_failed is a first-class terminal SSE event and blocks the approval token (fail-closed)."""

import pytest

from src.api.services import runner
from src.db.database import read_events
from src.models import Alert, RiskLevel

ALERT = Alert(
    alert_id="ALT-2026-0412",
    rule_name="SCATTER_GATHER_900K",
    root_account="ACC-IND-1042",
    total_amount_inr="900000.00",
    risk_level=RiskLevel.HIGH,
)


@pytest.mark.asyncio
async def test_failed_verification_emits_terminal_event_and_issues_no_token(monkeypatch):
    original = runner.execute_mode

    async def failing(alert, mode, thread_id, resume=False, on_event=None):
        state = await original(alert, mode, thread_id, resume=resume, on_event=on_event)
        state.error = "verification_failed"
        return state

    monkeypatch.setattr(runner, "execute_mode", failing)
    thread_id = runner.register_thread(ALERT, "c1_single", "tester")
    assert await runner.run_thread(thread_id, ALERT, "c1_single") == "verification_failed"
    last = read_events(thread_id)[-1]
    assert last["event"] == "verification_failed" and last["event"] in runner.TERMINAL_EVENTS
    assert last["approval_token"] is None and last["approved_hash"] is None
