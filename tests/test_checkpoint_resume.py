"""Milestone T3: durable checkpoint persistence and mid-run crash/resume (FR-6)."""

import pytest

from src.agent.c1_single import SimulatedCrashInterrupt, run_investigation
from src.db.database import load_checkpoint
from src.models import Alert, RiskLevel


@pytest.mark.asyncio
async def test_mid_run_crash_and_exact_resume(client, auth):
    thread_id = "thr-crash-test-0412"
    alert = Alert(
        alert_id="ALT-2026-0412",
        rule_name="SCATTER_GATHER_900K",
        root_account="ACC-IND-1042",
        total_amount_inr="900000.00",
        risk_level=RiskLevel.HIGH,
    )

    with pytest.raises(SimulatedCrashInterrupt):
        await run_investigation(alert=alert, thread_id=thread_id, stop_after_node="gather_evidence")

    cp = load_checkpoint(thread_id)
    assert cp is not None
    assert cp["current_node"] == "gather_evidence"
    assert cp["status"] == "running"
    assert cp["state"]["tool_calls_used"] >= 4

    resp = client.post(f"/api/v1/investigations/{thread_id}/resume", headers=auth("analyst"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "interrupt_required"
    assert body["worksheet"] is not None
    assert body["worksheet"]["recommended_disposition"] == "escalate_str"
    assert body["replan_count"] >= 1
