"""Milestone T3: Durable Checkpoint Persistence & Mid-Run Crash/Resume Tests (FR-6)"""
import pytest
from fastapi.testclient import TestClient

from src.agent.c1_single import SimulatedCrashInterrupt, run_investigation
from src.api.main import _threads, app
from src.db.database import load_checkpoint
from src.models import Alert, RiskLevel


@pytest.mark.asyncio
async def test_mid_run_crash_and_exact_resume():
    """Simulate a process crash right after `gather_evidence` and verify clean resume from SQLite checkpoint."""
    thread_id = "thr-crash-test-0412"
    alert = Alert(
        alert_id="ALT-2026-0412",
        rule_name="SCATTER_GATHER_900K",
        root_account="ACC-IND-1042",
        total_amount_inr="900000.00",
        risk_level=RiskLevel.HIGH,
    )

    with pytest.raises(SimulatedCrashInterrupt):
        await run_investigation(
            alert=alert,
            thread_id=thread_id,
            stop_after_node="gather_evidence",
        )

    # Verify durable checkpoint exists in SQLite at exact interrupted node
    cp = load_checkpoint(thread_id)
    assert cp is not None
    assert cp["current_node"] == "gather_evidence"
    assert cp["status"] == "running"
    calls_before_crash = cp["state"]["tool_calls_used"]
    assert calls_before_crash >= 4

    # Clear any in-memory API thread cache to simulate fresh server process boot
    _threads.pop(thread_id, None)

    # Resume via FastAPI crash-recovery endpoint
    client = TestClient(app)
    resp = client.post(f"/api/v1/investigations/{thread_id}/resume")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "interrupt_required"
    assert body["worksheet"] is not None
    assert body["worksheet"]["recommended_disposition"] == "escalate_str"
    assert body["replan_count"] >= 1
