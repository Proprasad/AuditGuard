"""Milestone T3: durable checkpoint persistence and mid-run crash/resume (FR-6)."""

import pytest

from src.agent.c0_fixed import run_fixed_pipeline
from src.agent.c1_single import SimulatedCrashInterrupt, run_investigation
from src.agent.c2_multi import run_multi_agent
from src.db.database import get_db, load_checkpoint
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


@pytest.mark.asyncio
async def test_c0_and_c2_specialist_crash_resume_and_idempotent_draft(client, auth):
    alert = Alert(
        alert_id="ALT-2026-0412",
        rule_name="SCATTER_GATHER_900K",
        root_account="ACC-IND-1042",
        total_amount_inr="900000.00",
        risk_level=RiskLevel.HIGH,
    )
    headers = auth("analyst")

    # C0 crash after gather_evidence -> exact resume without duplicating worksheets
    with pytest.raises(SimulatedCrashInterrupt):
        await run_fixed_pipeline(alert=alert, thread_id="thr-crash-c0", stop_after_node="gather_evidence")
    r_c0 = client.post("/api/v1/investigations/thr-crash-c0/resume", headers=headers)
    assert r_c0.status_code == 200 and r_c0.json()["status"] == "interrupt_required"

    # C2 crash right after flow_tracer specialist -> exact resume from specialist checkpoint
    with pytest.raises(SimulatedCrashInterrupt):
        await run_multi_agent(alert=alert, thread_id="thr-crash-c2", stop_after_node="flow_tracer")
    cp_c2 = load_checkpoint("thr-crash-c2")
    assert cp_c2 is not None and cp_c2["current_node"] == "flow_tracer"
    r_c2 = client.post("/api/v1/investigations/thr-crash-c2/resume", headers=headers)
    assert r_c2.status_code == 200 and r_c2.json()["status"] == "interrupt_required"
    assert r_c2.json()["replan_count"] >= 1

    # Idempotent draft check: resuming an already paused thread does not create duplicate worksheets
    r_c2_again = client.post("/api/v1/investigations/thr-crash-c2/resume", headers=headers)
    assert r_c2_again.status_code == 200
    with get_db() as conn:
        ws_cnt = conn.execute("SELECT COUNT(*) FROM worksheets WHERE thread_id = 'thr-crash-c2'").fetchone()[0]
    assert ws_cnt == 1
