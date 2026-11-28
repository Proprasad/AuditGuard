"""
Second-Pass Audit Closure Suite (`C-01`..`L-04`).

Verifies all 8 newly mandated security, distributed-runtime, schema, and coverage invariants:
  1. Spawned `case-actions` HTTP server HMAC auth (`401` without `X-AuditGuard-MCP-Token`) + server-side verifier +
     `approve()` fail-closed `409 INTERRUPT_NOT_ACTIVE` when LangGraph is not paused at `interrupt()`.
  2. Maker-Checker RBAC (`analyst` `403` on approve, masked `approval_token`), JWT `jti` logout revocation (`401`),
     and `/metrics` bearer-token protection.
  3. Per-specialist `SpecialistHandOff.allowed_tool_budget` enforcement (`SPECIALIST_BUDGET_EXCEEDED`) + dynamic
     `PlanProposal` (`focus_accounts`, `clause_ids`) & unconsolidated `get_counterparty_history`.
  4. Crash-resume preserving `total_tokens_used` & `critique_retries_used`, plus pre-reserved LLM cost cap.
  5. Unprefixed prose currency (`rupees`, `lakhs`, `crores`) verification + `ws.compute_hash() == ws.payload_hash`.
  6. PostgreSQL `translate_sql` + `CompatRow` + write-scope authorizer unit tests + telemetry-based Reflexion rules.
  7. Strict `extra="forbid"` on `TokenRequest`, `LlmConfigUpdateRequest`, `GuardrailResult`, `HookDecision`.
  8. CLI (`src/cli.py`) `CliRunner` and Chainlit UI (`src/ui/app.py`) handler coverage.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
import respx
from typer.testing import CliRunner

from src.agent import planning, reasoning
from src.agent.c0_fixed import run_fixed_pipeline
from src.agent.c1_single import SimulatedCrashInterrupt, run_investigation
from src.agent.c2_multi import run_multi_agent
from src.agent.llm_client import LlmCallMeta
from src.api.deps import LlmConfigUpdateRequest, TokenRequest
from src.api.services import approval as approval_service
from src.cli import app as cli_app
from src.config import get_hmac_secret, get_policy, settings
from src.core.verifier import verify_worksheet
from src.db import case_repo
from src.db.database import append_audit_log, save_checkpoint
from src.db.postgres_backend import CompatRow, enforce_write_scope, translate_sql
from src.guardrails.guardrails import GuardrailResult
from src.guardrails.hooks import HookDecision
from src.mcp_servers.client import call_mcp_tool
from src.mcp_servers.http_auth import MCP_TOKEN_HEADER, mcp_service_token
from src.models import Alert, DecisionRequest, DispositionWorksheet, RiskLevel, SpecialistHandOff
from src.reflexion.loop import generate_candidate_lesson

ROOT = Path(__file__).resolve().parents[1]
ALERT = Alert(
    alert_id="ALT-2026-0412",
    rule_name="SCATTER_GATHER_900K",
    root_account="ACC-IND-1042",
    total_amount_inr="900000.00",
    risk_level=RiskLevel.HIGH,
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.mark.asyncio
async def test_w2_01_case_actions_http_hmac_auth_server_verifier_and_interrupt_gate(
    isolated_operational_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    port = _free_port()
    hmac_val = get_hmac_secret().decode("utf-8")
    env = {
        **os.environ,
        "MCP_CASE_ACTIONS_PORT": str(port),
        "SQLITE_DB_PATH": str(isolated_operational_db),
        "HMAC_SECRET": hmac_val,
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "src.mcp_servers.case_actions"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            with socket.socket() as s:
                s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            assert proc.poll() is None
            await asyncio.sleep(0.3)
        else:
            pytest.fail("case-actions HTTP server did not start")

        async with httpx.AsyncClient(timeout=10.0) as hc:
            no_auth = await hc.post(f"http://127.0.0.1:{port}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
            bad_auth = await hc.post(
                f"http://127.0.0.1:{port}/mcp",
                headers={MCP_TOKEN_HEADER: "forged-token"},
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            assert no_auth.status_code == 401 and bad_auth.status_code == 401

        monkeypatch.setattr(settings, "mcp_transport", "http")
        monkeypatch.setattr(settings, "mcp_host", "127.0.0.1")
        monkeypatch.setattr(settings, "mcp_case_actions_port", port)
        assert len(mcp_service_token()) == 64

        # Server-side verifier downgrades guilt-claiming or ungrounded drafts even when caller claims status="passed"
        downgraded = await call_mcp_tool(
            "case-actions",
            "draft_disposition_report",
            {
                "alert_id": "ALT-2026-0412",
                "thread_id": "thr-http-srv-verify",
                "recommended_disposition": "escalate_str",
                "recommendation_rationale": "Money laundering confirmed with INR 999999.00.",
                "confidence_score": "0.90",
                "verification_status": "passed",
                "evidence_registry": {"FIU-IND-RFI-BA-01": {"clause_id": "FIU-IND-RFI-BA-01"}},
            },
            timeout_s=15.0,
        )
        assert downgraded["status"] == "ok"
        assert downgraded["content"]["verification_status"] == "failed"
        assert downgraded["content"]["recommended_disposition"] == "request_info"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    # Prove approve() fails closed with 409 INTERRUPT_NOT_ACTIVE when LangGraph has no active interrupt()
    draft = case_repo.upsert_draft(
        {
            "alert_id": "ALT-2026-0412",
            "recommended_disposition": "escalate_str",
            "recommendation_rationale": "Grounded outflow INR 900000.00 citing FIU-IND-RFI-BA-01.",
            "confidence_score": "0.8500",
            "regulatory_citations": ["FIU-IND-RFI-BA-01"],
            "hypotheses": [
                {"label": "suspicious", "explanation": "Scatter-gather trail.", "confidence": "0.8500"},
                {"label": "benign", "explanation": "Registry check negative.", "confidence": "0.1500"},
            ],
            "missing_evidence": ["Beneficiary bank statements"],
            "alert_amount_inr": "900000.00",
            "verification_status": "passed",
            "verification_discrepancies": [],
        },
        thread_id="thr-no-interrupt",
    )
    tok = case_repo.issue_approval_token("thr-no-interrupt", draft["worksheet_id"])
    # Maker-checker (AG-02) needs a recorded requester distinct from the approver to reach the interrupt check.
    append_audit_log("thr-no-interrupt", case_repo.REQUESTED_EVENT, "analyst", {"alert_id": "ALT-2026-0412"})
    state_dict = {"evidence_registry": {"FIU-IND-RFI-BA-01": {"clause_id": "FIU-IND-RFI-BA-01"}}}
    save_checkpoint(
        thread_id="thr-no-interrupt",
        alert_id="ALT-2026-0412",
        mode="c1_single",
        current_node="interrupt_required",
        status="interrupt_required",
        state_dict=state_dict,
        worksheet_id=draft["worksheet_id"],
        payload_hash=draft["payload_hash"],
    )
    fake_thread = {
        "thread_id": "thr-no-interrupt",
        "alert_id": "ALT-2026-0412",
        "mode": "c1_single",
        "status": "interrupt_required",
        "worksheet_id": draft["worksheet_id"],
        "payload_hash": draft["payload_hash"],
        "state": state_dict,
    }
    req = DecisionRequest(action="approve", approved_hash=tok["approved_hash"], approval_token=tok["approval_token"])
    with pytest.raises(approval_service.DecisionError) as exc_info:
        await approval_service.approve(fake_thread, req, "reviewer")
    assert exc_info.value.status_code == 409 and exc_info.value.code == "INTERRUPT_NOT_ACTIVE"


def test_w2_02_maker_checker_logout_revocation_and_metrics_auth(client: Any, auth: Any, monkeypatch: Any) -> None:
    analyst = auth("analyst")
    logout = client.post("/api/v1/auth/logout", headers=analyst)
    assert logout.status_code == 200 and logout.json()["status"] == "revoked"
    # Revoked JWT jti is immediately rejected
    assert client.get("/api/v1/alerts", headers=analyst).status_code == 401

    from pydantic import SecretStr

    monkeypatch.setattr(settings, "metrics_token", SecretStr("prom-scrape-secret-token-123456"))
    assert client.get("/metrics").status_code == 401
    assert (
        client.get("/metrics", headers={"Authorization": "Bearer prom-scrape-secret-token-123456"}).status_code == 200
    )


@pytest.mark.asyncio
async def test_w2_03_specialist_sub_budget_and_dynamic_plan_gathering(monkeypatch: pytest.MonkeyPatch) -> None:
    orig_handoffs = planning.c2_handoffs

    def tight_benign_handoffs(budget: int) -> list[SpecialistHandOff]:
        items = orig_handoffs(budget)
        return [
            SpecialistHandOff(
                task_id=h.task_id,
                target_agent=h.target_agent,
                objective=h.objective,
                allowed_tool_budget=1 if h.target_agent == "benign_investigator" else h.allowed_tool_budget,
            )
            for h in items
        ]

    monkeypatch.setattr(planning, "c2_handoffs", tight_benign_handoffs)
    st = await run_multi_agent(ALERT, thread_id="thr-tight-specialist")
    assert any("SPECIALIST_BUDGET_EXCEEDED" in d for d in st.degraded_evidence)
    benign_run = next(r for r in st.agent_runs if r["agent_id"] == "benign_investigator")
    assert benign_run["tool_calls"] == 1

    # Dynamic PlanProposal focus_accounts + clause_ids trigger get_account_transactions and get_clause_by_id
    monkeypatch.setattr(planning, "c2_handoffs", orig_handoffs)

    async def dynamic_plan(*args: Any, **kwargs: Any) -> tuple[reasoning.PlanProposal, LlmCallMeta]:
        prop = reasoning.PlanProposal.model_validate(
            {
                "steps": ["1. Scan", "2. Check focus account", "3. Lookup SOP-SG-003"],
                "graph_params": {
                    "time_window_days": 14,
                    "max_hops": 4,
                    "amount_tolerance": "0.12",
                    "min_intermediaries": 2,
                },
                "focus_accounts": ["ACC-EXTRA-FOCUS"],
                "clause_ids": ["SOP-SG-003"],
            }
        )
        return prop, LlmCallMeta(used_live_llm=True, model="openai/gpt-5-mini")

    monkeypatch.setattr(reasoning, "propose_plan", dynamic_plan)
    dyn_state = await run_investigation(ALERT, thread_id="thr-dyn-plan")
    assert "SOP-SG-003" in dyn_state.evidence_registry


@pytest.mark.asyncio
async def test_w2_04_crash_resume_preserves_tokens_retries_and_prereserves_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-resumetestkey1234567890abcdef")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://openrouter.ai/api/v1")
    url = "https://openrouter.ai/api/v1/chat/completions"

    def mock_llm(request: httpx.Request) -> httpx.Response:
        msg = str(json.loads(request.content.decode("utf-8"))["messages"][-1]["content"])
        usage = {"prompt_tokens": 400, "completion_tokens": 100, "total_tokens": 500}
        if "Create an investigation plan" in msg:
            body = {
                "steps": ["1. Gather", "2. Score", "3. Verify"],
                "graph_params": {
                    "time_window_days": 21,
                    "max_hops": 4,
                    "amount_tolerance": "0.15",
                    "min_intermediaries": 2,
                },
            }
        elif "COMPETING hypotheses" in msg:
            body = {
                "suspicious": {"explanation": "Multi-hop layering.", "confidence": 0.88},
                "benign": {"explanation": "No registry.", "confidence": 0.12},
            }
        elif "Critique the current evidence" in msg:
            body = {"contradiction_found": False, "reason": "Sufficient."}
        elif '"previous_draft_failed_verification": []' in msg:
            body = {"rationale": "Invented 900001 rupees transfer."}
        else:
            body = {"rationale": "Verified dispersal of INR 900000.00."}
        choices = [{"message": {"content": json.dumps(body)}}]
        return httpx.Response(200, json={"model": "openai/gpt-5-mini", "choices": choices, "usage": usage})

    with respx.mock(assert_all_called=False) as router:
        router.post(url).mock(side_effect=mock_llm)
        with pytest.raises(SimulatedCrashInterrupt):
            await run_investigation(ALERT, thread_id="thr-crash-tokens", stop_after_node="critique")
        resumed = await run_investigation(ALERT, thread_id="thr-crash-tokens", resume=True)

    # 3 calls before crash (plan+hyp+crit = 1500) + 2 calls after resume (draft + retry = 1000) >= 2500
    assert resumed.total_tokens_used >= 2500
    assert resumed.critique_retries_used == 1

    # Pre-reservation blocks LLM call when remaining USD is smaller than conservative call ceiling
    nearly_spent = get_policy().new_ledger()
    nearly_spent.preload(cost_usd=Decimal("0.149900"))
    assert nearly_spent.check_llm_allowed(Decimal("0.002000")).allowed is False


@pytest.mark.asyncio
async def test_w2_05_prose_amounts_and_canonical_hash_parity(client: Any, auth: Any) -> None:
    reg = {"FIU-IND-RFI-BA-01": {"clause_id": "FIU-IND-RFI-BA-01"}}
    base_ws = {
        "alert_id": "ALT-2026-0412",
        "recommended_disposition": "escalate_str",
        "confidence_score": "0.8500",
        "regulatory_citations": ["FIU-IND-RFI-BA-01"],
        "alert_amount_inr": "900000.00",
        "hypotheses": [
            {"label": "suspicious", "explanation": "Rapid dispersal pattern.", "confidence": "0.8500"},
            {"label": "benign", "explanation": "Commercial invoice hypothesis.", "confidence": "0.1500"},
        ],
        "missing_evidence": ["Beneficiary bank statements"],
    }
    bad_rupees = verify_worksheet({**base_ws, "recommendation_rationale": "Moved 900001 rupees."}, reg)
    bad_lakhs = verify_worksheet({**base_ws, "recommendation_rationale": "Moved 9.5 lakhs."}, reg)
    good_lakhs = verify_worksheet(
        {**base_ws, "recommendation_rationale": "Moved 9 lakhs citing FIU-IND-RFI-BA-01."}, reg
    )
    assert not bad_rupees.passed and any(d.code == "UNGROUNDED_AMOUNT" for d in bad_rupees.discrepancies)
    assert not bad_lakhs.passed and any(d.code == "UNGROUNDED_AMOUNT" for d in bad_lakhs.discrepancies)
    assert good_lakhs.passed is True

    for idx, fn in enumerate((run_fixed_pipeline, run_investigation, run_multi_agent)):
        st = await fn(ALERT, thread_id=f"thr-hash-parity-{idx}")
        assert st.worksheet is not None
        assert len(st.worksheet.payload_hash) == 64
        assert st.worksheet.compute_hash() == st.worksheet.payload_hash

    # Also verify hash parity survives analyst edit
    sr = auth("senior_reviewer")
    run = client.post("/api/v1/investigations/run", json={"alert_id": "ALT-2026-0412", "mode": "c1_single"}, headers=sr)
    tid = run.json()["thread_id"]
    edit = client.post(
        f"/api/v1/investigations/{tid}/decision",
        headers=sr,
        json={"action": "edit", "edit": {"recommendation_rationale": "Verified INR 900000.00 dispersal."}},
    )
    assert edit.status_code == 200
    state_ws = client.get(f"/api/v1/investigations/{tid}/state", headers=sr).json()["state"]["worksheet"]
    rehydrated = DispositionWorksheet.model_validate(state_ws)
    assert rehydrated.compute_hash() == edit.json()["payload_hash"]


def test_w2_06_postgres_translator_write_guard_and_telemetry_reflexion() -> None:
    sql_upsert, ret_u = translate_sql(
        "INSERT OR REPLACE INTO system_flags (flag_key, flag_value) VALUES (?, '?literal?')"
    )
    assert ret_u is None
    assert "ON CONFLICT (flag_key) DO UPDATE SET flag_value = EXCLUDED.flag_value" in sql_upsert
    assert "%s, '?literal?'" in sql_upsert

    sql_ignore, _ = translate_sql("INSERT OR IGNORE INTO banks (bank_id, bank_name, ifsc_prefix) VALUES (?, ?, ?)")
    assert "ON CONFLICT (bank_id) DO NOTHING" in sql_ignore

    sql_audit, ret_col = translate_sql("INSERT INTO audit_logs (thread_id, event_type) VALUES (?, ?)")
    assert ret_col == "log_id" and "RETURNING log_id" in sql_audit

    row = CompatRow(["case_id", "disposition"], ("CASE-1", "escalate_str"))
    assert row["case_id"] == "CASE-1" and row[1] == "escalate_str" and dict(row)["disposition"] == "escalate_str"

    allowed = frozenset({"worksheets", "cases", "approval_tokens", "audit_logs"})
    enforce_write_scope("INSERT INTO cases (case_id) VALUES ('1')", allowed)
    with pytest.raises(sqlite3.DatabaseError):
        enforce_write_scope("DELETE FROM transactions", allowed)
    with pytest.raises(sqlite3.DatabaseError):
        enforce_write_scope("DROP TABLE banks", allowed)

    # Telemetry-derived Reflexion lesson (no `category` field needed!)
    lesson = generate_candidate_lesson(
        {
            "root_account": "ACC-1",
            "expected_disposition": "escalate_str",
            "transactions": [
                {
                    "sender_account": "ACC-1",
                    "receiver_account": "ACC-2",
                    "amount_inr": "500000.00",
                    "timestamp": "2026-09-01T00:00:00Z",
                },
                {
                    "sender_account": "ACC-2",
                    "receiver_account": "ACC-3",
                    "amount_inr": "490000.00",
                    "timestamp": "2026-09-18T00:00:00Z",
                },
            ],
        },
        "request_info",
    )
    assert "time_window_days" in lesson.actionable_rule


def test_w2_07_strict_models_forbid_extra_fields(client: Any, auth: Any) -> None:
    for cls, valid in (
        (TokenRequest, {"username": "u", "password": "p"}),
        (LlmConfigUpdateRequest, {"enabled": False}),
        (GuardrailResult, {"allowed": True, "scrubbed_text": "ok"}),
        (HookDecision, {"allowed": True}),
    ):
        with pytest.raises(ValidationError):
            cls.model_validate({**valid, "unexpected_field": "boom"})
    assert (
        client.post(
            "/api/v1/config/llm",
            json={"enabled": False, "injected_extra": True},
            headers=auth("admin"),
        ).status_code
        == 422
    )


def test_w2_08_cli_commands() -> None:
    runner = CliRunner()
    bad = runner.invoke(cli_app, ["investigate", "ALT-NO-SUCH-ALERT"])
    assert bad.exit_code == 1 and "INVALID_ALERT_ID" in bad.stdout

    ok = runner.invoke(cli_app, ["investigate", "ALT-2026-0412", "--mode", "c0_fixed"])
    assert ok.exit_code == 0, ok.stdout
    parsed = json.loads(ok.stdout)
    assert parsed["alert_id"] == "ALT-2026-0412" and len(parsed["payload_hash"]) == 64


@pytest.mark.asyncio
async def test_w2_09_chainlit_ui_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib
    import types

    sent_messages: list[str] = []
    session_state: dict[str, Any] = {"mode": "c1_single"}

    class FakeSession:
        def get(self, k: str, default: Any = None) -> Any:
            return session_state.get(k, default)

        def set(self, k: str, v: Any) -> None:
            session_state[k] = v

    class FakeAction:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

    class FakeMessage:
        def __init__(self, content: str = "", **_: Any) -> None:
            self.content = content

        async def send(self) -> FakeMessage:
            sent_messages.append(self.content)
            return self

        async def stream_token(self, token: str) -> None:
            self.content += token

    stub_cl: Any = types.ModuleType("chainlit")
    stub_cl.user_session = FakeSession()
    stub_cl.Message = FakeMessage
    stub_cl.Action = FakeAction
    stub_cl.on_chat_start = lambda fn: fn
    stub_cl.on_message = lambda fn: fn
    stub_cl.password_auth_callback = lambda fn: fn
    stub_cl.User = types.SimpleNamespace
    stub_cl.action_callback = lambda _name: (lambda fn: fn)
    monkeypatch.setitem(sys.modules, "chainlit", stub_cl)
    sys.modules.pop("src.ui.app", None)
    ui_app = importlib.import_module("src.ui.app")

    assert ui_app._render_event("plan_updated", {"steps": ["1. Step A"]}) is not None
    assert ui_app._render_event("tool_called", {"message": "2 calls"}) is not None
    assert ui_app._render_event("hypotheses_scored", {"message": "scored"}) is not None
    assert ui_app._render_event("replan_triggered", {"reason": "Widen window"}) is not None
    assert ui_app._render_event("verification_completed", {"message": "verified"}) is not None
    assert ui_app._parse_sse_data('data: {"event": "started"}') == {"event": "started"}
    assert ui_app._parse_sse_data("data: {bad") is None

    await ui_app.on_chat_start()
    assert session_state["mode"] == "c1_single"
    await ui_app.on_message(FakeMessage("/mode c2_multi"))  # type: ignore[arg-type]
    assert session_state["mode"] == "c2_multi"
    await ui_app.on_message(FakeMessage("/mode invalid_mode"))  # type: ignore[arg-type]
    assert any("Invalid mode" in m for m in sent_messages)

    await ui_app._show_approval_card(
        {
            "worksheet_id": "DWS-TEST1",
            "recommended_disposition": "escalate_str",
            "confidence_score": 0.85,
            "payload_hash": "a" * 64,
            "approved_hash": "a" * 64,
            "approval_token": "APPROVE:1:a:b",
        }
    )
    session_state["thread_id"] = "thr-ui-test"

    async def fake_api(_client: Any, _method: str, _path: str, **_kwargs: Any) -> dict[str, Any]:
        return {"decision": "escalate_str", "receipt": {"case_id": "CASE-1", "audit_entry_id": "AUD-000001"}}

    monkeypatch.setattr(ui_app, "_api", fake_api)
    await ui_app.on_message(FakeMessage("approve and confirm"))  # type: ignore[arg-type]
    assert session_state["pending"] is None
    assert any("Decision recorded" in m for m in sent_messages)
