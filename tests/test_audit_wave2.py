"""Audit Wave 2 regression tests (finding IDs refer to docs/audit/AUDIT_REPORT.md)."""

from __future__ import annotations

from typing import Any

import pytest

# --------------------------------------------------------------------------- AG-14 tipping-off guardrail

TIPPING_OFF = [
    "Inform the customer that an STR has been filed with FIU-IND.",
    "We should notify the account holder about the suspicious transaction report.",
    "Let the client know they are under investigation for these transfers.",
    "Share the STR with the customer before closing the case.",
    "Tip off the beneficiary regarding our suspicion.",
    "Please tell the subject that the account is being monitored and reported to FIU.",
    "Disclose the suspicious activity report to the account holder.",
]
LEGITIMATE = [
    "Do not inform the customer that an STR has been filed.",
    "Never notify the account holder about the suspicious transaction report.",
    "Request source-of-funds documents from the customer for TXN-1.",
    "File the STR with FIU-IND without disclosing it to the customer.",
    "Escalate to the MLRO; avoid tipping-off the customer.",
    "The customer was informed that the KYC refresh is due.",
    "Notify FIU-IND of the suspicious transaction report within 7 days.",
]


@pytest.mark.parametrize("text", TIPPING_OFF)
def test_tipping_off_detected(text: str) -> None:
    from src.core.verifier_patterns import check_tipping_off

    assert check_tipping_off(text), text


@pytest.mark.parametrize("text", LEGITIMATE)
def test_legitimate_customer_language_not_flagged(text: str) -> None:
    from src.core.verifier_patterns import check_tipping_off

    assert check_tipping_off(text) == [], text


def _worksheet(rationale: str) -> dict[str, Any]:
    return {
        "recommended_disposition": "escalate_str",
        "confidence_score": "0.80",
        "recommendation_rationale": rationale,
        "hypotheses": [],
        "regulatory_citations": [],
        "fund_flow_paths": [],
    }


def test_verifier_fails_closed_on_tipping_off() -> None:
    from src.core.verifier import verify_worksheet

    res = verify_worksheet(_worksheet(TIPPING_OFF[0]), {})
    assert res.checks["no_tipping_off"] is False
    assert any(d.code == "TIPPING_OFF" for d in res.discrepancies)
    clean = verify_worksheet(_worksheet(LEGITIMATE[0]), {})
    assert clean.checks["no_tipping_off"] is True


def test_output_guardrail_blocks_tipping_off() -> None:
    from src.guardrails.guardrails import apply_output_guardrails

    blocked = apply_output_guardrails(TIPPING_OFF[1])
    assert not blocked.allowed and "tipping_off" in (blocked.blocked_reason or "")
    assert apply_output_guardrails(LEGITIMATE[1]).allowed


def test_case_actions_server_side_check_downgrades_tipping_off() -> None:
    from src.mcp_servers.case_actions import _enforce_server_side_verification

    content = {**_worksheet(TIPPING_OFF[2]), "verification_status": "passed"}
    out = _enforce_server_side_verification(content, None)
    assert out["verification_status"] == "failed"
    assert out["recommended_disposition"] == "request_info"
    assert out["verification_discrepancies"][0]["code"] == "TIPPING_OFF"


# --------------------------------------------------------------------------- AG-18 erasure ordering


def _run_and_customer(client: Any, auth: Any) -> tuple[str, str]:
    from src.db.database import get_db

    run = client.post(
        "/api/v1/investigations/run", json={"alert_id": "ALT-2026-0412", "mode": "c1_single"}, headers=auth("analyst")
    )
    assert run.status_code == 200, run.text
    with get_db() as conn:
        cust = conn.execute(
            "SELECT acc.customer_id FROM alerts a JOIN accounts acc ON a.seed_account_id = acc.account_id "
            "WHERE a.alert_id = 'ALT-2026-0412'"
        ).fetchone()[0]
    return str(run.json()["thread_id"]), str(cust)


def _saver_rows(thread_id: str) -> int:
    import sqlite3

    from src.agent.graph import checkpoint_db_path

    with sqlite3.connect(str(checkpoint_db_path())) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM checkpoints WHERE thread_id = ?", (thread_id,)).fetchone()[0])


def _full_name(customer_id: str) -> str:
    from src.db.database import get_db

    with get_db() as conn:
        return str(conn.execute("SELECT full_name FROM customers WHERE customer_id = ?", (customer_id,)).fetchone()[0])


def _last_forget_event() -> tuple[str, str]:
    from src.db.database import get_db

    with get_db() as conn:
        row = conn.execute(
            "SELECT event_type, details_json FROM audit_logs WHERE thread_id = 'memory-forget' ORDER BY log_id DESC"
        ).fetchone()
    return str(row[0]), str(row[1])


def test_erasure_purges_checkpoint_saver_before_operational_redaction(client: Any, auth: Any, monkeypatch: Any) -> None:
    from src.api.services import erasure

    tid, cust = _run_and_customer(client, auth)
    assert _saver_rows(tid) > 0
    seen: dict[str, str] = {}
    real_purge = erasure._purge_langgraph_saver

    def spy(threads: list[str]) -> int:
        seen["name_at_purge"] = _full_name(cust)
        return real_purge(threads)

    monkeypatch.setattr(erasure, "_purge_langgraph_saver", spy)
    resp = client.delete(f"/api/v1/memory/{cust}", headers=auth("senior_reviewer"))
    assert resp.status_code == 200, resp.text
    assert seen["name_at_purge"] != "[REDACTED]", "saver must be purged before the operational commit"
    assert _saver_rows(tid) == 0 and _full_name(cust) == "[REDACTED]"


def test_erasure_saver_failure_changes_nothing_and_is_reported(client: Any, auth: Any, monkeypatch: Any) -> None:
    import sqlite3

    from src.api.services import erasure

    tid, cust = _run_and_customer(client, auth)

    def broken(_threads: list[str]) -> int:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(erasure, "_purge_langgraph_saver", broken)
    resp = client.delete(f"/api/v1/memory/{cust}", headers=auth("senior_reviewer"))
    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "ERASURE_INCOMPLETE"
    assert resp.json()["detail"]["stage"] == "checkpoint_saver"
    assert _full_name(cust) != "[REDACTED]" and _saver_rows(tid) > 0
    event, details = _last_forget_event()
    assert event == "customer_erasure_failed" and "checkpoint_saver" in details and cust not in details


def test_erasure_operational_failure_is_reported_and_retry_completes(client: Any, auth: Any, monkeypatch: Any) -> None:
    import sqlite3

    from src.api.services import erasure

    tid, cust = _run_and_customer(client, auth)
    real_redact = erasure._redact_operational

    def broken(*_a: Any, **_k: Any) -> dict[str, int]:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(erasure, "_redact_operational", broken)
    resp = client.delete(f"/api/v1/memory/{cust}", headers=auth("senior_reviewer"))
    assert resp.status_code == 503 and resp.json()["detail"]["stage"] == "operational"
    assert _saver_rows(tid) == 0, "checkpoint PII is already gone (over-erasure is the safe direction)"
    assert _last_forget_event()[0] == "customer_erasure_failed"

    monkeypatch.setattr(erasure, "_redact_operational", real_redact)
    retry = client.delete(f"/api/v1/memory/{cust}", headers=auth("senior_reviewer"))
    assert retry.status_code == 200 and _full_name(cust) == "[REDACTED]"
    assert _last_forget_event()[0] == "customer_memory_deleted"


# --------------------------------------------------------------------------- AG-25 magic numbers live in config


def test_magic_numbers_live_in_policy_with_unchanged_values() -> None:
    from decimal import Decimal

    from src.config import get_policy

    p = get_policy()
    lim = p.agent_limits
    assert (lim.c1_max_turns, lim.c2_specialist_max_turns) == (12, 4)
    assert (lim.c2_replan_handoff_budget, lim.c2_replan_max_turns) == (2, 2)
    assert p.approval.token_ttl_seconds == 900
    assert (p.reflector.temperature, p.reflector.max_tokens) == (Decimal("0.1"), 512)
    r = p.retrieval
    assert (r.bm25_k1, r.bm25_b) == (Decimal("1.5"), Decimal("0.75"))
    assert (r.dense_blend.svd, r.dense_blend.subword) == (Decimal("0.40"), Decimal("0.60"))
    w = r.rerank_weights
    assert (w.rrf, w.bm25, w.dense, w.coverage, w.bigram, w.title, w.id_hit) == tuple(
        Decimal(x) for x in ("0.35", "0.25", "0.20", "0.10", "0.06", "0.04", "0.35")
    )
    a = r.abstention
    assert (a.bm25_min, a.bm25_soft_min, a.bm25_per_token, a.dense_min, a.coverage_min, a.term_hit_min) == (
        Decimal("10.5"), Decimal("9.5"), Decimal("1.15"), Decimal("0.44"), Decimal("0.34"), 2
    )
    assert (a.short_query_bm25_min, a.short_query_dense_min, a.low_term_dense_min) == (
        Decimal("4.5"), Decimal("0.30"), Decimal("0.48")
    )
    q = p.query_typology
    assert (q.multi_tier_min_hops, q.fee_skim_min_retention_pct, q.staggered_min_span_days) == (4, Decimal("5.0"), 10)


@pytest.mark.asyncio
async def test_c1_turn_cap_is_read_from_policy() -> None:
    from src.agent.loop import run_c1_agent_loop
    from src.agent.planning import RunContext
    from src.agent.tooling import GuardedToolbox
    from src.config import get_policy
    from src.models import Alert, InvestigationState, RiskLevel
    from tests.fakes import FakeLLM, make_text_turn

    base = get_policy()
    policy = base.model_copy(update={"agent_limits": base.agent_limits.model_copy(update={"c1_max_turns": 1})})
    ctx = RunContext(mode="c1_single", policy=policy, ledger=policy.new_ledger(), boxes={}, label="c1", role="c1")
    ctx.boxes["primary"] = GuardedToolbox("c1_single", ctx.ledger, "thr-turns")
    fake = FakeLLM([make_text_turn("thinking")] * 5)
    alert = Alert(
        alert_id="ALT-2026-0412", rule_name="SCATTER_GATHER_900K", root_account="ACC-IND-1042",
        total_amount_inr="900000.00", risk_level=RiskLevel.HIGH,
    )
    await run_c1_agent_loop(InvestigationState(thread_id="thr-turns", alert=alert), ctx, fake)
    assert len(fake.calls) == 1


# --------------------------------------------------------------------------- AG-27 MCP annotations + catalogue

_READ = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
EXPECTED_ANNOTATIONS = {
    **{t: _READ for t in (
        "get_alert_context", "get_account_transactions", "get_kyc_profile", "get_counterparty_history",
        "check_commercial_registry", "find_candidate_fund_flows", "compute_flow_conservation",
        "compare_graph_runs", "search_regulations", "get_clause_by_id",
    )},
    "draft_disposition_report": {
        "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False
    },
    "submit_case_disposition": {
        "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False
    },
}


@pytest.mark.asyncio
async def test_every_mcp_tool_declares_safety_annotations() -> None:
    from eval.tool_catalogue import collect_tools

    tools = {t["name"]: t for t in await collect_tools()}
    assert set(tools) == set(EXPECTED_ANNOTATIONS)
    for name, expected in EXPECTED_ANNOTATIONS.items():
        got = {k: tools[name]["annotations"].get(k) for k in expected}
        assert got == expected, name


@pytest.mark.asyncio
async def test_tool_catalogue_doc_is_current() -> None:
    from pathlib import Path

    from eval.tool_catalogue import CATALOGUE_PATH, collect_tools, render_catalogue

    expected = render_catalogue(await collect_tools())
    assert Path(CATALOGUE_PATH).read_text(encoding="utf-8") == expected, "run `python -m eval.tool_catalogue`"


# --------------------------------------------------------------------------- AG-09 correlation id + metrics + alert


def test_correlation_id_round_trips_and_invalid_values_are_replaced(client: Any) -> None:
    good = client.get("/health", headers={"X-Correlation-ID": "abc123def456"})
    assert good.headers["X-Correlation-ID"] == "abc123def456"
    bad = client.get("/health", headers={"X-Correlation-ID": "bad id\r\nX-Evil: 1"})
    generated = bad.headers["X-Correlation-ID"]
    assert generated != "bad id\r\nX-Evil: 1" and len(generated) == 12 and generated.isalnum()
    assert client.get("/health").headers["X-Correlation-ID"] != generated


def test_investigation_events_carry_the_request_correlation_id(client: Any, auth: Any) -> None:
    import json

    from src.db.database import get_db

    hdr = {**auth("analyst"), "X-Correlation-ID": "run-corr-0001"}
    body = {"alert_id": "ALT-2026-0412", "mode": "c1_single"}
    run = client.post("/api/v1/investigations/run", json=body, headers=hdr)
    assert run.status_code == 200 and run.headers["X-Correlation-ID"] == "run-corr-0001"
    with get_db() as conn:
        rows = conn.execute(
            "SELECT payload_json FROM investigation_events WHERE thread_id = ?", (run.json()["thread_id"],)
        ).fetchall()
    assert rows and all(json.loads(r[0]).get("correlation_id") == "run-corr-0001" for r in rows)


def test_masked_500_reports_the_request_correlation_id(isolated_operational_db: Any, monkeypatch: Any) -> None:
    from fastapi.testclient import TestClient

    from src.api.main import app
    from src.api.routes import investigations
    from tests.conftest import TEST_ENV, USERS

    def explode(_limit: int) -> list[Any]:
        raise RuntimeError("boom")

    monkeypatch.setattr(investigations, "list_checkpoints", explode)
    with TestClient(app, raise_server_exceptions=False) as tc:
        user, key = USERS["analyst"]
        tok = tc.post("/api/v1/auth/token", json={"username": user, "password": TEST_ENV[key]}).json()["access_token"]
        resp = tc.get(
            "/api/v1/investigations", headers={"Authorization": f"Bearer {tok}", "X-Correlation-ID": "err-corr-0001"}
        )
    assert resp.status_code == 500
    assert resp.json() == {"detail": "INTERNAL_ERROR", "correlation_id": "err-corr-0001"}
    assert resp.headers["X-Correlation-ID"] == "err-corr-0001"


def _sample(name: str, labels: dict[str, str]) -> float:
    from prometheus_client import REGISTRY

    return float(REGISTRY.get_sample_value(name, labels) or 0.0)


@pytest.mark.asyncio
async def test_mcp_tool_metrics_and_correlation_meta(isolated_operational_db: Any, monkeypatch: Any) -> None:
    import fastmcp

    from src.mcp_servers.client import call_mcp_tool
    from src.observability.correlation import bind_correlation_id

    seen: list[Any] = []
    real_call = fastmcp.Client.call_tool

    async def spy(self: Any, name: str, arguments: Any = None, **kw: Any) -> Any:
        seen.append(kw.get("meta"))
        return await real_call(self, name, arguments, **kw)

    monkeypatch.setattr(fastmcp.Client, "call_tool", spy)
    ok_labels = {"server": "compliance-kb", "tool": "get_clause_by_id", "status": "ok"}
    err_labels = {"server": "compliance-kb", "tool": "get_clause_by_id", "status": "CLAUSE_NOT_FOUND"}
    calls = "auditguard_mcp_tool_calls_total"
    ok0, err0 = _sample(calls, ok_labels), _sample(calls, err_labels)
    bind_correlation_id("mcp-corr-0001")
    good = await call_mcp_tool("compliance-kb", "get_clause_by_id", {"clause_id": "PMLA-2002-S3-P01"})
    bad = await call_mcp_tool("compliance-kb", "get_clause_by_id", {"clause_id": "NOPE-1"})
    assert good.get("status") != "error" and bad.get("error_code") == "CLAUSE_NOT_FOUND"
    assert _sample("auditguard_mcp_tool_calls_total", ok_labels) == ok0 + 1
    assert _sample("auditguard_mcp_tool_calls_total", err_labels) == err0 + 1
    dur = {"server": "compliance-kb", "tool": "get_clause_by_id"}
    assert _sample("auditguard_mcp_tool_duration_seconds_count", dur) >= 2
    assert seen and all(m == {"correlation_id": "mcp-corr-0001"} for m in seen)


@pytest.mark.asyncio
async def test_llm_call_metrics_recorded_for_replayed_calls(tmp_path: Any) -> None:
    import httpx

    from src.llm import LLMClient

    def handler(_: httpx.Request) -> httpx.Response:
        msg = {"role": "assistant", "content": "ok"}
        return httpx.Response(200, json={
            "model": "openai/gpt-5-mini", "choices": [{"finish_reason": "stop", "message": msg}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
        })

    cas = tmp_path / "c.jsonl"
    rec = LLMClient(mode="record", cassette_path=cas, run_id="m", runs_dir=tmp_path, api_key="sk-or-test",
                    transport=httpx.MockTransport(handler))
    labels = {"model": "openai/gpt-5-mini", "mode": "record", "status": "ok"}
    before = _sample("auditguard_llm_calls_total", labels)
    tok_before = _sample("auditguard_llm_tokens_total", {"model": "openai/gpt-5-mini", "kind": "prompt"})
    await rec.chat([{"role": "user", "content": "hi"}], model="openai/gpt-5-mini")
    assert _sample("auditguard_llm_calls_total", labels) == before + 1
    assert _sample("auditguard_llm_tokens_total", {"model": "openai/gpt-5-mini", "kind": "prompt"}) == tok_before + 100

    rep = LLMClient(mode="replay", cassette_path=cas, run_id="m2", runs_dir=tmp_path, api_key="")
    rep_labels = {"model": "openai/gpt-5-mini", "mode": "replay", "status": "ok"}
    rep_before = _sample("auditguard_llm_calls_total", rep_labels)
    await rep.chat([{"role": "user", "content": "hi"}], model="openai/gpt-5-mini")
    assert _sample("auditguard_llm_calls_total", rep_labels) == rep_before + 1
    miss_labels = {"model": "openai/gpt-5-mini", "mode": "replay", "status": "error"}
    miss_before = _sample("auditguard_llm_calls_total", miss_labels)
    with pytest.raises(Exception):  # noqa: B017 - CassetteMissError; the metric is what is asserted
        await rep.chat([{"role": "user", "content": "unseen"}], model="openai/gpt-5-mini")
    assert _sample("auditguard_llm_calls_total", miss_labels) == miss_before + 1


def test_mcp_repeated_failure_alert_rule_exists() -> None:
    from pathlib import Path

    import yaml

    rules = yaml.safe_load(Path("monitoring/alerts.yml").read_text(encoding="utf-8"))["groups"][0]["rules"]
    rule = next(r for r in rules if r["alert"] == "MCPRepeatedFailures")
    assert "auditguard_mcp_tool_calls_total" in rule["expr"] and 'status!="ok"' in rule["expr"]
    assert rule["labels"]["severity"] == "critical"


# --------------------------------------------------------------------------- AG-29 live per-tool SSE events


@pytest.mark.asyncio
async def test_llm_loop_emits_one_event_per_tool_call_as_it_happens() -> None:
    from src.agent.loop import run_c1_agent_loop
    from src.agent.planning import TOOL_EVENT_NODE, RunContext
    from src.agent.tooling import GuardedToolbox
    from src.config import get_policy
    from src.models import Alert, InvestigationState, RiskLevel
    from tests.fakes import FakeLLM, make_text_turn, make_tool_turn

    events: list[tuple[str, dict[str, Any]]] = []
    fake: FakeLLM

    def second_turn(_m: Any, _t: Any) -> Any:
        streamed = [e[1]["tool"] for e in events]
        assert streamed == ["get_alert_context", "calc"], "events must stream before the next turn"
        return make_text_turn("done")

    fake = FakeLLM([
        make_tool_turn(("get_alert_context", {"alert_id": "ALT-2026-0412"}), ("calc", {"op": "sum", "values": ["1"]})),
        second_turn,
    ])
    policy = get_policy()
    ctx = RunContext(mode="c1_single", policy=policy, ledger=policy.new_ledger(), boxes={}, label="c1", role="c1",
                     emit=lambda name, data: events.append((name, data)))
    ctx.boxes["primary"] = GuardedToolbox("c1_single", ctx.ledger, "thr-sse")
    alert = Alert(alert_id="ALT-2026-0412", rule_name="SCATTER_GATHER_900K", root_account="ACC-IND-1042",
                  total_amount_inr="900000.00", risk_level=RiskLevel.HIGH)
    await run_c1_agent_loop(InvestigationState(thread_id="thr-sse", alert=alert), ctx, fake, max_turns=2)
    assert all(name == TOOL_EVENT_NODE for name, _ in events)
    first = events[0][1]
    assert first["role"] == "c1_single" and first["status"] == "ok" and first["call_index"] == 1


def test_runner_turns_tool_events_into_tool_executed_sse() -> None:
    from src.agent.planning import TOOL_EVENT_NODE
    from src.api.services.runner import _node_events

    out = _node_events(TOOL_EVENT_NODE, {"role": "flow_tracer", "tool": "find_candidate_fund_flows", "status": "ok",
                                          "error_code": None, "call_index": 3})
    assert out[0][0] == "tool_executed" and out[0][1]["category"] == "mcp_tool"
    assert "find_candidate_fund_flows" in out[0][1]["message"]


# --------------------------------------------------------------------------- AG-10 logout (workbench + Chainlit)


def test_workbench_has_a_logout_control_wired_to_revocation() -> None:
    from pathlib import Path

    static = Path("src/ui/static")
    html = (static / "index.html").read_text(encoding="utf-8")
    app_js = (static / "js" / "app.js").read_text(encoding="utf-8")
    api_js = (static / "js" / "api.js").read_text(encoding="utf-8")
    assert 'id="btnLogout"' in html and 'id="currentUserLabel"' in html
    assert 'getElementById("btnLogout")' in app_js and "api.logout()" in app_js
    logout_body = api_js[api_js.index("async logout()"):]
    logout_body = logout_body[: logout_body.index("\n  }\n")]
    for needle in ("/api/v1/auth/logout", "this.closeStream()", "this.clearToken()"):
        assert needle in logout_body, needle


def test_api_responses_are_not_cacheable(client: Any, auth: Any) -> None:
    resp = client.get("/api/v1/alerts", headers=auth("analyst"))
    assert resp.status_code == 200 and resp.headers["Cache-Control"] == "no-store"


def test_after_logout_the_token_cannot_read_or_approve(client: Any, auth: Any) -> None:
    analyst, senior = auth("analyst"), auth("senior_reviewer")
    run = client.post(
        "/api/v1/investigations/run", json={"alert_id": "ALT-2026-0412", "mode": "c1_single"}, headers=analyst
    )
    tid = run.json()["thread_id"]
    prep = client.post(f"/api/v1/investigations/{tid}/decision/prepare", headers=senior).json()
    assert client.post("/api/v1/auth/logout", headers=senior).status_code == 200
    assert client.get("/api/v1/investigations", headers=senior).status_code == 401
    body = {"action": "approve", "approved_hash": prep["approved_hash"], "approval_token": prep["approval_token"]}
    assert client.post(f"/api/v1/investigations/{tid}/decision", json=body, headers=senior).status_code == 401


@pytest.mark.asyncio
async def test_chainlit_logout_revokes_the_users_api_token(client: Any, monkeypatch: Any) -> None:
    import importlib
    import sys

    import httpx

    from src.api.main import app as api_app
    from tests.conftest import TEST_ENV, USERS

    monkeypatch.delitem(sys.modules, "src.ui.app", raising=False)  # never reuse a copy built on a chainlit stub
    ui = importlib.import_module("src.ui.app")

    monkeypatch.setenv("CHAINLIT_AUTH_SECRET", "test-chainlit-secret-" + "x" * 40)
    from chainlit.auth import create_jwt

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api_app), base_url="http://api") as hc:
        monkeypatch.setattr(ui, "API_BASE", "http://api")
        user_name, key = USERS["analyst"]
        user = await ui.login_user(hc, user_name, TEST_ENV[key])
        assert user is not None
        api_token = user.metadata["api_token"]
        cookie_jwt = create_jwt(user)
        assert await ui.revoke_from_cookies({"access_token": cookie_jwt}, hc) is True
        after = await hc.get("/api/v1/alerts", headers={"Authorization": f"Bearer {api_token}"})
        assert after.status_code == 401
        assert await ui.revoke_from_cookies({}, hc) is False
        assert await ui.revoke_from_cookies({"access_token": "not-a-jwt"}, hc) is False


# --------------------------------------------------------------------------- AG-21 / AG-19 start/stop + compose


def test_compose_stack_is_named_pinned_and_health_gated() -> None:
    from pathlib import Path

    import yaml

    spec = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    assert spec["name"] == "auditguard-v3"
    services = spec["services"]
    assert all("container_name" not in s for s in services.values()), "fixed names ignore the project name"
    assert all(not str(s.get("image", "x:pinned")).endswith(":latest") for s in services.values())
    for name in ("mcp-compliance-kb", "mcp-graph-engine", "mcp-bank-records", "mcp-case-actions", "api", "ui"):
        assert "healthcheck" in services[name], name
    assert all(v["condition"] == "service_healthy" for v in services["api"]["depends_on"].values())
    assert services["ui"]["depends_on"]["api"]["condition"] == "service_healthy"


def test_start_stop_scripts_are_executable_and_documented() -> None:
    import os
    from pathlib import Path
    import subprocess

    for script in ("scripts/start.sh", "scripts/stop.sh"):
        assert os.access(script, os.X_OK), script
        subprocess.run(["bash", "-n", script], check=True)  # noqa: S603, S607 - fixed repo script
        out = subprocess.run([script, "--help"], check=True, capture_output=True, text=True).stdout  # noqa: S603
        assert "--local" in out
    makefile = Path("Makefile").read_text(encoding="utf-8")
    for target in ("start:", "stop:", "start-local:", "stop-local:"):
        assert f"\n{target}" in makefile, target


# --------------------------------------------------------------------------- AG-33 Postgres service logins


def test_restricted_service_logins_skip_schema_ddl(monkeypatch: Any) -> None:
    from contextlib import contextmanager

    from src.db import database

    calls: list[str] = []

    class FakePg:
        def __init__(self, can_create: bool) -> None:
            self.can_create = can_create

        def execute(self, sql: str, _params: Any = ()) -> Any:
            calls.append(sql)
            row = (self.can_create,)
            return type("Cur", (), {"fetchone": staticmethod(lambda: row)})()

        def executescript(self, _sql: str) -> None:
            calls.append("DDL")

        def executemany(self, _sql: str, _rows: Any) -> None:
            calls.append("SEED")

    for can_create, expect_ddl in ((False, False), (True, True)):
        calls.clear()
        fake = FakePg(can_create)

        @contextmanager
        def fake_db(fake: FakePg = fake) -> Any:
            yield fake

        monkeypatch.setattr(database, "use_postgres_active", lambda: True)
        monkeypatch.setattr(database, "get_db", fake_db)
        database.init_db(force=True)
        assert any("has_schema_privilege" in c for c in calls)
        assert ("DDL" in calls and "SEED" in calls) is expect_ddl


def test_compose_gives_mcp_data_services_their_own_restricted_logins() -> None:
    from pathlib import Path

    import yaml

    svc = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))["services"]
    cw, ro = svc["mcp-case-actions"]["environment"], svc["mcp-bank-records"]["environment"]
    assert cw["POSTGRES_USER"] == "auditguard_case_writer"
    assert "POSTGRES_CASE_WRITER_PASSWORD" in cw["POSTGRES_PASSWORD"]
    assert ro["POSTGRES_USER"] == "auditguard_ro" and "POSTGRES_RO_PASSWORD" in ro["POSTGRES_PASSWORD"]
    pg = svc["postgres"]
    assert any("init_db_roles.sh" in v for v in pg["volumes"])
    assert {"POSTGRES_RO_PASSWORD", "POSTGRES_CASE_WRITER_PASSWORD"} <= set(pg["environment"])
    env_example = Path(".env.example").read_text(encoding="utf-8")
    init_env = Path("scripts/init_env.py").read_text(encoding="utf-8")
    for key in ("POSTGRES_RO_PASSWORD", "POSTGRES_CASE_WRITER_PASSWORD"):
        assert f"{key}=CHANGE_ME" in env_example and f'"{key}"' in init_env
    roles_sh = Path("scripts/init_db_roles.sh").read_text(encoding="utf-8")
    assert "LOGIN PASSWORD" in roles_sh
    ddl = Path("scripts/init_db.sql").read_text(encoding="utf-8")
    assert "REVOKE ALL ON revoked_tokens FROM auditguard_case_writer" in ddl
    assert ddl.index("REVOKE ALL ON users FROM auditguard_ro, auditguard_case_writer") > ddl.index(
        "GRANT SELECT ON ALL TABLES"
    ), (
        "the REVOKE must follow the blanket GRANT, because init_db.sql is re-run at every owner start-up"
    )


# --------------------------------------------------------------------------- AG-28 stale running threads


def _force_status(thread_id: str, status: str) -> None:
    from src.db.database import get_db

    with get_db() as conn:
        conn.execute("UPDATE thread_checkpoints SET status = ? WHERE thread_id = ?", (status, thread_id))


def _status(thread_id: str) -> str:
    from src.db.database import get_db

    with get_db() as conn:
        row = conn.execute("SELECT status FROM thread_checkpoints WHERE thread_id = ?", (thread_id,)).fetchone()
    return str(row[0])


def test_startup_marks_threads_left_running_as_interrupted(client: Any, auth: Any) -> None:
    import json

    from fastapi.testclient import TestClient

    from src.api.main import app
    from src.db.database import get_db

    analyst, senior = auth("analyst"), auth("senior_reviewer")
    tid = client.post(
        "/api/v1/investigations/run", json={"alert_id": "ALT-2026-0412", "mode": "c1_single"}, headers=analyst
    ).json()["thread_id"]
    done = client.post(
        "/api/v1/investigations/run", json={"alert_id": "ALT-2026-0412", "mode": "c0_fixed"}, headers=analyst
    ).json()["thread_id"]
    done_status = _status(done)
    _force_status(tid, "running")  # what a crash mid-run leaves behind
    with TestClient(app):  # a fresh process start runs the lifespan sweep
        pass
    assert _status(tid) == "interrupted" and _status(done) == done_status
    with get_db() as conn:
        last = conn.execute(
            "SELECT event, payload_json FROM investigation_events WHERE thread_id = ? ORDER BY event_id DESC",
            (tid,),
        ).fetchone()
    assert last[0] == "error" and json.loads(last[1])["code"] == "INTERRUPTED"

    prep = client.post(f"/api/v1/investigations/{tid}/decision/prepare", headers=senior)
    assert prep.status_code == 409 and prep.json()["detail"]["code"] == "NOT_READY"
    resumed = client.post(f"/api/v1/investigations/{tid}/resume", headers=analyst)
    assert resumed.status_code == 200, resumed.text
    assert _status(tid) not in ("interrupted", "running")


# --------------------------------------------------------------------------- AG-20 CI accuracy floor


def test_ci_runs_the_dev_accuracy_floor() -> None:
    from pathlib import Path

    ci = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    makefile = Path("Makefile").read_text(encoding="utf-8")
    assert "make eval-gate" in ci
    assert "MIN_ACCURACY ?= 0.45" in makefile and "--min-accuracy $(MIN_ACCURACY)" in makefile
    assert "--split v2_dev" in makefile and "--llm offline" in makefile


# --------------------------------------------------------------------------- AG-04 / AG-32 lesson review + freeze hash


def _playbook(tmp_path: Any, lessons: list[dict[str, Any]], frozen: bool = False) -> Any:
    import json

    p = tmp_path / "playbook.json"
    p.write_text(json.dumps({"frozen": frozen, "lessons": lessons}, indent=2) + "\n", encoding="utf-8")
    return p


def _lesson(
    lid: str, status: str = "pending", rule: str = "Run get_counterparty_history before closing."
) -> dict[str, Any]:
    return {
        "lesson_id": lid,
        "trigger_precondition": "Observed hop depth above 3 with a staggered window",
        "observed_failure": "Stopped after one bounded scan",
        "actionable_rule": rule,
        "status": status,
        "reviewer_rationale": "",
        "created_at": "2026-11-28T00:00:00+00:00",
    }


def test_review_requires_reviewer_reason_and_blocks_label_leaks(tmp_path: Any) -> None:
    from src.reflexion import review

    path = _playbook(tmp_path, [_lesson("LES-A"), _lesson("LES-B", rule="Escalate instead of close_benign.")])
    with pytest.raises(review.ReviewError, match="reviewer"):
        review.decide(path, "LES-A", "approved", reviewer="", reason="ok")
    with pytest.raises(review.ReviewError, match="reason"):
        review.decide(path, "LES-A", "approved", reviewer="alice", reason=" ")
    with pytest.raises(review.ReviewError, match="label"):
        review.decide(path, "LES-B", "approved", reviewer="alice", reason="looks fine")
    review.decide(path, "LES-A", "approved", reviewer="alice", reason="generalises across typologies")
    a = {x["lesson_id"]: x for x in review.load(path)["lessons"]}["LES-A"]
    assert a["status"] == "approved" and a["reviewer"] == "alice" and a["reviewed_at"]
    assert a["reviewer_rationale"] == "generalises across typologies"


def test_edit_returns_lesson_to_pending_and_freeze_needs_zero_pending(tmp_path: Any) -> None:
    from src.reflexion import review

    path = _playbook(tmp_path, [_lesson("LES-A"), _lesson("LES-B")])
    review.decide(path, "LES-A", "approved", reviewer="alice", reason="ok rule")
    review.edit(path, "LES-A", reviewer="bob", reason="tighten", actionable_rule="Check the registry first.")
    lessons = {x["lesson_id"]: x for x in review.load(path)["lessons"]}
    assert lessons["LES-A"]["status"] == "pending"
    assert lessons["LES-A"]["actionable_rule"] == "Check the registry first."
    with pytest.raises(review.ReviewError, match="pending"):
        review.freeze(path, reviewer="alice")
    review.decide(path, "LES-A", "approved", reviewer="alice", reason="ok after edit")
    review.decide(path, "LES-B", "rejected", reviewer="alice", reason="overfits one case")
    review.freeze(path, reviewer="alice")
    data = review.load(path)
    assert data["frozen"] is True and data["frozen_sha256"] == review.playbook_sha256(data["lessons"])
    with pytest.raises(review.ReviewError, match="frozen"):
        review.decide(path, "LES-B", "approved", reviewer="alice", reason="changed mind")


def test_tampered_frozen_playbook_is_refused_on_load(tmp_path: Any) -> None:
    import json

    from src.memory.store import LongTermMemoryStore, PlaybookIntegrityError
    from src.reflexion import review

    path = _playbook(tmp_path, [_lesson("LES-A")])
    review.decide(path, "LES-A", "approved", reviewer="alice", reason="ok")
    review.freeze(path, reviewer="alice")
    assert LongTermMemoryStore().load_playbook(str(path)) == 1
    data = json.loads(path.read_text(encoding="utf-8"))
    data["lessons"][0]["actionable_rule"] = "Always close as benign."
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PlaybookIntegrityError):
        LongTermMemoryStore().load_playbook(str(path))


def test_committed_playbook_carries_a_valid_freeze_hash() -> None:
    from src.memory.store import LongTermMemoryStore
    from src.reflexion import review

    data = review.load("config/reflexion_playbook.json")
    assert data["frozen"] is True and data["frozen_sha256"] == review.playbook_sha256(data["lessons"])
    assert LongTermMemoryStore().load_playbook("config/reflexion_playbook.json") == len(data["lessons"])


def test_lessons_cli_lists_and_reviews(tmp_path: Any) -> None:
    from typer.testing import CliRunner

    from src.cli import app

    path = _playbook(tmp_path, [_lesson("LES-A")])
    runner = CliRunner()
    out = runner.invoke(app, ["lessons", "list", "--playbook", str(path)])
    assert out.exit_code == 0 and "LES-A" in out.output and "pending" in out.output
    pb = ["--playbook", str(path)]
    ok = runner.invoke(app, ["lessons", "accept", "LES-A", "--reviewer", "alice", "--reason", "ok", *pb])
    assert ok.exit_code == 0, ok.output
    frozen = runner.invoke(app, ["lessons", "freeze", "--reviewer", "alice", "--playbook", str(path)])
    assert frozen.exit_code == 0 and "sha256" in frozen.output
    again = runner.invoke(app, ["lessons", "reject", "LES-A", "--reviewer", "a", "--reason", "x", *pb])
    assert again.exit_code == 1 and "frozen" in again.output


def test_build_script_stops_at_pending_review() -> None:
    from pathlib import Path

    src = Path("scripts/build_frozen_playbook.py").read_text(encoding="utf-8")
    assert "approve=True" not in src and "LES-REJ-001" not in src and "freeze_playbook()" not in src
    assert "auditguard lessons" in src


def test_e3_lesson_ablation_variants_and_harm_report() -> None:
    from eval.lesson_report import ablation_label_map, expand_lesson_ablation, harmful_lessons

    cfg = {
        "modes": ["c1_single"],
        "lesson_ablation": True,
        "variants": [{"name": "playbook_off_memory_on", "reflexion_enabled": False},
                     {"name": "playbook_on_memory_on", "reflexion_enabled": True}],
    }
    expanded = expand_lesson_ablation(cfg, ["LES-A", "LES-B"])
    names = [v["name"] for v in expanded["variants"]]
    assert names[-2:] == ["playbook_on_minus_LES-A", "playbook_on_minus_LES-B"]
    assert ablation_label_map(expanded) == {"c1_single_playbook_on_minus_LES-A": ["LES-A"],
                                            "c1_single_playbook_on_minus_LES-B": ["LES-B"]}
    results = {
        "c1_single_playbook_on_memory_on": {"metrics": {"disposition_accuracy": 0.50, "weighted_error_cost": 1.0}},
        "c1_single_playbook_on_minus_LES-A": {"metrics": {"disposition_accuracy": 0.55, "weighted_error_cost": 0.9}},
        "c1_single_playbook_on_minus_LES-B": {"metrics": {"disposition_accuracy": 0.45, "weighted_error_cost": 1.2}},
    }
    report = {(r["lesson_id"], r["mode"]): r for r in harmful_lessons(results, expanded)}
    assert report[("LES-A", "c1_single")]["harmful"] is True
    assert report[("LES-B", "c1_single")]["harmful"] is False
    assert report[("LES-A", "c1_single")]["delta_accuracy"] == pytest.approx(0.05)


def test_lesson_ablation_hides_a_lesson_only_inside_the_block() -> None:
    from eval.lesson_report import lesson_ablation
    from src.memory.store import LongTermMemoryStore, ReflexionLesson

    store = LongTermMemoryStore()
    store.add_lesson(ReflexionLesson(lesson_id="LES-A", trigger_precondition="hop depth", observed_failure="x",
                                     actionable_rule="check registry", status="approved"))
    store.freeze_playbook()
    with lesson_ablation(store, ["LES-A"]):
        assert store.retrieve_top_lessons("hop depth registry", 3) == []
    assert [x.lesson_id for x in store.retrieve_top_lessons("hop depth registry", 3)] == ["LES-A"]


# --------------------------------------------------------------------------- AG-07 / AG-08 opt-in neural retrieval


def test_default_retrieval_backend_is_builtin() -> None:
    from src.config import get_policy

    r = get_policy().retrieval
    assert r.backend == "builtin"
    assert r.embedding_model and r.reranker_model


def test_neural_backend_falls_back_to_builtin_when_rag_extra_missing(monkeypatch: Any) -> None:
    from src.mcp_servers import compliance_kb, neural_retrieval

    idx = compliance_kb.get_regulatory_index()
    query = "structuring cash deposits below the CTR threshold"
    builtin = [c.clause_id for c in idx.search(query, top_k=5)]

    def unavailable(*_a: Any, **_k: Any) -> Any:
        raise neural_retrieval.NeuralBackendUnavailable("sentence-transformers not installed")

    monkeypatch.setattr(neural_retrieval, "get_neural_retriever", unavailable)
    compliance_kb.set_backend_override("neural")
    try:
        assert [c.clause_id for c in idx.search(query, top_k=5)] == builtin
    finally:
        compliance_kb.set_backend_override(None)


def test_neural_backend_ranks_with_embeddings_and_cross_encoder(monkeypatch: Any) -> None:
    from src.mcp_servers import compliance_kb, neural_retrieval

    idx = compliance_kb.get_regulatory_index()
    target = len(idx.clauses) - 1

    class StubNeural:
        def dense_scores_all(self, _query: str) -> list[float]:
            return [1.0 if i == target else 0.01 for i in range(len(idx.clauses))]

        def rerank(self, _query: str, candidates: list[int]) -> list[tuple[int, float]]:
            return sorted(((i, 0.99 if i == target else 0.10) for i in candidates), key=lambda x: -x[1])

    monkeypatch.setattr(neural_retrieval, "get_neural_retriever", lambda *_a, **_k: StubNeural())
    compliance_kb.set_backend_override("neural")
    try:
        hits = idx.search("suspicious transaction report filing obligations FIU-IND", top_k=3)
    finally:
        compliance_kb.set_backend_override(None)
    assert hits and hits[0].clause_id == idx.clauses[target].clause_id and hits[0].relevance_score == 0.99


def test_query_expansion_table_is_frozen() -> None:
    from src.config import get_policy
    from src.core.canonical import canonical_sha256
    from src.mcp_servers.compliance_kb import _STOPWORDS, DOMAIN_CONCEPTS

    tables = {"concepts": DOMAIN_CONCEPTS, "stopwords": sorted(_STOPWORDS)}
    assert canonical_sha256(tables) == get_policy().retrieval.expansion_table_sha256, (
        "the hand-written synonym table changed: re-measure retrieval, then update retrieval.expansion_table_sha256"
    )


# --------------------------------------------------------------------------- AG-12 C2 replan budget


def _c2_supervisor_fake(replan_requests: int, flow_tracer_complies: bool) -> Any:
    import json

    from tests.fakes import FakeLLM, make_text_turn, make_tool_turn

    plan = json.dumps({"steps": ["trace", "kyc", "reg", "critic"], "handoffs": [
        {"task_id": "HO-FLOW", "target_agent": "flow_tracer", "objective": "scan", "allowed_tool_budget": 4},
        {"task_id": "HO-BENIGN", "target_agent": "benign_investigator", "objective": "kyc", "allowed_tool_budget": 3},
        {"task_id": "HO-REG", "target_agent": "regulatory_analyst", "objective": "reg", "allowed_tool_budget": 2},
        {"task_id": "HO-CRITIC", "target_agent": "reporter_critic", "objective": "draft", "allowed_tool_budget": 2},
    ]})
    yes = json.dumps({"request_replan": True, "time_window_days": 18, "max_hops": 4, "amount_tolerance": "0.15",
                      "reason": "widen the window"})
    no = json.dumps({"request_replan": False, "reason": "enough evidence"})
    state = {"replan_checks": 0}

    def supervisor(messages: list[dict[str, Any]], tools: Any) -> Any:
        if "request_replan" not in str(messages[-1].get("content", "")):
            return make_text_turn(plan)
        state["replan_checks"] += 1
        return make_text_turn(yes if state["replan_checks"] <= replan_requests else no)

    def flow_tracer(messages: list[dict[str, Any]], tools: Any) -> Any:
        directive = "replan_directive" in str(messages[0].get("content", ""))
        last_is_tool = messages[-1].get("role") == "tool"
        if directive and flow_tracer_complies and not last_is_tool:
            return make_tool_turn(("replan_graph", {"time_window_days": 18, "max_hops": 4,
                                                    "amount_tolerance": "0.15", "reason": "widen"}))
        if not directive and not any(m.get("role") == "tool" for m in messages):
            return make_tool_turn(("get_alert_context", {"alert_id": "ALT-2026-0412"}))
        return make_text_turn("done")

    fake = FakeLLM(role_scripts={
        "C2 Investigation Supervisor": [supervisor] * 20,
        "Specialist `flow_tracer`": [flow_tracer] * 40,
    })
    return fake, state


@pytest.mark.asyncio
async def test_c2_replans_terminate_when_the_flow_tracer_ignores_the_directive() -> None:
    from src.agent.c2_multi import run_multi_agent
    from src.config import get_policy
    from src.models import Alert, RiskLevel

    fake, seen = _c2_supervisor_fake(replan_requests=99, flow_tracer_complies=False)
    alert = Alert(alert_id="ALT-2026-0412", rule_name="SCATTER_GATHER_900K", root_account="ACC-IND-1042",
                  total_amount_inr="900000.00", risk_level=RiskLevel.HIGH)
    st = await run_multi_agent(alert, thread_id="thr-c2-noncompliant", llm_client=fake, seed=42)
    assert st.worksheet is not None, "the run must finish with a worksheet, not hit the recursion limit"
    assert st.replan_count == 0
    assert st.replan_attempts == get_policy().budgets.max_replans
    assert seen["replan_checks"] == get_policy().budgets.max_replans


@pytest.mark.asyncio
async def test_c2_can_replan_more_than_once_up_to_the_policy_budget() -> None:
    from src.agent.c2_multi import run_multi_agent
    from src.models import Alert, RiskLevel

    fake, seen = _c2_supervisor_fake(replan_requests=2, flow_tracer_complies=True)
    alert = Alert(alert_id="ALT-2026-0412", rule_name="SCATTER_GATHER_900K", root_account="ACC-IND-1042",
                  total_amount_inr="900000.00", risk_level=RiskLevel.HIGH)
    st = await run_multi_agent(alert, thread_id="thr-c2-two-replans", llm_client=fake, seed=42)
    assert st.worksheet is not None
    assert st.replan_attempts == 2 and st.replan_count == 2
    assert seen["replan_checks"] == 3, "asked twice, then declined"


# --------------------------------------------------------------------------- AG-05 subject history (memory reads)


def _seed_customer_history(customer_id: str, alert_id: str, disposition: str) -> None:
    from src.memory.store import memory_store

    memory_store.save_case_episode(
        customer_id,
        {"alert_id": alert_id, "disposition": disposition, "reviewer_id": "reviewer", "payload_hash": "h"},
        human_approved=True,
    )


def _root_customer(account_id: str) -> str:
    from src.db.database import get_db

    with get_db() as conn:
        return str(conn.execute("SELECT customer_id FROM accounts WHERE account_id = ?", (account_id,)).fetchone()[0])


def test_subject_history_is_scoped_stale_labelled_and_gated(isolated_operational_db: Any) -> None:
    from src.memory.subject_history import subject_history
    from src.models import Alert, RiskLevel

    alert = Alert(alert_id="ALT-2026-0412", rule_name="SCATTER_GATHER_900K", root_account="ACC-IND-1042",
                  total_amount_inr="900000.00", risk_level=RiskLevel.HIGH)
    cust = _root_customer("ACC-IND-1042")
    assert subject_history(alert, memory_enabled=True) is None, "no approved history yet"
    _seed_customer_history("CUST-SOMEONE-ELSE", "ALT-OTHER-1", "escalate_str")
    assert subject_history(alert, memory_enabled=True) is None, "another customer's history never leaks"
    _seed_customer_history(cust, "ALT-2026-0412", "close_benign")  # the same alert: would leak its own answer
    assert subject_history(alert, memory_enabled=True) is None
    _seed_customer_history(cust, "ALT-2025-0099", "request_info")
    hist = subject_history(alert, memory_enabled=True)
    assert hist is not None and [e["alert_id"] for e in hist["prior_dispositions"]] == ["ALT-2025-0099"]
    assert "may be stale" in hist["note"] and "not evidence" in hist["note"]
    assert subject_history(alert, memory_enabled=False) is None


@pytest.mark.asyncio
async def test_c1_prompt_carries_wrapped_subject_history_only_when_present(isolated_operational_db: Any) -> None:
    from src.agent.c1_single import run_investigation
    from src.models import Alert, RiskLevel
    from tests.fakes import FakeLLM, make_text_turn

    alert = Alert(alert_id="ALT-2026-0412", rule_name="SCATTER_GATHER_900K", root_account="ACC-IND-1042",
                  total_amount_inr="900000.00", risk_level=RiskLevel.HIGH)
    plain = FakeLLM([make_text_turn("x")] * 3)
    await run_investigation(alert, llm_client=plain, thread_id="thr-hist-0")
    assert "subject_history" not in str(plain.calls[0]["messages"])

    _seed_customer_history(_root_customer("ACC-IND-1042"), "ALT-2025-0099", "request_info")
    fake = FakeLLM([make_text_turn("x")] * 3)
    await run_investigation(alert, llm_client=fake, thread_id="thr-hist-1")
    user_msg = str(fake.calls[0]["messages"][1]["content"])
    assert '<untrusted_data source="memory:subject_history">' in user_msg and "ALT-2025-0099" in user_msg


# --------------------------------------------------------------------------- AG-06 lesson retrieval


def _lesson_store() -> Any:
    from src.memory.store import LongTermMemoryStore, ReflexionLesson

    store = LongTermMemoryStore()
    for lid, pre in (
        ("LES-SCATTER", "Outbound scatter legs present within 7 days but zero consolidation legs"),
        ("LES-SKIM", "Consolidated inflow is 5-12% lower than distributed outflow"),
        ("LES-OTHER", "Dormant account reactivated with high-velocity IMPS credits"),
    ):
        store.add_lesson(ReflexionLesson(lesson_id=lid, trigger_precondition=pre, observed_failure="x",
                                         actionable_rule="do y", status="approved"))
    return store


def test_lessons_need_a_precondition_match_and_are_capped() -> None:
    from src.config import get_policy
    from src.reflexion.retrieval import select_lessons

    store, policy = _lesson_store(), get_policy()
    assert policy.lesson_retrieval.top_k == 2 and policy.lesson_retrieval.min_overlap >= 2
    assert select_lessons(store, "scatter gather 900k alert", policy) == [], "a constant alert query matches nothing"
    hits = select_lessons(store, "outbound scatter legs present zero consolidation legs", policy)
    assert [h.split("]")[0] for h in hits] == ["[LES-SCATTER"]
    both = select_lessons(
        store,
        "outbound scatter legs present zero consolidation legs consolidated inflow lower than distributed outflow "
        "dormant account reactivated high-velocity imps credits",
        policy,
    )
    assert len(both) == 2


def test_observed_features_describe_what_the_scan_found() -> None:
    from src.models import Alert, FundFlowPath, RiskLevel
    from src.reflexion.retrieval import observed_feature_text

    alert = Alert(alert_id="A", rule_name="SCATTER_GATHER_900K", root_account="R", total_amount_inr="900000.00",
                  risk_level=RiskLevel.HIGH)
    txs = [{"sender_account": "R", "receiver_account": "M1", "amount_inr": "450000.00"}]
    assert "zero consolidation" in observed_feature_text(alert, [], txs)
    path = FundFlowPath(path_id="PATH-1", nodes=["R", "M1", "D"], edge_tx_ids=["T1"], total_outflow_inr="900000.00",
                        total_consolidated_inr="828000.00", net_difference_inr="72000.00", retention_pct="8.00",
                        hop_count=2, time_span_days="3.00", amount_leaked_ratio="0.08")
    text = observed_feature_text(alert, [path], txs)
    assert "zero consolidation" not in text and "lower than distributed outflow" in text


# --------------------------------------------------------------------------- AG-11 live context trimming


def test_live_trim_pins_prompt_and_alert_and_keeps_tool_pairs() -> None:
    from src.memory.store import trim_live_context

    msgs: list[dict[str, Any]] = [{"role": "system", "content": "sys"}, {"role": "user", "content": "ALERT"}]
    for i in range(30):
        msgs.append({"role": "assistant", "content": "", "tool_calls": [{"id": f"c{i}"}]})
        msgs.append({"role": "tool", "tool_call_id": f"c{i}", "content": f"result {i}"})
    out = trim_live_context(msgs, window=12)
    assert out[0]["content"] == "sys" and out[1]["content"] == "ALERT"
    assert out[2]["role"] == "user" and '<untrusted_data source="memory:trimmed_turns">' in out[2]["content"]
    assert len(out) <= 12 + 1 and out[3]["role"] == "assistant", "never start the window on an orphan tool reply"
    assert out[-1]["content"] == "result 29"
    assert trim_live_context(msgs[:8], window=12) == msgs[:8], "short conversations are untouched"


# --------------------------------------------------------------------------- AG-24 versioned C2 prompts


def test_c2_prompts_come_from_versioned_yaml() -> None:
    from src.agent.prompts import load_prompt_template, render_c2_supervisor_prompt, render_specialist_prompt
    from src.config import get_policy

    sup, spec = load_prompt_template("c2_supervisor"), load_prompt_template("c2_specialist")
    assert sup.version and spec.version and sup.agent == "c2_supervisor" and spec.agent == "c2_specialist"
    policy = get_policy()
    text = render_c2_supervisor_prompt(policy, ["[LES-X] IF a THEN b"])
    assert text.startswith(f"[PROMPT_VERSION={sup.version} | AGENT=c2_supervisor]\n")
    assert "C2 Investigation Supervisor" in text and f"{policy.budgets.max_tool_calls} tool calls" in text
    assert "- [LES-X] IF a THEN b" in text
    s_text = render_specialist_prompt("flow_tracer", "scan", 3, {"alert_id": "A"})
    assert s_text.startswith(f"[PROMPT_VERSION={spec.version} | AGENT=c2_specialist]\n")
    assert "C2 Specialist `flow_tracer`" in s_text and '"alert_id": "A"' in s_text


@pytest.mark.asyncio
async def test_transcripts_record_the_prompt_version_of_each_call(tmp_path: Any) -> None:
    import json

    import httpx

    from src.llm import LLMClient

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "model": "openai/gpt-5-mini", "choices": [{"finish_reason": "stop", "message": {"role": "assistant",
                                                                                             "content": "ok"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
        })

    client = LLMClient(mode="live", run_id="pv", runs_dir=tmp_path, api_key="sk-or-test",
                       transport=httpx.MockTransport(handler))
    await client.chat([{"role": "system", "content": "[PROMPT_VERSION=9.9.9 | AGENT=c2_supervisor]\nYou are"},
                       {"role": "user", "content": "go"}], model="openai/gpt-5-mini")
    await client.chat([{"role": "user", "content": "no system prompt"}], model="openai/gpt-5-mini")
    assert client.transcript_path is not None
    rows = [json.loads(x) for x in client.transcript_path.read_text(encoding="utf-8").splitlines()]
    assert (rows[0]["prompt_version"], rows[0]["prompt_agent"]) == ("9.9.9", "c2_supervisor")
    assert (rows[1]["prompt_version"], rows[1]["prompt_agent"]) == ("", "")
