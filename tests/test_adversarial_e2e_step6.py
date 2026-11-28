"""
Step 6 Adversarial & Workflow Assurance Suite — Part 2 (Scenarios 13–18).

Covers MultiDiGraph parallel-transfer Decimal conservation, full held-out alert/case/account/TXN
operational DB isolation scan, `.env` newline-injection rejection, full-table right-to-erasure +
Loki PII scrubbing, `respx`-mocked OpenRouter HTTP self-correction, and spawned FastMCP HTTP transport.
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

import httpx
import pytest
import respx

from eval.run_eval import OPERATIONAL_DB, prepare_isolated_eval_db
from src.agent.c1_single import run_investigation
from src.config import settings
from src.core.canonical import to_money
from src.db.database import get_db
from src.guardrails.hooks import decode_llm_tool_content
from src.mcp_servers.client import call_mcp_tool
from src.models import Alert, RiskLevel
from src.observability.redaction import redact_for_logs, redact_text

ROOT = Path(__file__).resolve().parents[1]
ALERT_412 = Alert(
    alert_id="ALT-2026-0412",
    rule_name="SCATTER_GATHER_900K",
    root_account="ACC-IND-1042",
    total_amount_inr="900000.00",
    risk_level=RiskLevel.HIGH,
)


@pytest.mark.asyncio
async def test_13_multidigraph_preserves_5_parallel_transfers_and_decimal_purity():
    assert to_money("0.10") + to_money("0.20") == Decimal("0.30")
    txs = [
        {
            "tx_id": f"TXN-PAR-{i}",
            "sender": "ACC-A",
            "receiver": "ACC-B",
            "amount_inr": f"180000.0{i}",
            "timestamp": f"2026-09-01T1{i}:00:00Z",
        }
        for i in range(1, 6)
    ] + [
        {
            "tx_id": "TXN-CONSOL-1",
            "sender": "ACC-B",
            "receiver": "ACC-C",
            "amount_inr": "880000.15",
            "timestamp": "2026-09-02T10:00:00Z",
        }
    ]
    res = await call_mcp_tool(
        "graph-engine",
        "find_candidate_fund_flows",
        {
            "root_account": "ACC-A",
            "transactions": txs,
            "time_window_days": 7,
            "max_hops": 3,
            "amount_tolerance": "0.10",
        },
    )
    assert res["status"] == "ok"
    two_hop = [p for p in res["paths"] if p["hop_count"] == 2]
    assert len(two_hop) == 1
    assert Decimal(two_hop[0]["total_outflow_inr"]) == Decimal("900000.15")
    assert set(two_hop[0]["edge_tx_ids"]) >= {f"TXN-PAR-{i}" for i in range(1, 6)} | {"TXN-CONSOL-1"}


def test_14_zero_held_out_ids_across_every_table_in_operational_db(monkeypatch):
    held_out_ids: set[str] = set()
    for f in (ROOT / "eval" / "held_out").glob("*.json"):
        data = json.loads(f.read_text(encoding="utf-8"))
        held_out_ids.add(data["alert_id"])
        held_out_ids.add(data["case_id"])
        held_out_ids.add(data["root_account"])
        held_out_ids.update(data.get("network_accounts", []))
        held_out_ids.update(t["tx_id"] for t in data.get("transactions", []) if t.get("tx_id"))
    assert len(held_out_ids) >= 100

    if OPERATIONAL_DB.exists():
        conn = sqlite3.connect(f"file:{OPERATIONAL_DB.as_posix()}?mode=ro", uri=True)
        try:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for tbl in tables:
                dump = json.dumps(conn.execute(f"SELECT * FROM {tbl}").fetchall())  # noqa: S608
                leaked = [hid for hid in held_out_ids if hid in dump]
                assert not leaked, f"Held-out leakage in {tbl}: {leaked}"
        finally:
            conn.close()

    monkeypatch.setenv("SQLITE_DB_PATH", str(OPERATIONAL_DB))
    with pytest.raises(RuntimeError, match="operational DB"):
        prepare_isolated_eval_db()


def test_15_llm_config_newline_env_injection_422_and_non_admin_403(client, auth):
    env_file = ROOT / ".env"
    before = env_file.read_bytes() if env_file.exists() else None
    assert (
        client.post("/api/v1/config/llm", json={"model": "openai/gpt-5-mini"}, headers=auth("analyst")).status_code
        == 403
    )
    inj = client.post(
        "/api/v1/config/llm",
        json={"model": "openai/gpt-5-mini\nAPI_SECRET_KEY=attacker_controlled_secret_value_123456"},
        headers=auth("admin"),
    )
    assert inj.status_code == 422
    after = env_file.read_bytes() if env_file.exists() else None
    assert before == after


def test_16_right_to_erasure_purges_all_tables_and_loki_scrubber(client, auth):
    analyst = auth("analyst")
    senior = auth("senior_reviewer")
    run = client.post(
        "/api/v1/investigations/run", json={"alert_id": "ALT-2026-0412", "mode": "c1_single"}, headers=analyst
    )
    tid = run.json()["thread_id"]
    appr = client.post(f"/api/v1/investigations/{tid}/decision/prepare", headers=senior).json()
    assert (
        client.post(
            f"/api/v1/investigations/{tid}/decision",
            json={
                "action": "approve",
                "approved_hash": appr["approved_hash"],
                "approval_token": appr["approval_token"],
                "notes": "PAN ABCDE1234F",
            },
            headers=senior,
        ).status_code
        == 200
    )

    with get_db() as conn:
        cust_id = conn.execute(
            "SELECT acc.customer_id FROM alerts a JOIN accounts acc ON "
            "a.seed_account_id = acc.account_id WHERE a.alert_id = 'ALT-2026-0412'"
        ).fetchone()[0]
        assert conn.execute("SELECT COUNT(*) FROM entity_profiles WHERE customer_id = ?", (cust_id,)).fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM case_episodes WHERE customer_id = ?", (cust_id,)).fetchone()[0] == 1

    erased = client.delete(f"/api/v1/memory/{cust_id}", headers=senior)
    assert erased.status_code == 200
    with get_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM entity_profiles WHERE customer_id = ?", (cust_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM case_episodes WHERE customer_id = ?", (cust_id,)).fetchone()[0] == 0
        assert (
            conn.execute("SELECT COUNT(*) FROM commercial_registry WHERE customer_id = ?", (cust_id,)).fetchone()[0]
            == 0
        )
        cust_row = conn.execute(
            "SELECT full_name, declared_annual_income_inr, synthetic_pan_hash FROM customers WHERE customer_id = ?",
            (cust_id,),
        ).fetchone()
        assert cust_row["full_name"] == "[REDACTED]" and cust_row["declared_annual_income_inr"] == "0.00"
        assert str(cust_row["synthetic_pan_hash"]).startswith("REDACTED-")
        ws_json = conn.execute("SELECT content_json FROM worksheets WHERE alert_id = 'ALT-2026-0412'").fetchone()[0]
        case_json = conn.execute("SELECT worksheet_json FROM cases WHERE alert_id = 'ALT-2026-0412'").fetchone()[0]
        cp_json = conn.execute("SELECT state_json FROM thread_checkpoints WHERE thread_id = ?", (tid,)).fetchone()[0]
        forget_log = conn.execute(
            "SELECT details_json FROM audit_logs WHERE thread_id = 'memory-forget' ORDER BY log_id DESC LIMIT 1"
        ).fetchone()[0]
    for blob in (ws_json, case_json, cp_json):
        assert json.loads(blob)["redacted"] is True
        assert "ACC-IND-1042" not in blob
    assert cust_id not in forget_log and "customer_id_sha256" in forget_log

    scrubbed_msg = redact_text(f"Reviewed ACC-IND-1042 {cust_id} PAN ABCDE1234F token APPROVE:id:sha:sig")
    scrubbed_extra = redact_for_logs(
        {"reviewer_notes": "Sensitive note", "customer_id": cust_id, "approval_token": "secret"}
    )
    assert "ABCDE1234F" not in scrubbed_msg and "ACC-IND-1042" not in scrubbed_msg and cust_id not in scrubbed_msg
    assert scrubbed_extra["reviewer_notes"] == "[REDACTED]" and scrubbed_extra["customer_id"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_17_respx_mocked_openrouter_http_end_to_end(monkeypatch):
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-respxtestkey1234567890abcdef")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://openrouter.ai/api/v1")

    url = "https://openrouter.ai/api/v1/chat/completions"
    call_idx = 0

    def _tc_resp(calls: list[tuple[str, dict[str, object]]], usage: dict[str, int]) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "openai/gpt-5-mini",
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": f"call_{i + 1}",
                                    "type": "function",
                                    "function": {"name": n, "arguments": json.dumps(a)},
                                }
                                for i, (n, a) in enumerate(calls)
                            ],
                        },
                    }
                ],
                "usage": usage,
            },
        )

    def responder(request: httpx.Request) -> httpx.Response:
        nonlocal call_idx
        call_idx += 1
        body = json.loads(request.content.decode("utf-8"))
        msgs = body["messages"]
        usage = {"prompt_tokens": 550, "completion_tokens": 200, "total_tokens": 750}
        tool_msgs = {
            m["name"]: decode_llm_tool_content(m["content"]) for m in msgs if m.get("role") == "tool" and m.get("name")
        }

        if call_idx == 1:
            return _tc_resp([("get_alert_context", {"alert_id": "ALT-2026-0412"})], usage)
        if call_idx == 2:
            return _tc_resp([("find_candidate_fund_flows", {"root_account": "ACC-IND-1042"})], usage)
        if call_idx == 3:
            return _tc_resp(
                [
                    (
                        "replan_graph",
                        {
                            "time_window_days": 21,
                            "max_hops": 4,
                            "amount_tolerance": "0.15",
                            "reason": "Expand window to capture delayed consolidation leg.",
                        },
                    ),
                    ("get_kyc_profile", {"account_id": "ACC-IND-1042"}),
                    ("search_regulations", {"query": "scatter gather layering", "top_k": 3}),
                ],
                usage,
            )
        p0 = tool_msgs["replan_graph"]["paths"][0]
        kyc_id = tool_msgs["get_kyc_profile"]["evidence_id"]
        clause_id = tool_msgs["search_regulations"]["clauses"][0]["clause_id"]
        if call_idx == 4:
            # Deliberately emit ungrounded INR 777777.00 + prohibited guilt claim to verify 1-round repair
            return _tc_resp(
                [
                    (
                        "finish",
                        {
                            "recommended_disposition": "escalate_str",
                            "confidence_score": "0.89",
                            "recommendation_rationale": "Observed suspicious transfer of INR 777777.00.",
                            "suspicious_hypothesis": {
                                "explanation": "Staggered pass-through across intermediaries.",
                                "confidence": "0.89",
                                "evidence_ids": [p0["path_id"], kyc_id],
                                "regulatory_citations": [clause_id],
                            },
                            "benign_hypothesis": {
                                "explanation": "Money laundering confirmed in benign slot.",
                                "confidence": "0.11",
                                "evidence_ids": [kyc_id],
                                "regulatory_citations": [clause_id],
                            },
                            "missing_evidence": ["Beneficiary bank statement"],
                            "regulatory_citations": [clause_id],
                        },
                    )
                ],
                usage,
            )
        assert "UNGROUNDED_AMOUNT" in str(msgs[-1]["content"])
        return _tc_resp(
            [
                (
                    "finish",
                    {
                        "recommended_disposition": "escalate_str",
                        "confidence_score": "0.89",
                        "recommendation_rationale": (
                            f"Observed dispersal of INR 900000.00 consolidated to INR 828000.00 across "
                            f"{p0['path_id']} ({kyc_id}) under {clause_id}."
                        ),
                        "suspicious_hypothesis": {
                            "explanation": f"Verified staggered consolidation trail on {p0['path_id']}.",
                            "confidence": "0.89",
                            "evidence_ids": [p0["path_id"], kyc_id],
                            "regulatory_citations": [clause_id],
                        },
                        "benign_hypothesis": {
                            "explanation": f"No active commercial registration found for {kyc_id}.",
                            "confidence": "0.11",
                            "evidence_ids": [kyc_id],
                            "regulatory_citations": [clause_id],
                        },
                        "missing_evidence": ["Destination beneficiary source-of-funds records"],
                        "regulatory_citations": [clause_id],
                    },
                )
            ],
            usage,
        )

    with respx.mock(assert_all_called=True) as router:
        router.post(url).mock(side_effect=responder)
        state = await run_investigation(ALERT_412, thread_id="thr-respx-e2e")

    assert call_idx >= 5
    assert state.replan_count == 1
    assert state.plan is not None and state.plan.graph_params.time_window_days == 21
    assert state.error is None
    assert state.worksheet is not None
    assert "INR 900000.00" in state.worksheet.recommendation_rationale
    assert "777777.00" not in state.worksheet.recommendation_rationale
    for hyp in state.worksheet.hypotheses:
        assert "money laundering confirmed" not in hyp.explanation.lower()
    assert state.total_tokens_used >= 3500
    assert state.estimated_cost_usd > Decimal("0")


@pytest.mark.asyncio
async def test_18_spawned_fastmcp_http_server_and_timeout(isolated_operational_db, monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {**os.environ, "MCP_GRAPH_ENGINE_PORT": str(port), "SQLITE_DB_PATH": str(isolated_operational_db)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "src.mcp_servers.graph_engine"],
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
            await asyncio.sleep(0.4)
        else:
            pytest.fail("graph-engine HTTP server did not start")

        monkeypatch.setattr(settings, "mcp_transport", "http")
        monkeypatch.setattr(settings, "mcp_host", "127.0.0.1")
        monkeypatch.setattr(settings, "mcp_graph_engine_port", port)

        ok = await call_mcp_tool(
            "graph-engine",
            "find_candidate_fund_flows",
            {"root_account": "A", "transactions": [], "time_window_days": 7, "max_hops": 3},
            timeout_s=15.0,
        )
        assert ok["status"] == "ok" and ok["calc_id"].startswith("CALC-")

        timed_out = await call_mcp_tool(
            "graph-engine",
            "find_candidate_fund_flows",
            {"root_account": "A", "transactions": [], "time_window_days": 7, "max_hops": 3},
            timeout_s=0.0001,
        )
        assert timed_out["status"] == "error" and timed_out["error_code"] in {
            "MCP_TIMEOUT",
            "MCP_UNAVAILABLE",
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
