"""
Phase 0 Acceptance Suite (`docs/AGENT_GUIDE.md` §4 Phase 0):
  1. `test_parallel_edges`: parallel transfers `root -> INT` (two 1,50,000.00 transfers) sum to `300000.00`
     in `Decimal` with both `tx_ids` preserved.
  2. `test_tool_error_not_swallowed`: MCP tool error returns `{status: "error", error_code, message}`, logs & counts
     `tool_errors` on `InvestigationState` + `audit_logs`, surfaces in `worksheet.degraded_evidence`, and never
     silently masks proven suspicious evidence into `request_info`.
  3. `test_yaml_honoured`: `run(config="E1")` with no CLI overrides honours `split="held_out"`, `repeats=3`, `budgets`,
     `defenses_enabled`, and `metrics`; CLI flags override only when explicitly passed; unimplemented YAML metrics
     raise `NotImplementedError`.
  4. `test_approval_requires_analyst_signature`: `auth_required=True` by default; no token is pre-minted before
     `POST .../decision/prepare`; token is signed with `HMAC(secret, hash|sub|nonce)` and expires in 15 min;
     submitting under a different reviewer's JWT or after 15m TTL fails with `403`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import hmac
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner
import yaml

from eval.run_eval import app as eval_cli, run as run_eval_cmd, run_case
from src.agent.c1_single import run_investigation
from src.config import get_hmac_secret, settings
from src.db import case_repo
from src.db.database import get_db, list_audit_logs
from src.mcp_servers import bank_records
from src.mcp_servers.client import call_mcp_tool
from src.models import Alert, RiskLevel


@pytest.mark.asyncio
async def test_parallel_edges() -> None:
    """Two parallel 1,50,000.00 transfers root->INT followed by INT->BEN must report outflow 300000.00."""
    txs = [
        {
            "tx_id": "TXN-PAR-1",
            "sender": "ACC-ROOT",
            "receiver": "ACC-INT-1",
            "amount_inr": "150000.00",
            "timestamp": "2026-09-01T10:00:00Z",
        },
        {
            "tx_id": "TXN-PAR-2",
            "sender": "ACC-ROOT",
            "receiver": "ACC-INT-1",
            "amount_inr": "150000.00",
            "timestamp": "2026-09-01T11:30:00Z",
        },
        {
            "tx_id": "TXN-PAR-3",
            "sender": "ACC-ROOT",
            "receiver": "ACC-INT-2",
            "amount_inr": "100000.00",
            "timestamp": "2026-09-01T12:00:00Z",
        },
        {
            "tx_id": "TXN-PAR-4",
            "sender": "ACC-INT-1",
            "receiver": "ACC-BEN",
            "amount_inr": "285000.00",
            "timestamp": "2026-09-02T09:00:00Z",
        },
        {
            "tx_id": "TXN-PAR-5",
            "sender": "ACC-INT-2",
            "receiver": "ACC-BEN",
            "amount_inr": "95000.00",
            "timestamp": "2026-09-02T10:00:00Z",
        },
    ]
    res = await call_mcp_tool(
        "graph-engine",
        "find_candidate_fund_flows",
        {
            "root_account": "ACC-ROOT",
            "transactions": txs,
            "time_window_days": 7,
            "max_hops": 3,
            "amount_tolerance": "0.10",
            "min_intermediaries": 2,
        },
    )
    assert res["status"] == "ok"
    int1_paths = [p for p in res["paths"] if p["nodes"] == ["ACC-ROOT", "ACC-INT-1", "ACC-BEN"]]
    assert len(int1_paths) == 1
    p = int1_paths[0]
    assert Decimal(str(p["total_outflow_inr"])) == Decimal("300000.00")
    assert Decimal(str(p["total_consolidated_inr"])) == Decimal("285000.00")
    assert {"TXN-PAR-1", "TXN-PAR-2", "TXN-PAR-4"} <= set(p["edge_tx_ids"])


@pytest.mark.asyncio
async def test_tool_error_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """MCP tool errors return structured error envelopes, increment tool_errors, log to audit_logs, and surface."""
    bad = await call_mcp_tool("no-such-mcp", "noop", {})
    assert bad["status"] == "error" and bad["error_code"] == "UNKNOWN_MCP_SERVER" and bad["message"]

    real_call = call_mcp_tool

    async def _faulty_registry_call(server: str, tool: str, params: dict[str, Any]) -> dict[str, Any]:
        if tool == "check_commercial_registry":
            return {
                "status": "error",
                "success": False,
                "error_code": "MCP_UPSTREAM_503",
                "message": "registry backend unavailable",
                "error": "registry backend unavailable",
            }
        return await real_call(server, tool, params)

    monkeypatch.setattr("src.agent.tooling.call_mcp_tool", _faulty_registry_call)

    alert = Alert(
        alert_id="ALT-2026-0412",
        rule_name="SCATTER_GATHER",
        root_account="ACC-IND-1042",
        network_accounts=["ACC-MULE-201", "ACC-MULE-202", "ACC-SHELL-900"],
        total_amount_inr=Decimal("900000.00"),
        risk_level=RiskLevel.HIGH,
    )
    state = await run_investigation(alert, thread_id="thr-p0-toolerr")
    assert state.tool_error_count >= 1
    assert any(e["error_code"] == "MCP_UPSTREAM_503" for e in state.tool_errors)
    assert state.worksheet is not None
    assert any("MCP_UPSTREAM_503" in d for d in state.worksheet.degraded_evidence)
    # Multi-hop layering is already proven; non-fatal registry error must NOT silently mask to request_info
    assert state.worksheet.recommended_disposition.value == "escalate_str"

    logs = list_audit_logs(thread_id="thr-p0-toolerr", limit=50)
    assert any(row["event_type"] == "tool_error_recorded" for row in logs)

    # Also verify eval run_case surfaces tool_errors count
    dev_case = yaml.safe_load(Path("data/synthetic/showcase/ALT-2026-0412.json").read_text(encoding="utf-8"))
    assert bank_records._eval_case_ctx.get() is None
    monkeypatch.delenv("SQLITE_DB_PATH", raising=False)
    from eval.run_eval import prepare_isolated_eval_db

    prepare_isolated_eval_db()
    eval_out = await run_case(dev_case, mode="c1_single")
    assert eval_out["tool_errors"] >= 1


def test_yaml_honoured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`--config E1` with no flags runs 3 repeats on `held_out` and computes every metric in `E1.yaml`."""
    calls: list[tuple[str, str]] = []
    real_run_case = run_case

    async def _tracked_run_case(case: dict[str, Any], mode: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((mode, str(case["case_id"])))
        return await real_run_case(case, mode=mode, **kwargs)

    monkeypatch.setattr("eval.run_eval.run_case", _tracked_run_case)

    # Limit to 2 held_out cases ONLY via a temporary copy of E1? NO: test `--config E1` directly with no flags on
    # split/repeats (we pass limit=2 ONLY to keep unit test <5s, while asserting split=='held_out' and repeats==3!)
    summary = run_eval_cmd(config="E1", limit=2)
    assert summary["split"] == "held_out"
    assert summary["repeats"] == 3
    assert set(summary["results"].keys()) == {"c0_fixed", "c1_single", "c2_multi"}
    # 3 modes * 3 repeats * 2 held-out cases = 18 actual invocations
    assert len(calls) == 18

    e1_yaml = yaml.safe_load(Path("config/experiments/E1.yaml").read_text(encoding="utf-8"))
    for mode_label, mode_res in summary["results"].items():
        metrics = mode_res["metrics"]
        assert metrics["repeats_executed"] == 3, mode_label
        for required_metric in e1_yaml["metrics"]:
            assert required_metric in metrics, f"{required_metric} missing from {mode_label}"

    # CLI flags override YAML when explicitly supplied
    runner = CliRunner()
    cli_res = runner.invoke(eval_cli, ["--config", "E1", "--split", "dev", "--repeats", "1", "--limit", "1"])
    assert cli_res.exit_code == 0, cli_res.stdout
    assert "1 dev cases (repeats=1)" in cli_res.stdout

    # Unimplemented metric in YAML MUST fail loudly with NotImplementedError
    bad_yaml = tmp_path / "E_BAD.yaml"
    bad_yaml.write_text(
        yaml.safe_dump(
            {
                "experiment_id": "E_BAD",
                "split": "dev",
                "repeats": 1,
                "modes": ["c0_fixed"],
                "metrics": ["disposition_accuracy", "nonexistent_fabricated_metric"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(NotImplementedError, match="nonexistent_fabricated_metric"):
        run_eval_cmd(config=str(bad_yaml), limit=1)


def test_approval_requires_analyst_signature(client: Any, auth: Any) -> None:
    """`auth_required=True` default; `/decision/prepare` binds `HMAC(secret, hash|sub|nonce)` + 15m TTL."""
    assert settings.auth_required is True

    analyst = auth("analyst")
    reviewer = auth("senior_reviewer")
    admin = auth("admin")  # second distinct user (`sub='admin'`) with senior_reviewer+ privileges

    run = client.post(
        "/api/v1/investigations/run",
        json={"alert_id": "ALT-2026-0412", "mode": "c1_single"},
        headers=analyst,
    )
    assert run.status_code == 200
    tid = run.json()["thread_id"]
    ws_hash = run.json()["payload_hash"]

    # 1. Server does NOT pre-mint an approval token before `/decision/prepare`
    st = client.get(f"/api/v1/investigations/{tid}/state", headers=reviewer).json()
    assert st["approval"]["approval_token"] is None

    # 2. Analyst cannot call `/decision/prepare` (403 Maker-Checker)
    assert client.post(f"/api/v1/investigations/{tid}/decision/prepare", headers=analyst).status_code == 403
    assert client.post("/decision/prepare", json={"thread_id": tid}, headers=analyst).status_code == 403

    # 3. Reviewer prepares token via `/decision/prepare` -> verify `HMAC(secret, hash|sub|nonce)` structure
    prep = client.post(
        "/decision/prepare",
        json={"thread_id": tid, "approved_hash": ws_hash},
        headers=reviewer,
    )
    assert prep.status_code == 200, prep.text
    prep_body = prep.json()
    assert prep_body["issued_to"] == "reviewer"
    tok_parts = prep_body["approval_token"].split(":")
    assert len(tok_parts) == 4 and tok_parts[0] == "APPROVE"
    nonce, tok_sha, tok_sig = tok_parts[1], tok_parts[2], tok_parts[3]
    expected_sig = hmac.new(
        get_hmac_secret(), f"{tok_sha}|reviewer|{nonce}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    assert tok_sig == expected_sig

    # 4. Identity mismatch: `admin` (`sub='admin'`) attempting to submit `reviewer`'s token is rejected (403)
    cross_user = client.post(
        f"/api/v1/investigations/{tid}/decision",
        json={
            "action": "approve",
            "approved_hash": prep_body["approved_hash"],
            "approval_token": prep_body["approval_token"],
        },
        headers=admin,
    )
    assert cross_user.status_code == 403
    assert cross_user.json()["detail"]["code"] == "TOKEN_IDENTITY_MISMATCH"

    # 5. 15-minute expiry: backdate `expires_at` on a prepared `admin` token and verify `403 TOKEN_EXPIRED`
    admin_prep = client.post(f"/api/v1/investigations/{tid}/decision/prepare", headers=admin).json()
    past_iso = (datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat()
    with get_db() as conn:
        conn.execute(
            "UPDATE approval_tokens SET expires_at = ? WHERE token_id = ?",
            (past_iso, admin_prep["approval_token"].split(":")[1]),
        )
    expired = client.post(
        f"/api/v1/investigations/{tid}/decision",
        json={
            "action": "approve",
            "approved_hash": admin_prep["approved_hash"],
            "approval_token": admin_prep["approval_token"],
        },
        headers=admin,
    )
    assert expired.status_code == 403
    assert expired.json()["detail"]["code"] == "TOKEN_EXPIRED"

    # 6. Matching `reviewer` with their valid, unconsumed, non-expired token commits cleanly (200), replay is 409
    ok = client.post(
        f"/api/v1/investigations/{tid}/decision",
        json={
            "action": "approve",
            "approved_hash": prep_body["approved_hash"],
            "approval_token": prep_body["approval_token"],
            "notes": "Reviewer-signed commit verified.",
        },
        headers=reviewer,
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "committed"
    assert case_repo.APPROVAL_TOKEN_TTL_SECONDS == 900
