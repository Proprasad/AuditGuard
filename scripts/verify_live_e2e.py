"""
Mandatory Step 7.2 Live End-to-End Workflow Verification (ZERO MOCKS).

Spawns the 4 FastMCP servers over streamable HTTP + FastAPI Uvicorn over TCP with `LLM_ENABLED=true`
(live OpenRouter) and executes `ALT-2026-0007` end-to-end across C0, C1, and C2:
  1. Analyst authentication via POST /api/v1/auth/token -> valid HS256 JWT.
  2. Real-time SSE streaming via POST /api/v1/investigations + GET /stream across C0, C1, C2 with wall-clock deltas.
  3. Direct LangGraph AsyncSqliteSaver inspection proving pause at `human_gate` (`interrupt()`), structured plan,
     competing hypotheses, Decimal `CALC-*` / `PATH-*`, and resolved `TXN-*` / `KYC-*` / `REG-*` IDs.
  4. Adversarial gate probes: unauthenticated (401), missing hash (422), ungrounded 1-INR edit (422), valid edit
     recomputing SHA-256 + voiding old token, stale token attempt (403).
  5. Single-use HMAC approval commit (200) -> LangGraph resumed to END (`next=()`) -> immediate replay rejected (409).
  6. Read-only scan of `data/auditguard.db` confirming 0 held-out leakage.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_tcp(port: int, proc: subprocess.Popen[Any], name: str, timeout_s: float = 45.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited prematurely with code {proc.returncode}")
        time.sleep(0.3)
    raise TimeoutError(f"{name} did not bind port {port} within {timeout_s}s")


async def _stream_to_gate(
    client: httpx.AsyncClient, base_url: str, headers: dict[str, str], alert_id: str, mode: str
) -> tuple[str, list[tuple[float, str, dict[str, Any]]]]:
    t0 = time.perf_counter()
    reg = await client.post(
        f"{base_url}/api/v1/investigations", json={"alert_id": alert_id, "mode": mode}, headers=headers
    )
    assert reg.status_code == 200, reg.text
    tid = reg.json()["thread_id"]

    received: list[tuple[float, str, dict[str, Any]]] = []
    async with client.stream("GET", f"{base_url}/api/v1/investigations/{tid}/stream", headers=headers) as resp:
        assert resp.status_code == 200
        ev_name = "message"
        async for line in resp.aiter_lines():
            if line.startswith("event:"):
                ev_name = line[6:].strip()
            elif line.startswith("data:"):
                dt_ms = round((time.perf_counter() - t0) * 1000, 1)
                payload = json.loads(line[5:].strip())
                received.append((dt_ms, ev_name, payload))
                if ev_name in ("interrupt_required", "verification_failed", "completed", "error"):
                    break
    return tid, received


async def _inspect_langgraph_checkpoint(db_path: Path, tid: str, mode: str) -> dict[str, Any]:
    os.environ["SQLITE_DB_PATH"] = str(db_path)
    from src.agent import c0_fixed
    from src.agent.graph import build_c0_graph, build_graph, make_context, open_saver

    ctx = make_context(mode, tid)
    async with open_saver() as saver:
        sg = (
            build_c0_graph(ctx, tid, c0_fixed.scan_node, c0_fixed.draft_node)
            if mode == "c0_fixed"
            else build_graph(ctx, tid)
        )
        snap = await sg.compile(checkpointer=saver).aget_state({"configurable": {"thread_id": tid}})
    inv = snap.values.get("inv", {}) if snap.values else {}
    interrupts = [intr.value for t in snap.tasks for intr in getattr(t, "interrupts", ())]
    reg_keys = list((inv.get("evidence_registry") or {}).keys())
    return {
        "next_nodes": list(snap.next),
        "has_interrupt": bool(interrupts),
        "interrupt_payload": interrupts[0] if interrupts else None,
        "reasoning_mode": inv.get("reasoning_mode"),
        "replan_count": inv.get("replan_count"),
        "tool_calls_used": inv.get("tool_calls_used"),
        "tokens_used": inv.get("total_tokens_used"),
        "cost_usd": inv.get("estimated_cost_usd"),
        "plan_steps_count": len((inv.get("plan") or {}).get("steps", [])),
        "hypotheses": [(h["label"], h["confidence"]) for h in inv.get("active_hypotheses", [])],
        "calc_ids": [k for k in reg_keys if k.startswith("CALC-")],
        "path_ids": [k for k in reg_keys if k.startswith("PATH-")],
        "txn_count": sum(1 for k in reg_keys if k.startswith("TXN-")),
        "kyc_ids": [k for k in reg_keys if k.startswith("KYC-")],
        "reg_ids": [k for k in reg_keys if k.startswith(("REG-", "SOP-"))],
    }


async def run_verification() -> None:
    dotenv = {k: str(v) for k, v in dotenv_values(ROOT / ".env").items() if v is not None}
    analyst_pw = dotenv.get("ANALYST_PASSWORD") or os.environ.get("ANALYST_PASSWORD", "")
    assert analyst_pw, "ANALYST_PASSWORD missing in .env (run python scripts/init_env.py)"

    # Clone operational DB into a dedicated live-verification copy so operational `data/auditguard.db` stays pristine
    tmp_dir = Path(tempfile.mkdtemp(prefix="auditguard_live_e2e_"))
    live_db = tmp_dir / "live_auditguard.db"
    shutil.copy2(ROOT / "data" / "auditguard.db", live_db)

    p_kb, p_ge, p_br, p_ca, p_api = (_free_port() for _ in range(5))
    env = {
        **os.environ,
        **dotenv,
        "SQLITE_DB_PATH": str(live_db),
        "AUTH_REQUIRED": "true",
        "LLM_ENABLED": "true",
        "MCP_TRANSPORT": "http",
        "MCP_HOST": "127.0.0.1",
        "MCP_COMPLIANCE_KB_PORT": str(p_kb),
        "MCP_GRAPH_ENGINE_PORT": str(p_ge),
        "MCP_BANK_RECORDS_PORT": str(p_br),
        "MCP_CASE_ACTIONS_PORT": str(p_ca),
    }

    procs: list[subprocess.Popen[Any]] = []
    specs = [
        ("mcp-compliance-kb", [sys.executable, "-m", "src.mcp_servers.compliance_kb"], p_kb),
        ("mcp-graph-engine", [sys.executable, "-m", "src.mcp_servers.graph_engine"], p_ge),
        ("mcp-bank-records", [sys.executable, "-m", "src.mcp_servers.bank_records"], p_br),
        ("mcp-case-actions", [sys.executable, "-m", "src.mcp_servers.case_actions"], p_ca),
        (
            "auditguard-api",
            [sys.executable, "-m", "uvicorn", "src.api.main:app", "--host", "127.0.0.1", "--port", str(p_api)],
            p_api,
        ),
    ]

    try:
        print("=== BOOTING LIVE FLEET (4 FastMCP HTTP Servers + FastAPI Uvicorn + Live OpenRouter) ===")
        for name, cmd, port in specs:
            p = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(p)
        for (name, _, port), p in zip(specs, procs, strict=True):
            _wait_tcp(port, p, name)
            print(f"  [ONLINE] {name} -> 127.0.0.1:{port} (pid={p.pid})")

        base = f"http://127.0.0.1:{p_api}"
        async with httpx.AsyncClient(timeout=httpx.Timeout(240.0, connect=10.0)) as client:
            # Step 1: Analyst JWT Authentication
            print("\n=== STEP 1: ANALYST JWT AUTHENTICATION ===")
            bad_login = await client.post(
                f"{base}/api/v1/auth/token", json={"username": "analyst", "password": "wrong"}
            )
            ok_login = await client.post(
                f"{base}/api/v1/auth/token", json={"username": "analyst", "password": analyst_pw}
            )
            assert bad_login.status_code == 401 and ok_login.status_code == 200
            tok_body = ok_login.json()
            headers = {"Authorization": f"Bearer {tok_body['access_token']}"}
            print(f"  Bad credentials -> HTTP {bad_login.status_code}")
            print(
                f"  Valid analyst   -> HTTP {ok_login.status_code} (role={tok_body['role']}, token_prefix={tok_body['access_token'][:24]}...)"
            )

            # Steps 2 & 3: Live SSE + LangGraph Checkpoint Inspection across C0, C1, C2 on ALT-2026-0007
            c2_tid = ""
            c2_terminal: dict[str, Any] = {}
            for mode in ("c0_fixed", "c1_single", "c2_multi"):
                print(f"\n=== STEP 2 & 3 [{mode.upper()}]: LIVE SSE STREAM + LANGGRAPH CHECKPOINT (ALT-2026-0007) ===")
                tid, events = await _stream_to_gate(client, base, headers, "ALT-2026-0007", mode)
                for dt_ms, ev_name, payload in events:
                    print(f"  [+{dt_ms:8.1f} ms] SSE event={ev_name:<22} msg={str(payload.get('message', ''))[:78]}")
                ev_names = [e[1] for e in events]
                assert ev_names[0] == "started" and ev_names[-1] == "interrupt_required", (
                    f"Unexpected SSE sequence: {ev_names}"
                )
                if mode in ("c1_single", "c2_multi"):
                    assert "plan_updated" in ev_names and "hypotheses_scored" in ev_names

                cp_info = await _inspect_langgraph_checkpoint(live_db, tid, mode)
                print("  LangGraph Checkpoint:", json.dumps(cp_info, default=str))
                assert cp_info["next_nodes"] == ["human_gate"] and cp_info["has_interrupt"] is True
                assert cp_info["calc_ids"] and cp_info["txn_count"] >= 3 and cp_info["kyc_ids"] and cp_info["reg_ids"]

                if mode != "c2_multi":
                    # Release C0 / C1 threads via reject so ALT-2026-0007 remains open for C2 full approval commit
                    rej = await client.post(
                        f"{base}/api/v1/investigations/{tid}/decision",
                        json={"action": "reject", "notes": f"Completed {mode} verification"},
                        headers=headers,
                    )
                    assert rej.status_code == 200
                else:
                    c2_tid = tid
                    c2_terminal = events[-1][2]

            # Step 4: Adversarial Decision Gate Probes on C2 paused thread
            print("\n=== STEP 4: ADVERSARIAL HUMAN GATE PROBES (401 / 422 / STALE TOKEN 403 / VALID EDIT) ===")
            h1 = c2_terminal["approved_hash"]
            t1 = c2_terminal["approval_token"]

            r_unauth = await client.post(
                f"{base}/api/v1/investigations/{c2_tid}/decision",
                json={"action": "approve", "approved_hash": h1, "approval_token": t1},
            )
            r_nohash = await client.post(
                f"{base}/api/v1/investigations/{c2_tid}/decision", json={"action": "approve"}, headers=headers
            )
            r_1inr = await client.post(
                f"{base}/api/v1/investigations/{c2_tid}/decision",
                json={
                    "action": "edit",
                    "edit": {"recommendation_rationale": "Tampered amount INR 900001.00 outside registry."},
                },
                headers=headers,
            )
            print(f"  Unauthenticated decision       -> HTTP {r_unauth.status_code}")
            print(f"  Missing-hash decision          -> HTTP {r_nohash.status_code}")
            print(f"  Ungrounded +1 INR edit attempt -> HTTP {r_1inr.status_code} ({r_1inr.json()['detail']['code']})")
            assert r_unauth.status_code == 401 and r_nohash.status_code == 422 and r_1inr.status_code == 422

            valid_rationale = (
                "Tier-2 analyst verified staggered INR 900000.00 dispersal and multi-hop consolidation trail."
            )
            r_edit = await client.post(
                f"{base}/api/v1/investigations/{c2_tid}/decision",
                json={
                    "action": "edit",
                    "edit": {"recommended_disposition": "escalate_str", "recommendation_rationale": valid_rationale},
                },
                headers=headers,
            )
            assert r_edit.status_code == 200, r_edit.text
            eb = r_edit.json()
            h2, t2 = eb["approved_hash"], eb["approval_token"]
            assert h2 != h1 and t2 != t1
            print(
                f"  Valid verified edit            -> HTTP {r_edit.status_code} (old_sha={h1[:12]}... -> new_sha={h2[:12]}...)"
            )

            r_stale_old_hash = await client.post(
                f"{base}/api/v1/investigations/{c2_tid}/decision",
                json={"action": "approve", "approved_hash": h1, "approval_token": t1},
                headers=headers,
            )
            r_stale_tok_new_hash = await client.post(
                f"{base}/api/v1/investigations/{c2_tid}/decision",
                json={"action": "approve", "approved_hash": h2, "approval_token": t1},
                headers=headers,
            )
            print(f"  Stale hash + stale token       -> HTTP {r_stale_old_hash.status_code}")
            print(f"  New hash + superseded token    -> HTTP {r_stale_tok_new_hash.status_code}")
            assert r_stale_old_hash.status_code == 403 and r_stale_tok_new_hash.status_code == 409

            # Step 5: Single-Use HMAC Commit + LangGraph Resume to END + Replay 409
            print("\n=== STEP 5: SINGLE-USE HMAC COMMIT (200) + LANGGRAPH END + REPLAY REJECTION (409) ===")
            r_commit = await client.post(
                f"{base}/api/v1/investigations/{c2_tid}/decision",
                json={
                    "action": "approve",
                    "approved_hash": h2,
                    "approval_token": t2,
                    "notes": "Approved for Principal Officer STR review.",
                },
                headers=headers,
            )
            assert r_commit.status_code == 200, r_commit.text
            receipt = r_commit.json()["receipt"]
            print(f"  Commit with fresh HMAC token   -> HTTP {r_commit.status_code} receipt={receipt}")

            post_cp = await _inspect_langgraph_checkpoint(live_db, c2_tid, "c2_multi")
            print(
                f"  LangGraph post-commit state    -> next_nodes={post_cp['next_nodes']}, has_interrupt={post_cp['has_interrupt']}"
            )
            assert post_cp["next_nodes"] == [] and post_cp["has_interrupt"] is False

            r_replay = await client.post(
                f"{base}/api/v1/investigations/{c2_tid}/decision",
                json={"action": "approve", "approved_hash": h2, "approval_token": t2},
                headers=headers,
            )
            print(
                f"  Immediate replay of same token -> HTTP {r_replay.status_code} ({r_replay.json()['detail']['code']})"
            )
            assert r_replay.status_code == 409

        # Step 6: Operational DB Held-Out Leakage Check
        print("\n=== STEP 6: OPERATIONAL DB HELD-OUT LEAKAGE CHECK ===")
        os.environ.pop("SQLITE_DB_PATH", None)
        chk = subprocess.run(
            [sys.executable, "scripts/purge_operational_db.py", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        print(chk.stdout.strip())
        print("\nALL LIVE END-TO-END VERIFICATION CHECKS PASSED 100%.")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    asyncio.run(run_verification())
