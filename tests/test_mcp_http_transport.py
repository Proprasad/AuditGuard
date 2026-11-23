"""Spawn a real FastMCP server process (streamable HTTP) and call it through `call_mcp_tool`."""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from src.mcp_servers.client import call_mcp_tool

ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_bank_records_over_real_http(isolated_operational_db, monkeypatch):
    port = _free_port()
    env = {**os.environ, "MCP_BANK_RECORDS_PORT": str(port), "SQLITE_DB_PATH": str(isolated_operational_db)}
    proc = subprocess.Popen([sys.executable, "-m", "src.mcp_servers.bank_records"], cwd=ROOT, env=env,  # noqa: S603
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            with socket.socket() as s:
                s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            assert proc.poll() is None, "MCP server exited early"
            time.sleep(0.5)
        else:
            pytest.fail("MCP server did not start")

        from src.config import settings

        monkeypatch.setattr(settings, "mcp_transport", "http")
        monkeypatch.setattr(settings, "mcp_host", "127.0.0.1")
        monkeypatch.setattr(settings, "mcp_bank_records_port", port)
        ok = await call_mcp_tool("bank-records", "get_alert_context", {"alert_id": "ALT-2026-0412"}, timeout_s=20)
        assert ok.get("status") == "ok" and ok["alert_id"] == "ALT-2026-0412"
        missing = await call_mcp_tool("bank-records", "get_alert_context", {"alert_id": "ALT-NOPE-1"}, timeout_s=20)
        assert missing["error_code"] == "INVALID_ALERT_ID"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
