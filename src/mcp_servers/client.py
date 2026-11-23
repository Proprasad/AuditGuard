"""
Unified MCP tool client built on the real FastMCP protocol client (`fastmcp.Client`).

* `MCP_TRANSPORT=http`      -> streamable-HTTP to the separately running FastMCP servers (container fleet).
* `MCP_TRANSPORT=inprocess` -> FastMCP's in-memory transport against the very same `FastMCP` server objects, so tool
                               discovery, argument validation and result serialisation are the real MCP code path.

There are no raw `.fn` calls and no silent fallbacks: any transport/tool failure is returned as an explicit, typed
error envelope (`status="error"`, `error_code`, `error`) that callers must treat as missing evidence.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import logging
from typing import Any

from fastmcp import Client

from src.config import settings

logger = logging.getLogger("auditguard.mcp")

_SERVERS: dict[str, str] = {
    "compliance-kb": "src.mcp_servers.compliance_kb",
    "graph-engine": "src.mcp_servers.graph_engine",
    "bank-records": "src.mcp_servers.bank_records",
    "case-actions": "src.mcp_servers.case_actions",
}


def _port(server: str) -> int:
    return {
        "compliance-kb": settings.mcp_compliance_kb_port,
        "graph-engine": settings.mcp_graph_engine_port,
        "bank-records": settings.mcp_bank_records_port,
        "case-actions": settings.mcp_case_actions_port,
    }[server]


def _target(server: str) -> Any:
    if settings.mcp_transport == "http":
        return f"http://{settings.mcp_host}:{_port(server)}/mcp"
    return importlib.import_module(_SERVERS[server]).mcp


def error_envelope(server: str, tool: str, code: str, message: str) -> dict[str, Any]:
    return {"status": "error", "success": False, "error_code": code, "error": message, "server": server, "tool": tool}


def _unwrap(server: str, tool: str, result: Any) -> dict[str, Any]:
    if result.is_error:
        text = " ".join(getattr(c, "text", "") for c in result.content)[:500]
        return error_envelope(server, tool, "MCP_TOOL_ERROR", text or "tool reported an error")
    structured = result.structured_content
    if isinstance(structured, dict):
        return structured
    for block in result.content:
        block_text = getattr(block, "text", None)
        if block_text:
            try:
                parsed = json.loads(block_text)
            except json.JSONDecodeError:
                break
            return parsed if isinstance(parsed, dict) else {"result": parsed}
    return error_envelope(server, tool, "MCP_EMPTY_RESULT", "tool returned no structured content")


async def call_mcp_tool(server: str, tool: str, params: dict[str, Any], timeout_s: float | None = None) -> dict[str, Any]:
    """Invoke `tool` on `server` through the MCP protocol. Never raises for transport/tool failures."""
    if server not in _SERVERS:
        return error_envelope(server, tool, "UNKNOWN_MCP_SERVER", f"unknown MCP server {server!r}")
    timeout = timeout_s if timeout_s is not None else settings.mcp_timeout_s
    try:
        async with Client(_target(server), timeout=timeout) as client:
            result = await asyncio.wait_for(client.call_tool(tool, {"params": params}, raise_on_error=False), timeout=timeout)
        return _unwrap(server, tool, result)
    except asyncio.TimeoutError:
        logger.warning("MCP timeout server=%s tool=%s after %ss", server, tool, timeout)
        return error_envelope(server, tool, "MCP_TIMEOUT", f"{server}.{tool} timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001 - transport boundary: surfaced as an explicit error envelope, never swallowed
        logger.warning("MCP transport failure server=%s tool=%s: %s", server, tool, exc)
        return error_envelope(server, tool, "MCP_UNAVAILABLE", f"{type(exc).__name__}: {exc}"[:300])
