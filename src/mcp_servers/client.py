"""
Unified MCP tool client built on the real FastMCP protocol client (`fastmcp.Client`).

* `MCP_TRANSPORT=http`      -> streamable-HTTP to the separately running FastMCP servers (container fleet),
                               reusing persistent lifespan-managed `Client` sessions when active.
* `MCP_TRANSPORT=inprocess` -> FastMCP's in-memory transport against the very same `FastMCP` server objects, so tool
                               discovery, argument validation and result serialisation are the real MCP code path.

There are no raw `.fn` calls and no silent fallbacks: any transport/tool failure is returned as an explicit, typed
error envelope (`status="error"`, `error_code`, `error`) that callers must treat as missing evidence.
"""

from __future__ import annotations

import asyncio
from contextlib import AbstractAsyncContextManager, AsyncExitStack
import importlib
import json
import logging
import os
import time
from typing import Any, cast

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from src.config import get_policy, settings
from src.mcp_servers.http_auth import MCP_TOKEN_HEADER, mcp_service_token
from src.observability.correlation import current_correlation_id
from src.observability.metrics import MCP_TOOL_CALLS_TOTAL, MCP_TOOL_DURATION

logger = logging.getLogger("auditguard.mcp")

_SERVERS: dict[str, str] = {
    "compliance-kb": "src.mcp_servers.compliance_kb",
    "graph-engine": "src.mcp_servers.graph_engine",
    "bank-records": "src.mcp_servers.bank_records",
    "case-actions": "src.mcp_servers.case_actions",
}
_POOL_ACTIVE: bool = False
_HTTP_CLIENTS: dict[tuple[str, str], tuple[Client[Any], AsyncExitStack]] = {}
_HTTP_LOCKS: dict[str, asyncio.Lock] = {}


def open_mcp_client_pool() -> None:
    global _POOL_ACTIVE
    _POOL_ACTIVE = True


async def close_mcp_client_pool() -> None:
    global _POOL_ACTIVE
    _POOL_ACTIVE = False
    entries = list(_HTTP_CLIENTS.values())
    _HTTP_CLIENTS.clear()
    _HTTP_LOCKS.clear()
    for _client, stack in entries:
        try:
            await stack.aclose()
        except Exception:  # noqa: BLE001 - best-effort shutdown cleanup
            logger.debug("ignored error closing pooled MCP client", exc_info=True)


def _port(server: str) -> int:
    return {
        "compliance-kb": settings.mcp_compliance_kb_port,
        "graph-engine": settings.mcp_graph_engine_port,
        "bank-records": settings.mcp_bank_records_port,
        "case-actions": settings.mcp_case_actions_port,
    }[server]


def _host(server: str) -> str:
    env_key = f"MCP_{server.upper().replace('-', '_')}_HOST"
    return os.getenv(env_key) or settings.mcp_host


def _http_url(server: str) -> str:
    return f"http://{_host(server)}:{_port(server)}/mcp"


def _target(server: str) -> Any:
    if settings.mcp_transport == "http":
        return StreamableHttpTransport(
            _http_url(server),
            headers={MCP_TOKEN_HEADER: mcp_service_token()},
        )
    return importlib.import_module(_SERVERS[server]).mcp


async def _get_pooled_http_client(server: str, timeout: float) -> Client[Any]:
    url = _http_url(server)
    key = (server, url)
    lock = _HTTP_LOCKS.setdefault(server, asyncio.Lock())
    async with lock:
        existing = _HTTP_CLIENTS.get(key)
        if existing is not None and existing[0].is_connected():
            return existing[0]
        client: Client[Any] = Client(
            StreamableHttpTransport(url, headers={MCP_TOKEN_HEADER: mcp_service_token()}),
            timeout=timeout,
        )
        stack = AsyncExitStack()
        await stack.enter_async_context(cast(AbstractAsyncContextManager[Any], client))
        _HTTP_CLIENTS[key] = (client, stack)
        return client


async def _evict_pooled_http_client(server: str) -> None:
    url = _http_url(server)
    entry = _HTTP_CLIENTS.pop((server, url), None)
    if entry is not None:
        try:
            await entry[1].aclose()
        except Exception:  # noqa: BLE001 - best-effort eviction cleanup
            logger.debug("ignored error evicting pooled MCP client", exc_info=True)


def error_envelope(server: str, tool: str, code: str, message: str) -> dict[str, Any]:
    logger.warning("MCP tool error server=%s tool=%s code=%s message=%s", server, tool, code, message)
    return {
        "status": "error",
        "success": False,
        "error_code": code,
        "message": message,
        "error": message,
        "server": server,
        "tool": tool,
    }


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


async def call_mcp_tool(
    server: str, tool: str, params: dict[str, Any], timeout_s: float | None = None
) -> dict[str, Any]:
    """Invoke `tool` on `server` through the MCP protocol. Never raises for transport/tool failures."""
    started = time.perf_counter()
    result = await _call_mcp_tool(server, tool, params, timeout_s)
    status = str(result.get("error_code") or "error") if result.get("status") == "error" else "ok"
    MCP_TOOL_CALLS_TOTAL.labels(server=server, tool=tool, status=status).inc()
    MCP_TOOL_DURATION.labels(server=server, tool=tool).observe(time.perf_counter() - started)
    return result


async def _call_mcp_tool(
    server: str, tool: str, params: dict[str, Any], timeout_s: float | None
) -> dict[str, Any]:
    if server not in _SERVERS:
        return error_envelope(server, tool, "UNKNOWN_MCP_SERVER", f"unknown MCP server {server!r}")
    timeout = timeout_s if timeout_s is not None else float(get_policy().timeouts.mcp_call_seconds)
    use_pool = _POOL_ACTIVE and settings.mcp_transport == "http"
    cid = current_correlation_id()
    meta = {"correlation_id": cid} if cid else None
    try:
        if use_pool:
            pooled = await asyncio.wait_for(_get_pooled_http_client(server, timeout), timeout=timeout)
            result = await asyncio.wait_for(
                pooled.call_tool(tool, {"params": params}, raise_on_error=False, meta=meta), timeout=timeout
            )
        else:
            async with Client(_target(server), timeout=timeout) as client:
                result = await asyncio.wait_for(
                    client.call_tool(tool, {"params": params}, raise_on_error=False, meta=meta), timeout=timeout
                )
        return _unwrap(server, tool, result)
    except asyncio.TimeoutError:
        if use_pool:
            await _evict_pooled_http_client(server)
        logger.warning("MCP timeout server=%s tool=%s after %ss", server, tool, timeout)
        return error_envelope(server, tool, "MCP_TIMEOUT", f"{server}.{tool} timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001 - transport boundary: surfaced as an explicit error envelope
        if use_pool:
            await _evict_pooled_http_client(server)
        logger.warning("MCP transport failure server=%s tool=%s: %s", server, tool, exc)
        return error_envelope(server, tool, "MCP_UNAVAILABLE", f"{type(exc).__name__}: {exc}"[:300])
