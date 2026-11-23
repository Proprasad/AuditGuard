"""
Internal HMAC service authentication for FastMCP HTTP servers (`8010-8013`).

Prevents unauthenticated direct HTTP calls to internal MCP endpoints when `MCP_TRANSPORT=http`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

import uvicorn
from fastmcp import FastMCP

from src.config import get_hmac_secret

MCP_TOKEN_HEADER = "x-auditguard-mcp-token"  # noqa: S105 - HTTP header name, not a secret
Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def mcp_service_token() -> str:
    override = os.getenv("MCP_SERVICE_TOKEN", "").strip()
    if override:
        return override
    return hmac.new(get_hmac_secret(), b"auditguard-mcp-service-v1", hashlib.sha256).hexdigest()


class McpServiceAuthApp:
    """Pure ASGI wrapper enforcing `X-AuditGuard-MCP-Token` constant-time verification on HTTP requests."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "http":
            headers = {
                bytes(k).decode("latin1").lower(): bytes(v).decode("latin1")
                for k, v in scope.get("headers", ())
            }
            provided = headers.get(MCP_TOKEN_HEADER, "")
            if not provided or not hmac.compare_digest(provided, mcp_service_token()):
                body = json.dumps(
                    {
                        "status": "error",
                        "error_code": "MCP_UNAUTHORIZED",
                        "message": "missing or invalid X-AuditGuard-MCP-Token header",
                    }
                ).encode("utf-8")
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self._app(scope, receive, send)


def build_authenticated_mcp_app(mcp_server: FastMCP) -> McpServiceAuthApp:
    inner = mcp_server.http_app(transport="streamable-http")
    return McpServiceAuthApp(inner)


def serve_mcp_http(mcp_server: FastMCP, port: int, host: str = "0.0.0.0") -> None:  # noqa: S104 - container bind
    uvicorn.run(build_authenticated_mcp_app(mcp_server), host=host, port=port, log_level="warning")
