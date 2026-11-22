"""
Guarded tool access shared by C0 / C1 / C2.

Every MCP call flows: pre_tool_hook (RBAC + bounds + BudgetLedger) -> MCP client -> post_tool_hook.
"""
from __future__ import annotations

from typing import Any

from src.core.policy import BudgetLedger
from src.guardrails.hooks import post_tool_hook, pre_tool_hook
from src.mcp_servers.client import call_mcp_tool


def error_envelope(code: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_code": code, "message": message}


def is_error(result: Any) -> bool:
    if not isinstance(result, dict):
        return True
    return result.get("status") == "error" or ("error" in result and "status" not in result)


class GuardedToolbox:
    """Role-scoped, budget-enforced tool caller."""

    def __init__(self, role: str, ledger: BudgetLedger) -> None:
        self.role = role
        self.ledger = ledger
        self.calls = 0

    async def call(self, server: str, tool: str, params: dict[str, Any]) -> dict[str, Any]:
        decision = pre_tool_hook(self.role, tool, params, ledger=self.ledger)
        if not decision.allowed:
            return error_envelope(decision.error_code, decision.message)
        self.calls += 1
        raw = await call_mcp_tool(server, tool, params)
        sanitized = post_tool_hook(tool, raw)
        if not isinstance(sanitized, dict):
            return error_envelope("MCP_BAD_RESPONSE", f"{server}.{tool} returned a non-object response")
        return sanitized
