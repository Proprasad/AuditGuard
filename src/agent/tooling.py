"""
Guarded tool access shared by C0 / C1 / C2.

Every MCP call flows: pre_tool_hook (RBAC + bounds + BudgetLedger) -> MCP client -> post_tool_hook
(PII scrub, escaped <untrusted_data> containment, normalised injection detection). Detections are written to
`audit_logs` and exposed via `security_events` so the run records degraded evidence.
"""
from __future__ import annotations

from typing import Any

from src.core.policy import BudgetLedger
from src.db.database import append_audit_log
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

    def __init__(self, role: str, ledger: BudgetLedger, thread_id: str = "unbound") -> None:
        self.role = role
        self.ledger = ledger
        self.thread_id = thread_id
        self.calls = 0
        self.security_events: list[dict[str, Any]] = []

    async def call(self, server: str, tool: str, params: dict[str, Any]) -> dict[str, Any]:
        decision = pre_tool_hook(self.role, tool, params, ledger=self.ledger)
        if not decision.allowed:
            return error_envelope(decision.error_code, decision.message)
        self.calls += 1
        raw = await call_mcp_tool(server, tool, params)
        flags: list[dict[str, Any]] = []
        sanitized = post_tool_hook(tool, raw, flags=flags)
        for flag in flags:
            self.security_events.append(flag)
            append_audit_log(thread_id=self.thread_id, event_type="injection_detected_in_tool_output", actor=self.role, details=flag)
        if not isinstance(sanitized, dict):
            return error_envelope("MCP_BAD_RESPONSE", f"{server}.{tool} returned a non-object response")
        return sanitized
