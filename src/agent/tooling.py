"""
Guarded tool access shared by C0 / C1 / C2.

Every MCP call flows: pre_tool_hook (RBAC + bounds + BudgetLedger) -> MCP client -> post_tool_hook
(PII scrub, escaped <untrusted_data> containment, normalised injection detection). Detections are written to
`audit_logs` and exposed via `security_events` so the run records degraded evidence.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from src.core.policy import BudgetLedger
from src.db.database import append_audit_log
from src.guardrails.hooks import post_tool_hook, pre_tool_hook
from src.mcp_servers.client import call_mcp_tool


def error_envelope(code: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_code": code, "message": message, "error": message}


def is_error(result: Any) -> bool:
    if not isinstance(result, dict):
        return True
    return result.get("status") == "error" or ("error" in result and "status" not in result)


class GuardedToolbox:
    """Role-scoped, budget-enforced tool caller (supports optional per-specialist sub-budget)."""

    def __init__(
        self,
        role: str,
        ledger: BudgetLedger,
        thread_id: str = "unbound",
        allowed_tool_budget: Optional[int] = None,
    ) -> None:
        self.role = role
        self.ledger = ledger
        self.thread_id = thread_id
        self.allowed_tool_budget = allowed_tool_budget
        self.calls = 0
        self.security_events: list[dict[str, Any]] = []

    def set_sub_budget(self, limit: Optional[int]) -> None:
        self.allowed_tool_budget = limit

    async def call(
        self,
        server: str,
        tool: str,
        params: dict[str, Any],
        *,
        has_human_approval_token: bool = False,
    ) -> dict[str, Any]:
        if self.allowed_tool_budget is not None and self.calls >= self.allowed_tool_budget:
            return error_envelope(
                "SPECIALIST_BUDGET_EXCEEDED",
                f"Specialist '{self.role}' exhausted handoff tool budget ({self.calls}/{self.allowed_tool_budget})",
            )
        decision = pre_tool_hook(
            self.role,
            tool,
            params,
            ledger=self.ledger,
            has_human_approval_token=has_human_approval_token,
        )
        if not decision.allowed:
            return error_envelope(decision.error_code, decision.message)
        self.calls += 1
        raw = await call_mcp_tool(server, tool, params)
        flags: list[dict[str, Any]] = []
        sanitized = post_tool_hook(tool, raw, flags=flags)
        for flag in flags:
            self.security_events.append(flag)
            await asyncio.to_thread(
                append_audit_log,
                self.thread_id,
                "injection_detected_in_tool_output",
                self.role,
                flag,
            )
        if not isinstance(sanitized, dict):
            return error_envelope("MCP_BAD_RESPONSE", f"{server}.{tool} returned a non-object response")
        return sanitized
