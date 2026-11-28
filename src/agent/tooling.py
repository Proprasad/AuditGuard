"""
Guarded tool access shared by C0 / C1 / C2.

Every MCP call flows: pre_tool_hook (RBAC + bounds + BudgetLedger) -> MCP client -> post_tool_hook
(PII scrub, escaped <untrusted_data> containment, normalised injection detection). Detections are written to
`audit_logs` and exposed via `security_events` so the run records degraded evidence. `defenses_enabled=False`
(E2 ablation) skips only the post_tool_hook; the pre-tool hook is never bypassed.
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
        defenses_enabled: bool = True,
    ) -> None:
        self.role = role
        self.ledger = ledger
        self.thread_id = thread_id
        self.allowed_tool_budget = allowed_tool_budget
        self.defenses_enabled = defenses_enabled
        self.calls = 0
        self.security_events: list[dict[str, Any]] = []
        self.tool_errors: list[dict[str, Any]] = []

    def set_sub_budget(self, limit: Optional[int]) -> None:
        self.allowed_tool_budget = limit

    async def _record_tool_error(self, server: str, tool: str, code: str, message: str) -> dict[str, Any]:
        entry = {"server": server, "tool": tool, "error_code": code, "message": message}
        self.tool_errors.append(entry)
        await asyncio.to_thread(append_audit_log, self.thread_id, "tool_error_recorded", self.role, entry)
        return error_envelope(code, message)

    async def call(
        self,
        server: str,
        tool: str,
        params: dict[str, Any],
        *,
        has_human_approval_token: bool = False,
    ) -> dict[str, Any]:
        is_exit_tool = tool in ("draft_disposition_report", "submit_case_disposition", "finish")
        if not is_exit_tool and self.allowed_tool_budget is not None and self.calls >= self.allowed_tool_budget:
            return await self._record_tool_error(
                server,
                tool,
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
            return await self._record_tool_error(server, tool, decision.error_code, decision.message)
        self.calls += 1
        raw = await call_mcp_tool(server, tool, params)
        if is_error(raw):
            code = str(raw.get("error_code") or "MCP_TOOL_ERROR")
            msg = str(raw.get("message") or raw.get("error") or "tool call failed")
            await self._record_tool_error(server, tool, code, msg)
            return raw
        if not self.defenses_enabled:
            # E2 `defenses_off` ablation: RBAC, approval hook, bounds and budgets above still run; only the
            # post-tool guardrails (PII masking, <untrusted_data> wrapping, injection screening) are disabled.
            return raw
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
            return await self._record_tool_error(
                server, tool, "MCP_BAD_RESPONSE", f"{server}.{tool} returned a non-object response"
            )
        return sanitized
