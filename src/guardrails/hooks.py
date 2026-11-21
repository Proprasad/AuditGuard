"""
Pre-Tool & Post-Tool Enforcement Hooks
- Pre-tool: RBAC allow-list, global call & cost budget, policy bounds validator
- Post-tool: PII scrubber, <untrusted_data> tagging, structured audit logging
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from src.guardrails.guardrails import mask_pii, tag_untrusted

# Per-agent RBAC tool allow-lists (Section 8.1)
AGENT_TOOL_ALLOWLIST: dict[str, set[str]] = {
    "c1_single": {
        "search_regulations",
        "get_clause_by_id",
        "find_candidate_fund_flows",
        "compute_flow_conservation",
        "compare_graph_runs",
        "get_alert_context",
        "get_account_transactions",
        "get_kyc_profile",
        "get_counterparty_history",
        "check_commercial_registry",
        "draft_disposition_report",
        "submit_case_disposition",  # Gated behind interrupt() + HMAC token
    },
    "flow_tracer": {
        "find_candidate_fund_flows",
        "compute_flow_conservation",
        "compare_graph_runs",
        "get_alert_context",
        "get_account_transactions",
    },
    "benign_investigator": {
        "get_kyc_profile",
        "get_counterparty_history",
        "check_commercial_registry",
        "get_account_transactions",
    },
    "regulatory_analyst": {
        "search_regulations",
        "get_clause_by_id",
    },
    "reporter_critic": {
        "find_candidate_fund_flows",
        "compute_flow_conservation",
        "compare_graph_runs",
        "draft_disposition_report",
        "submit_case_disposition",  # Gated behind interrupt() + HMAC token
    },
}

UNTRUSTED_TEXT_FIELDS = {"memo", "memo_text", "kyc_notes", "business_description", "text"}


class HookDecision(BaseModel):
    allowed: bool
    error_code: str = ""
    message: str = ""


def validate_graph_bounds(params: dict[str, Any]) -> HookDecision:
    """Enforce backend policy bounds on graph-engine parameters."""
    if "time_window_days" in params:
        tw = params["time_window_days"]
        if not (1 <= tw <= 30):
            return HookDecision(
                allowed=False,
                error_code="POLICY_BOUNDS_EXCEEDED",
                message=f"time_window_days={tw} outside allowed [1, 30]",
            )
    if "max_hops" in params:
        mh = params["max_hops"]
        if not (2 <= mh <= 5):
            return HookDecision(
                allowed=False,
                error_code="POLICY_BOUNDS_EXCEEDED",
                message=f"max_hops={mh} outside allowed [2, 5]",
            )
    if "amount_tolerance" in params:
        at = params["amount_tolerance"]
        if not (0.01 <= at <= 0.25):
            return HookDecision(
                allowed=False,
                error_code="POLICY_BOUNDS_EXCEEDED",
                message=f"amount_tolerance={at} outside allowed [0.01, 0.25]",
            )
    if "min_intermediaries" in params:
        mi = params["min_intermediaries"]
        if not (2 <= mi <= 10):
            return HookDecision(
                allowed=False,
                error_code="POLICY_BOUNDS_EXCEEDED",
                message=f"min_intermediaries={mi} outside allowed [2, 10]",
            )
    return HookDecision(allowed=True)


def pre_tool_hook(
    agent_role: str,
    tool_name: str,
    params: dict[str, Any],
    tool_calls_used: int = 0,
    max_tool_calls: int = 15,
    token_cost_usd: float = 0.0,
    max_cost_usd: float = 0.15,
    has_human_approval_token: bool = False,
) -> HookDecision:
    """
    Enforce RBAC, call/cost budget, and parameter bounds before any MCP tool runs.
    """
    allowed_tools = AGENT_TOOL_ALLOWLIST.get(agent_role, set())
    if tool_name not in allowed_tools:
        return HookDecision(
            allowed=False,
            error_code="RBAC_DENIED",
            message=f"Agent '{agent_role}' is not permitted to invoke '{tool_name}'",
        )

    if tool_name == "submit_case_disposition" and not has_human_approval_token:
        return HookDecision(
            allowed=False,
            error_code="APPROVAL_REQUIRED",
            message="submit_case_disposition requires a verified human approval token post-interrupt()",
        )

    if tool_calls_used >= max_tool_calls:
        return HookDecision(
            allowed=False,
            error_code="BUDGET_EXCEEDED",
            message=f"Tool call budget exhausted ({tool_calls_used}/{max_tool_calls})",
        )

    if token_cost_usd >= max_cost_usd:
        return HookDecision(
            allowed=False,
            error_code="BUDGET_EXCEEDED",
            message=f"Cost budget exhausted (${token_cost_usd:.4f}/${max_cost_usd:.2f})",
        )

    if tool_name == "find_candidate_fund_flows":
        bounds_check = validate_graph_bounds(params)
        if not bounds_check.allowed:
            return bounds_check

    return HookDecision(allowed=True)


def post_tool_hook(
    tool_name: str,
    result: Any,
    audit_log: list[dict[str, Any]] | None = None,
) -> Any:
    """
    Post-tool middleware:
    1. Scrub synthetic PII before telemetry/LLM context
    2. Wrap untrusted text fields (memos, KYC notes, retrieved passages) in <untrusted_data>
    3. Append structured audit entry
    """
    def _sanitize(obj: Any, key: str = "") -> Any:
        if isinstance(obj, dict):
            return {k: _sanitize(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_sanitize(item, key) for item in obj]
        if isinstance(obj, str):
            scrubbed, _ = mask_pii(obj)
            if key in UNTRUSTED_TEXT_FIELDS and scrubbed and not scrubbed.startswith("<untrusted_data>"):
                return tag_untrusted(scrubbed)
            return scrubbed
        return obj

    sanitized = _sanitize(result)

    if audit_log is not None:
        audit_log.append({
            "event_type": "tool_executed",
            "tool_name": tool_name,
            "timestamp": datetime.utcnow().isoformat(),
        })

    return sanitized
