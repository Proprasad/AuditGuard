"""
Pre-Tool & Post-Tool Enforcement Hooks
- Pre-tool: RBAC allow-list, policy-bound validation (from PolicyConfig), BudgetLedger enforcement
- Post-tool: PII scrubber, <untrusted_data> tagging, structured audit logging
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel

from src.config import get_policy
from src.core.policy import BudgetLedger
from src.guardrails.guardrails import mask_pii, tag_untrusted

# Per-agent RBAC tool allow-lists (enforced at the execution layer, never by prompt text)
AGENT_TOOL_ALLOWLIST: dict[str, set[str]] = {
    "c0_fixed": {
        "get_alert_context",
        "find_candidate_fund_flows",
        "get_kyc_profile",
        "search_regulations",
        "draft_disposition_report",
    },
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
        "submit_case_disposition",  # Gated: requires a verified, single-use human approval token
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
        "submit_case_disposition",  # Gated: requires a verified, single-use human approval token
    },
}

UNTRUSTED_TEXT_FIELDS = {"memo", "memo_text", "kyc_notes", "business_description", "text"}


class HookDecision(BaseModel):
    allowed: bool
    error_code: str = ""
    message: str = ""


def validate_graph_bounds(params: dict[str, Any]) -> HookDecision:
    """Enforce policy bounds (config/models.yaml) on graph-engine parameters."""
    violations = get_policy().validate_graph_params(params)
    if violations:
        return HookDecision(allowed=False, error_code="POLICY_BOUNDS_EXCEEDED", message="; ".join(violations))
    return HookDecision(allowed=True)


def pre_tool_hook(
    agent_role: str,
    tool_name: str,
    params: dict[str, Any],
    ledger: Optional[BudgetLedger] = None,
    has_human_approval_token: bool = False,
) -> HookDecision:
    """Enforce RBAC, parameter bounds and the per-run budget ledger before any MCP tool runs."""
    if tool_name not in AGENT_TOOL_ALLOWLIST.get(agent_role, set()):
        return HookDecision(
            allowed=False,
            error_code="RBAC_DENIED",
            message=f"Agent '{agent_role}' is not permitted to invoke '{tool_name}'",
        )

    if tool_name == "submit_case_disposition" and not has_human_approval_token:
        return HookDecision(
            allowed=False,
            error_code="APPROVAL_REQUIRED",
            message="submit_case_disposition requires a verified human approval token",
        )

    if tool_name == "find_candidate_fund_flows":
        bounds = validate_graph_bounds(params)
        if not bounds.allowed:
            return bounds

    if ledger is not None:
        verdict = ledger.try_consume_tool_call()
        if not verdict.allowed:
            return HookDecision(allowed=False, error_code=verdict.error_code, message=verdict.message)

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
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    return sanitized
