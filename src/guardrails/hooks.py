"""
Pre-Tool & Post-Tool Enforcement Hooks
- Pre-tool: RBAC allow-list, policy-bound validation (from PolicyConfig), BudgetLedger enforcement
- Post-tool: PII scrubber, <untrusted_data> tagging, structured audit logging
- LLM boundary: every non-internal tool result reaches an LLM inside one escaped <untrusted_data> envelope
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel

from src.config import get_policy
from src.core.policy import BudgetLedger
from src.guardrails.guardrails import (
    mask_pii,
    matched_injection_patterns,
    unwrap_untrusted_data,
    wrap_untrusted_data,
)

# Per-agent RBAC tool allow-lists (enforced at the execution layer, never by prompt text)
AGENT_TOOL_ALLOWLIST: dict[str, set[str]] = {
    "c0_fixed": {
        "get_alert_context",
        "find_candidate_fund_flows",
        "compute_flow_conservation",
        "get_kyc_profile",
        "check_commercial_registry",
        "search_regulations",
        "calc",
        "draft_disposition_report",
        "submit_case_disposition",  # Gated: requires a verified, single-use human approval token
    },
    "rule_engine": {
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
        "calc",
        "draft_disposition_report",
        "submit_case_disposition",  # Gated: requires a verified, single-use human approval token
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
        "calc",
        "replan_graph",
        "finish",
        "draft_disposition_report",
        "submit_case_disposition",  # Gated: requires a verified, single-use human approval token
    },
    "flow_tracer": {
        "find_candidate_fund_flows",
        "compute_flow_conservation",
        "compare_graph_runs",
        "get_alert_context",
        "get_account_transactions",
        "calc",
        "replan_graph",
    },
    "benign_investigator": {
        "get_kyc_profile",
        "get_counterparty_history",
        "check_commercial_registry",
        "get_account_transactions",
        "calc",
    },
    "regulatory_analyst": {
        "search_regulations",
        "get_clause_by_id",
    },
    "reporter_critic": {
        "find_candidate_fund_flows",
        "compute_flow_conservation",
        "compare_graph_runs",
        "calc",
        "finish",
        "draft_disposition_report",
        "submit_case_disposition",  # Gated: requires a verified, single-use human approval token
    },
}

UNTRUSTED_TEXT_FIELDS = {
    "memo",
    "memo_text",
    "kyc_notes",
    "business_description",
    "entity_name",
    "counterparty_name",
    "text",
}
# Curated internal regulatory corpus: still escaped/wrapped, but not injection-screened (SOP text quotes the attack
# phrases).
TRUSTED_CORPUS_TOOLS = {"search_regulations", "get_clause_by_id"}
# Echoes of the agent's own drafted worksheet (not external data): never screened, or a legitimate rationale such as
# "close as benign" would be withheld from the persisted worksheet.
OWN_OUTPUT_TOOLS = {"draft_disposition_report", "submit_case_disposition"}
# Agent-internal tools whose results AuditGuard computes itself (Decimal `calc`, `finish` validation feedback).
# Every other tool result (MCP data, graph outputs, retrieved corpus text, error envelopes, and any tool added later)
# reaches the LLM inside one escaped <untrusted_data> envelope: deny-by-default (audit AG-15).
INTERNAL_RESULT_TOOLS = frozenset({"calc", "finish"})
_ENVELOPE_PREFIX = '<untrusted_data source="tool:'


class HookDecision(BaseModel):
    model_config = {"extra": "forbid"}
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

    if tool_name in ("find_candidate_fund_flows", "replan_graph"):
        bounds = validate_graph_bounds(params)
        if not bounds.allowed:
            return bounds

    # Post-interrupt human disposition commit and the terminal `finish` wrapper (which delegates persistence
    # to `draft_disposition_report`) do not double-charge an autonomous investigation tool slot.
    if ledger is not None and tool_name not in ("submit_case_disposition", "finish"):
        is_exit_draft = tool_name == "draft_disposition_report"
        verdict = ledger.try_consume_tool_call(
            reserve=0 if is_exit_draft else 1,
            allow_over_cost=is_exit_draft,
        )
        if not verdict.allowed:
            return HookDecision(allowed=False, error_code=verdict.error_code, message=verdict.message)

    return HookDecision(allowed=True)


def _identifier(container: dict[str, Any], tool_name: str) -> str:
    for key in ("evidence_id", "tx_id", "txn_id", "clause_id", "account_id"):
        if container.get(key):
            return str(container[key])
    return tool_name


def post_tool_hook(
    tool_name: str,
    result: Any,
    audit_log: list[dict[str, Any]] | None = None,
    flags: list[dict[str, Any]] | None = None,
) -> Any:
    """
    Post-tool middleware applied to EVERY tool output before it can reach agent state / an LLM:
    1. PII scrubbing
    2. Every external text field is XML-escaped and wrapped in <untrusted_data source="...">
    3. Unicode-normalised injection detection: matching content is WITHHELD (replaced by a hash placeholder),
       the enclosing record is flagged (`injection_flagged`) and the detection is appended to `flags`
    """
    detections = flags if flags is not None else []
    screen_external = tool_name not in TRUSTED_CORPUS_TOOLS and tool_name not in OWN_OUTPUT_TOOLS

    def withhold(value: str, ident: str, key: str, patterns: list[str]) -> str:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        source = f"{ident}.{key}"
        detections.append(
            {"tool": tool_name, "source": source, "field": key, "patterns": patterns, "content_sha256": digest}
        )
        return wrap_untrusted_data(f"[WITHHELD: possible prompt-injection sha256:{digest}]", f"{ident}.{key}")

    def sanitize_dict(container: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        ident = _identifier(container, tool_name)
        flagged = False
        for key, value in container.items():
            # Every external string is screened; only the listed free-text fields are wrapped. Clean unlisted
            # values stay byte-identical (PII-masked only), so deny-by-default wrapping can follow separately.
            screen = screen_external and isinstance(value, str)
            patterns = matched_injection_patterns(value, external=True) if screen else []
            if patterns:
                out[key] = withhold(value, ident, key, patterns)
                flagged = True
            elif isinstance(value, str) and key in UNTRUSTED_TEXT_FIELDS:
                out[key] = wrap_untrusted_data(mask_pii(value)[0], f"{ident}.{key}")
            else:
                out[key] = sanitize(value)
        if flagged:
            out["injection_flagged"] = True
        return out

    def sanitize(obj: Any) -> Any:
        if isinstance(obj, dict):
            return sanitize_dict(obj)
        if isinstance(obj, list):
            return [sanitize(item) for item in obj]
        if isinstance(obj, str):
            patterns = matched_injection_patterns(obj, external=True) if screen_external else []
            return withhold(obj, tool_name, "list_item", patterns) if patterns else mask_pii(obj)[0]
        return obj

    sanitized = sanitize(result)
    if audit_log is not None:
        audit_log.append(
            {
                "event_type": "tool_executed",
                "tool_name": tool_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    return sanitized


def _flatten_field_wrappers(obj: Any) -> Any:
    """Drop field-level wrappers (and their escaping) so the single envelope escapes each value exactly once."""
    if isinstance(obj, dict):
        return {key: _flatten_field_wrappers(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_flatten_field_wrappers(item) for item in obj]
    if isinstance(obj, str):
        return unwrap_untrusted_data(obj)
    return obj


def llm_tool_content(tool_name: str, result: Any, *, defenses_enabled: bool = True) -> str:
    """
    Serialise a tool result for an LLM `tool` message.

    With defences on, everything except `INTERNAL_RESULT_TOOLS` is wrapped as one
    `<untrusted_data source="tool:<name>">` envelope whose payload is XML-escaped, so no field (listed or not)
    can close the envelope or smuggle tags. Agent state keeps its structured values; only the LLM copy changes.
    """
    if not defenses_enabled or tool_name in INTERNAL_RESULT_TOOLS:
        return json.dumps(result, sort_keys=True, default=str)
    payload = json.dumps(_flatten_field_wrappers(result), sort_keys=True, default=str)
    return wrap_untrusted_data(payload, f"tool:{tool_name}")


def decode_llm_tool_content(content: str) -> Any:
    """Inverse of `llm_tool_content`, for tests and transcript tooling."""
    if content.startswith(_ENVELOPE_PREFIX):
        return json.loads(unwrap_untrusted_data(content))
    return json.loads(content)
