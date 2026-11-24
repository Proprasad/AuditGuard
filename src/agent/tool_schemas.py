"""
Pydantic input models, OpenAI function-tool schema generator, and pure `Decimal` `calc`
helper shared by `src/agent/tools.py` (`AgentToolRuntime`).
"""

from __future__ import annotations

import copy
from decimal import Decimal
import json
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from src.core.canonical import (
    CENT,
    Confidence,
    Ratio,
    canonical_sha256,
    dec_str,
    to_confidence,
    to_decimal,
    to_money,
    to_ratio,
)
from src.guardrails.hooks import AGENT_TOOL_ALLOWLIST
from src.mcp_servers.bank_records import (
    CheckCommercialRegistryInput,
    GetAccountTransactionsInput,
    GetAlertContextInput,
    GetCounterpartyHistoryInput,
    GetKYCProfileInput,
)
from src.mcp_servers.compliance_kb import GetClauseInput, SearchRegulationsInput
from src.mcp_servers.graph_engine import TransactionEdge
from src.models import DispositionDecision, Hypothesis, HypothesisLabel, StrictModel


class LLMFindFlowsInput(StrictModel):
    """Graph flow search input; `transactions` defaults to all transactions already loaded in state."""

    root_account: str
    transactions: Optional[list[TransactionEdge]] = Field(
        default=None,
        description="Optional explicit transaction list; omit to analyze all transactions fetched in this session.",
    )
    time_window_days: Optional[int] = Field(default=None, description="Bounded lookahead window in days")
    max_hops: Optional[int] = Field(default=None, description="Bounded maximum path hops")
    amount_tolerance: Optional[Ratio] = Field(default=None, description="Decimal tolerance ratio e.g. '0.10'")
    min_intermediaries: Optional[int] = Field(default=None, description="Minimum intermediaries for scatter-gather")


class LLMConservationInput(StrictModel):
    """Decimal flow conservation check over reconstructed candidate paths."""

    path_ids: list[str] = Field(
        default_factory=list,
        description="Path IDs (e.g. ['PATH-1']) to verify; omit/empty to check top reconstructed multi-hop paths.",
    )
    amount_tolerance: Optional[Ratio] = None


class LLMCompareRunsInput(StrictModel):
    """Compare the two most recent graph scans to inspect newly uncovered consolidation paths."""

    note: str = Field(default="", description="Optional note explaining what delta is being checked")


class CalcInput(StrictModel):
    """Exact Decimal calculator (`sum`, `diff`, `pct`, `compare`) so the LLM never computes mental math."""

    op: Literal["sum", "diff", "pct", "compare"] = Field(
        description="Operation: 'sum' (sum all values), 'diff' (a - b), 'pct' ((a / b) * 100), 'compare' (a vs b)."
    )
    values: list[str] = Field(
        min_length=1,
        description="Exact numeric strings from tool outputs (e.g. ['900000.00', '828000.00']); 2 items for diff/pct.",
    )
    label: str = Field(default="", description="Short description of what figure is being computed")


class ReplanGraphInput(StrictModel):
    """Bounded graph replanning tool; consumes 1 replan slot, increments `replan_count`, and rescans flows."""

    time_window_days: int = Field(description="Updated lookahead window in days within policy bounds")
    max_hops: int = Field(description="Updated maximum hops within policy bounds")
    amount_tolerance: Ratio = Field(description="Updated Decimal tolerance ratio within policy bounds (e.g. '0.15')")
    reason: str = Field(min_length=3, description="Evidence-grounded contradiction or gap motivating the replan")


class HypothesisDraft(StrictModel):
    """Structured hypothesis entry required for both `suspicious` and `benign` perspectives."""

    explanation: str = Field(min_length=5, description="Evidence-grounded explanation without guilt assertions")
    confidence: Confidence = Field(description="Confidence in [0.00, 1.00]")
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Immutable IDs (`TXN-*`, `PATH-*`, `KYC-*`, `REGISTRY-*`, `CALC-*`) grounding this hypothesis",
    )
    regulatory_citations: list[str] = Field(
        default_factory=list,
        description=(
            "Retrieved passage IDs (e.g. PMLA-2002-*, PMLR-2005-*, RBI-KYC-2016-*, "
            "FIU-IND-RFI-*, FATF-*, SOP-*)"
        ),
    )


_DISP_ALIASES: dict[str, str] = {
    "escalate_str": "escalate_str",
    "escalate_str_review": "escalate_str",
    "escalate": "escalate_str",
    "close_benign": "close_benign",
    "benign": "close_benign",
    "request_info": "request_info",
    "insufficient_data": "request_info",
}


def _populate_legacy_hypotheses(merged: dict[str, Any]) -> dict[str, Any]:
    raw_hyps = merged.pop("hypotheses", None)
    if not isinstance(raw_hyps, list):
        return merged
    for item in raw_hyps:
        if not isinstance(item, dict):
            continue
        lbl = str(item.get("label", "")).lower()
        body = {k: v for k, v in item.items() if k != "label"}
        if lbl == "suspicious" and "suspicious_hypothesis" not in merged:
            merged["suspicious_hypothesis"] = body
        elif lbl == "benign" and "benign_hypothesis" not in merged:
            merged["benign_hypothesis"] = body
    return merged


class FinishInvestigationInput(StrictModel):
    """Terminal tool submitting the structured `DispositionWorksheet` draft for deterministic verification."""

    recommended_disposition: Literal["escalate_str", "close_benign", "request_info"]
    confidence_score: Confidence
    recommendation_rationale: str = Field(
        min_length=10,
        description="Concise rationale citing exact tool IDs and copying INR figures verbatim from tool outputs.",
    )
    suspicious_hypothesis: HypothesisDraft
    benign_hypothesis: HypothesisDraft
    missing_evidence: list[str] = Field(
        min_length=1,
        description="Explicit list of missing or out-of-band evidence items (required on every case).",
    )
    regulatory_citations: list[str] = Field(
        default_factory=list,
        description="Verified regulatory clause IDs retrieved from `compliance-kb`.",
    )

    @model_validator(mode="before")
    @classmethod
    def _accept_nested_worksheet(cls, data: Any) -> Any:
        raw = json.loads(data) if isinstance(data, str) else data
        if not isinstance(raw, dict):
            return raw
        inner = raw.get("worksheet_json") or raw.get("worksheet")
        inner_obj = json.loads(inner) if isinstance(inner, str) else inner
        merged = dict(inner_obj) if isinstance(inner_obj, dict) else dict(raw)
        if "hypotheses" in merged:
            return _populate_legacy_hypotheses(merged)
        return merged

    @field_validator("recommended_disposition", mode="before")
    @classmethod
    def _norm_disp(cls, value: Any) -> Any:
        if isinstance(value, str):
            return _DISP_ALIASES.get(value.strip().lower(), value)
        return value


TOOL_SPECS: dict[str, tuple[str, type[BaseModel], str]] = {
    "get_alert_context": (
        "bank-records",
        GetAlertContextInput,
        "Retrieve seed account, network accounts, and initial transactions for an alert ID.",
    ),
    "get_account_transactions": (
        "bank-records",
        GetAccountTransactionsInput,
        "Fetch parameterized read-only transaction history for a specific account within `days_back`.",
    ),
    "get_kyc_profile": (
        "bank-records",
        GetKYCProfileInput,
        "Retrieve customer KYC profile, declared annual income, risk category, and KYC notes.",
    ),
    "get_counterparty_history": (
        "bank-records",
        GetCounterpartyHistoryInput,
        "Inspect historical transfer relationship and prior volume between two accounts.",
    ),
    "check_commercial_registry": (
        "bank-records",
        CheckCommercialRegistryInput,
        "Verify GST / MCA / 80G / Chit commercial registration status for an entity and account.",
    ),
    "find_candidate_fund_flows": (
        "graph-engine",
        LLMFindFlowsInput,
        "Run deterministic MultiDiGraph fund-flow path reconstruction with exact Decimal math.",
    ),
    "compute_flow_conservation": (
        "graph-engine",
        LLMConservationInput,
        "Compute exact Decimal inflow/outflow conservation and structuring flags across candidate paths.",
    ),
    "compare_graph_runs": (
        "graph-engine",
        LLMCompareRunsInput,
        "Compare the previous and latest graph runs to identify newly discovered paths.",
    ),
    "search_regulations": (
        "compliance-kb",
        SearchRegulationsInput,
        "Hybrid RAG search over PMLA 2002, RBI KYC Master Direction, FIU-IND indicators, and SOPs.",
    ),
    "get_clause_by_id": (
        "compliance-kb",
        GetClauseInput,
        "Fetch a specific regulatory passage or internal SOP by its exact ID "
        "(e.g. FIU-IND-RFI-BA-01, PMLA-2002-S12-P01).",
    ),
    "calc": (
        "local",
        CalcInput,
        "Exact Decimal calculator (`sum`, `diff`, `pct`, `compare`); registers a `CALC-*` evidence entry.",
    ),
    "replan_graph": (
        "local",
        ReplanGraphInput,
        "Expand/adjust graph `time_window_days`, `max_hops`, and `amount_tolerance` within policy bounds.",
    ),
    "finish": (
        "local",
        FinishInvestigationInput,
        "Complete the investigation and submit a structured worksheet with both hypotheses and missing evidence.",
    ),
}

_NON_ADVERTISED_TOOLS = frozenset({"draft_disposition_report", "submit_case_disposition"})


def _inline_defs(node: Any, defs: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        if "$ref" in node:
            ref_name = str(node["$ref"]).rsplit("/", 1)[-1]
            resolved = copy.deepcopy(defs.get(ref_name, {}))
            extra = {k: v for k, v in node.items() if k != "$ref"}
            return _inline_defs({**resolved, **extra}, defs)
        return {k: _inline_defs(v, defs) for k, v in node.items() if k not in ("$defs", "title")}
    if isinstance(node, list):
        return [_inline_defs(item, defs) for item in node]
    return node


def build_openai_tools(
    role: str,
    *,
    include_finish: bool = True,
    replanning_enabled: bool = True,
    allow_calc: bool = True,
    allow_registry: bool = True,
    allow_rag: bool = True,
) -> list[dict[str, Any]]:
    """Build OpenAI-compatible `tools` list strictly scoped to `AGENT_TOOL_ALLOWLIST[role]` & ablations."""
    allowed = AGENT_TOOL_ALLOWLIST.get(role, set())
    schemas: list[dict[str, Any]] = []
    for name, (_, model_cls, description) in TOOL_SPECS.items():
        if name not in allowed or name in _NON_ADVERTISED_TOOLS:
            continue
        if (name == "finish" and not include_finish) or (name == "replan_graph" and not replanning_enabled):
            continue
        if (name == "calc" and not allow_calc) or (name == "check_commercial_registry" and not allow_registry):
            continue
        if name in ("search_regulations", "get_clause_by_id") and not allow_rag:
            continue
        raw_schema = model_cls.model_json_schema()
        defs = dict(raw_schema.get("$defs") or {})
        clean_schema = _inline_defs(raw_schema, defs)
        clean_schema.setdefault("type", "object")
        schemas.append(
            {"type": "function", "function": {"name": name, "description": description, "parameters": clean_schema}}
        )
    return schemas


def execute_decimal_calc(inp: CalcInput) -> dict[str, Any]:
    """Pure `Decimal` execution for `calc` (`sum`, `diff`, `pct`, `compare`)."""
    nums = [to_decimal(v, Decimal("0.0001")) for v in inp.values]
    calc_id = f"CALC-{canonical_sha256({'op': inp.op, 'values': [str(n) for n in nums]})[:8].upper()}"
    base: dict[str, Any] = {
        "status": "ok",
        "evidence_id": calc_id,
        "calc_id": calc_id,
        "op": inp.op,
        "inputs": [str(n) for n in nums],
        "label": inp.label,
    }
    if inp.op == "sum":
        total = to_money(sum(nums, Decimal("0")))
        return {**base, "result_inr": dec_str(total), "amount_inr": dec_str(total)}
    if len(nums) != 2:
        raise ValueError(f"calc op={inp.op!r} requires exactly 2 values, got {len(nums)}")
    a, b = nums[0], nums[1]
    if inp.op == "diff":
        signed = (a - b).quantize(CENT)
        abs_val = to_money(abs(a - b))
        return {
            **base,
            "signed_diff_inr": dec_str(signed),
            "result_inr": dec_str(abs_val),
            "amount_inr": dec_str(abs_val),
        }
    if inp.op == "pct":
        if b == 0:
            raise ValueError("calc op='pct' division by zero (second value is 0)")
        pct_val = ((a / b) * Decimal("100")).quantize(CENT)
        return {**base, "result_pct": dec_str(pct_val), "percentage": f"{dec_str(pct_val)}%"}
    rel = "gt" if a > b else ("lt" if a < b else "eq")
    abs_diff = to_money(abs(a - b))
    ratio_str = str(to_ratio(a / b)) if b != 0 and a >= 0 and b > 0 else None
    return {
        **base,
        "relation": rel,
        "abs_diff_inr": dec_str(abs_diff),
        "amount_inr": dec_str(abs_diff),
        "ratio": ratio_str,
    }


def build_hypotheses_from_finish(sub: FinishInvestigationInput) -> list[Hypothesis]:
    """Convert validated `FinishInvestigationInput` drafts into core `Hypothesis` models."""
    return [
        Hypothesis(
            label=HypothesisLabel.SUSPICIOUS,
            explanation=sub.suspicious_hypothesis.explanation,
            supporting_evidence=list(sub.suspicious_hypothesis.supporting_evidence),
            contradicting_evidence=list(sub.suspicious_hypothesis.contradicting_evidence),
            confidence=to_confidence(sub.suspicious_hypothesis.confidence),
            regulatory_citations=list(sub.suspicious_hypothesis.regulatory_citations),
            evidence_ids=list(sub.suspicious_hypothesis.evidence_ids),
        ),
        Hypothesis(
            label=HypothesisLabel.BENIGN,
            explanation=sub.benign_hypothesis.explanation,
            supporting_evidence=list(sub.benign_hypothesis.supporting_evidence),
            contradicting_evidence=list(sub.benign_hypothesis.contradicting_evidence),
            confidence=to_confidence(sub.benign_hypothesis.confidence),
            regulatory_citations=list(sub.benign_hypothesis.regulatory_citations),
            evidence_ids=list(sub.benign_hypothesis.evidence_ids),
        ),
    ]


def format_rationale_with_missing(sub: FinishInvestigationInput) -> tuple[DispositionDecision, float, str]:
    disp = DispositionDecision(sub.recommended_disposition)
    conf = float(to_confidence(sub.confidence_score))
    rationale = sub.recommendation_rationale.strip()
    missing_joined = "; ".join(m.strip() for m in sub.missing_evidence if m.strip())
    if missing_joined and "missing evidence" not in rationale.lower():
        rationale = f"{rationale} Missing evidence: {missing_joined}."
    return disp, conf, rationale
