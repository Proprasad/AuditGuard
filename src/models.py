"""
AuditGuard - Core Data Models (Pydantic v2, strict, exact decimals).

All currency / ratio / confidence fields use `Money` / `Ratio` / `Confidence` / `Usd` (Decimal-only, JSON strings).
There are no showcase defaults: alert IDs, accounts and amounts must always be supplied by a trusted source.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.core.canonical import Confidence, Money, Ratio, Usd, canonical_sha256, utc_now


def _policy() -> Any:
    from src.config import get_policy

    return get_policy()


def _zero_usd() -> Decimal:
    return Decimal("0.000000")


def _zero_conf() -> Decimal:
    return Decimal("0.0000")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AlertStatus(str, Enum):
    OPEN = "open"
    UNDER_INVESTIGATION = "under_investigation"
    ESCALATED_STR = "escalated_str"
    CLOSED_BENIGN = "closed_benign"
    CLOSED_PENDING_INFO = "closed_pending_info"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HypothesisLabel(str, Enum):
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"


class DispositionDecision(str, Enum):
    ESCALATE_STR = "escalate_str"
    CLOSE_BENIGN = "close_benign"
    REQUEST_INFO = "request_info"
    REJECTED = "rejected"
    PENDING = "pending"


class Alert(StrictModel):
    alert_id: str
    rule_name: str
    root_account: str
    network_accounts: list[str] = Field(default_factory=list)
    total_amount_inr: Money
    triggered_at: datetime = Field(default_factory=utc_now)
    status: AlertStatus = AlertStatus.OPEN
    risk_level: RiskLevel = RiskLevel.MEDIUM


class FundFlowPath(StrictModel):
    """Candidate layering path reconstructed by the graph engine using `Decimal` (deterministic IDs)."""

    path_id: str
    nodes: list[str]
    edge_tx_ids: list[str] = Field(default_factory=list)
    total_outflow_inr: Money
    total_consolidated_inr: Money
    net_difference_inr: Money
    retention_pct: Money
    hop_count: int
    time_span_days: Money
    amount_leaked_ratio: Ratio
    is_suspicious: bool = False
    suspicion_reason: str = "none"


class GraphParams(StrictModel):
    time_window_days: int
    max_hops: int
    amount_tolerance: Ratio
    min_intermediaries: int

    @classmethod
    def policy_default(cls) -> GraphParams:
        return cls(**_policy().default_graph_params())


class Hypothesis(StrictModel):
    label: HypothesisLabel
    explanation: str
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    confidence: Confidence
    regulatory_citations: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class InvestigationPlan(StrictModel):
    plan_id: str = Field(default_factory=lambda: uuid4().hex[:8])
    steps: list[str]
    graph_params: GraphParams = Field(default_factory=GraphParams.policy_default)
    focus_accounts: list[str] = Field(default_factory=list)
    regulatory_queries: list[str] = Field(default_factory=list)
    clause_ids: list[str] = Field(default_factory=list)
    replan_count: int = 0
    replan_reason: Optional[str] = None


class DispositionWorksheet(StrictModel):
    """
    Citation-verified worksheet for mandatory human review. `compute_hash()` produces the exact same canonical
    SHA-256 (`payload_hash`) persisted and verified by `case-actions`.
    """

    worksheet_id: str = Field(default_factory=lambda: f"DWS-{uuid4().hex[:8].upper()}")
    alert_id: str
    created_at: datetime = Field(default_factory=utc_now)
    drafted_at: Optional[str] = None
    investigator_agent: str

    candidate_paths: list[FundFlowPath] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    regulatory_citations: list[str] = Field(default_factory=list)
    kyc_summaries: list[str] = Field(default_factory=list)
    degraded_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    alert_amount_inr: Optional[str] = None
    verification_status: str = "passed"
    verification_discrepancies: list[dict[str, Any]] = Field(default_factory=list)

    recommended_disposition: DispositionDecision = DispositionDecision.PENDING
    recommendation_rationale: str = ""
    confidence_score: Confidence = Field(default_factory=_zero_conf)

    analyst_notes: Optional[str] = None
    edited_by: Optional[str] = None
    edited_at: Optional[str] = None

    reviewer_id: Optional[str] = None
    reviewer_decision: Optional[DispositionDecision] = None
    reviewer_notes: str = ""
    reviewed_at: Optional[datetime] = None

    payload_hash: str = ""

    @model_validator(mode="before")
    @classmethod
    def _drop_legacy_computed(cls, data: Any) -> Any:
        if isinstance(data, dict) and "approval_token" in data:
            data = {k: v for k, v in data.items() if k != "approval_token"}
        return data

    def canonical_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "alert_id": self.alert_id,
            "recommended_disposition": self.recommended_disposition.value,
            "recommendation_rationale": self.recommendation_rationale,
            "confidence_score": self.confidence_score,
            "candidate_paths": [p.model_dump(mode="json") for p in self.candidate_paths],
            "regulatory_citations": list(self.regulatory_citations),
            "kyc_summaries": list(self.kyc_summaries),
            "hypotheses": [h.model_dump(mode="json") for h in self.hypotheses],
            "degraded_evidence": list(self.degraded_evidence),
            "alert_amount_inr": self.alert_amount_inr,
            "verification_status": self.verification_status,
            "verification_discrepancies": list(self.verification_discrepancies),
            "drafted_at": self.drafted_at,
        }
        for opt_key in ("analyst_notes", "edited_by", "edited_at"):
            val = getattr(self, opt_key)
            if val is not None:
                payload[opt_key] = val
        return payload

    def compute_hash(self) -> str:
        return canonical_sha256(self.canonical_payload())


class SpecialistHandOff(StrictModel):
    task_id: str
    target_agent: Literal["flow_tracer", "benign_investigator", "regulatory_analyst", "reporter_critic"]
    objective: str
    allowed_tool_budget: int = Field(ge=0)


class SpecialistFinding(StrictModel):
    task_id: str
    agent_name: str
    summary: str
    tool_calls: int = Field(ge=0)
    evidence_ids_added: list[str] = Field(default_factory=list)
    recommended_replan: Optional[dict[str, Any]] = None


class InvestigationState(StrictModel):
    """Typed investigation state (durably checkpointed per `thread_id`)."""

    thread_id: str = Field(default_factory=lambda: f"thr-{uuid4().hex[:12]}")
    alert: Alert

    plan: Optional[InvestigationPlan] = None
    proposed_params: Optional[GraphParams] = None
    proposed_focus_accounts: list[str] = Field(default_factory=list)
    proposed_regulatory_queries: list[str] = Field(default_factory=list)
    proposed_clause_ids: list[str] = Field(default_factory=list)
    refresh_kyc: bool = False
    refresh_regulations: bool = False
    reasoning_mode: str = "rubric"
    current_node: str = "start"
    current_step: int = 0
    replan_count: int = 0
    max_replans: int = Field(default_factory=lambda: _policy().budgets.max_replans)

    evidence_registry: dict[str, Any] = Field(default_factory=dict)
    calc_log: list[dict[str, Any]] = Field(default_factory=list)
    retrieved_lessons: list[str] = Field(default_factory=list)
    transactions: list[dict[str, Any]] = Field(default_factory=list)
    kyc_profiles: list[dict[str, Any]] = Field(default_factory=list)
    fund_flow_paths: list[FundFlowPath] = Field(default_factory=list)
    regulatory_snippets: list[str] = Field(default_factory=list)
    regulatory_clauses: list[dict[str, Any]] = Field(default_factory=list)
    specialist_handoffs: list[dict[str, Any]] = Field(default_factory=list)
    specialist_findings: list[dict[str, Any]] = Field(default_factory=list)
    degraded_evidence: list[str] = Field(default_factory=list)

    active_hypotheses: list[Hypothesis] = Field(default_factory=list)
    critiques: list[str] = Field(default_factory=list)

    workflow_steps: list[dict[str, Any]] = Field(default_factory=list)
    agent_runs: list[dict[str, Any]] = Field(default_factory=list)
    flow_summary: dict[str, Any] = Field(default_factory=dict)

    worksheet: Optional[DispositionWorksheet] = None
    human_decision: Optional[DispositionDecision] = None

    tool_calls_used: int = 0
    tool_error_count: int = 0
    tool_errors: list[dict[str, Any]] = Field(default_factory=list)
    max_tool_calls: int = Field(default_factory=lambda: _policy().budgets.max_tool_calls)
    critique_retries_used: int = 0
    total_tokens_used: int = 0
    estimated_cost_usd: Usd = Field(default_factory=_zero_usd)
    budget_remaining_usd: Usd = Field(default_factory=lambda: _policy().budgets.max_cost_usd_per_case)

    rolling_summary: str = ""
    messages: list[dict[str, Any]] = Field(default_factory=list)

    error: Optional[str] = None
    is_complete: bool = False


class InvestigateRequest(StrictModel):
    """The server resolves root account / network / amount from the trusted alert record."""

    alert_id: str
    agent_mode: Literal["c0_fixed", "rule_engine", "c1_single", "c2_multi"] = Field(validation_alias="mode")

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class InvestigateResponse(StrictModel):
    thread_id: str
    alert_id: str
    status: str
    payload_hash: Optional[str] = None
    worksheet: Optional[DispositionWorksheet] = None
    replan_count: int = 0
    tool_calls_used: int = 0
    tool_errors: int = 0
    cost_usd: Usd = Field(default_factory=_zero_usd)
    tokens_used: int = 0


class PrepareDecisionRequest(StrictModel):
    """Request an analyst/reviewer-signed single-use approval token (15-minute TTL)."""

    thread_id: Optional[str] = None
    approved_hash: Optional[str] = None


class EditWorksheetRequest(StrictModel):
    """Restricted analyst edit: only these fields may change; everything else is evidence-derived."""

    recommended_disposition: Optional[DispositionDecision] = None
    recommendation_rationale: Optional[str] = Field(default=None, max_length=8000)
    analyst_notes: Optional[str] = Field(default=None, max_length=4000)


class DecisionRequest(StrictModel):
    """Human decision. Reviewer identity comes from the JWT, never from the body."""

    action: Literal["approve", "edit", "reject"]
    approved_hash: Optional[str] = None
    approval_token: Optional[str] = None
    edit: Optional[EditWorksheetRequest] = None
    notes: str = Field(default="", max_length=4000)

    @model_validator(mode="after")
    def _check_action_fields(self) -> DecisionRequest:
        if self.action == "approve" and not (self.approved_hash and self.approval_token):
            raise ValueError("approve requires approved_hash and approval_token")
        if self.action == "edit" and self.edit is None:
            raise ValueError("edit requires an 'edit' payload")
        return self
