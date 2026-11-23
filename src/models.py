"""
AuditGuard - Core Data Models (Pydantic v2, strict, exact decimals).

All currency / ratio fields use `Money` / `Ratio` / `Usd` (Decimal-only, JSON strings). There are no
showcase defaults: alert IDs, accounts and amounts must always be supplied by a trusted source.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.core.canonical import Money, Ratio, Usd, canonical_sha256, utc_now


def _policy() -> Any:
    from src.config import get_policy

    return get_policy()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Enums
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Core Domain
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    confidence: float = Field(ge=0.0, le=1.0)
    regulatory_citations: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class InvestigationPlan(StrictModel):
    plan_id: str = Field(default_factory=lambda: uuid4().hex[:8])
    steps: list[str]
    graph_params: GraphParams = Field(default_factory=GraphParams.policy_default)
    replan_count: int = 0
    replan_reason: Optional[str] = None


class DispositionWorksheet(StrictModel):
    """
    Citation-verified worksheet for mandatory human review. `payload_hash` is the canonical SHA-256 recorded
    by case-actions at draft time (single source of truth); any edit recomputes it.
    """

    worksheet_id: str = Field(default_factory=lambda: f"DWS-{uuid4().hex[:8].upper()}")
    alert_id: str
    created_at: datetime = Field(default_factory=utc_now)
    investigator_agent: str

    candidate_paths: list[FundFlowPath] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    regulatory_citations: list[str] = Field(default_factory=list)
    kyc_summaries: list[str] = Field(default_factory=list)

    recommended_disposition: DispositionDecision = DispositionDecision.PENDING
    recommendation_rationale: str = ""
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)

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
        return self.model_dump(
            mode="python",
            exclude={"payload_hash", "reviewer_id", "reviewer_decision", "reviewer_notes", "reviewed_at"},
        )

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
    reasoning_mode: str = "rubric"
    current_node: str = "start"
    current_step: int = 0
    replan_count: int = 0
    max_replans: int = Field(default_factory=lambda: _policy().budgets.max_replans)

    evidence_registry: dict[str, Any] = Field(default_factory=dict)
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
    max_tool_calls: int = Field(default_factory=lambda: _policy().budgets.max_tool_calls)
    total_tokens_used: int = 0
    estimated_cost_usd: Usd = Field(default_factory=lambda: _zero_usd())
    budget_remaining_usd: Usd = Field(default_factory=lambda: _policy().budgets.max_cost_usd_per_case)

    rolling_summary: str = ""
    messages: list[dict[str, Any]] = Field(default_factory=list)

    error: Optional[str] = None
    is_complete: bool = False


def _zero_usd() -> Any:
    from decimal import Decimal

    return Decimal("0.000000")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ API Schemas
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class InvestigateRequest(StrictModel):
    """The server resolves root account / network / amount from the trusted alert record."""

    alert_id: str
    agent_mode: Literal["c0_fixed", "c1_single", "c2_multi"] = Field(validation_alias="mode")

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class InvestigateResponse(StrictModel):
    thread_id: str
    alert_id: str
    status: str
    payload_hash: Optional[str] = None
    worksheet: Optional[DispositionWorksheet] = None
    replan_count: int = 0
    tool_calls_used: int = 0
    cost_usd: Usd = Field(default_factory=_zero_usd)
    tokens_used: int = 0


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
    def _check_action_fields(self) -> "DecisionRequest":
        if self.action == "approve" and not (self.approved_hash and self.approval_token):
            raise ValueError("approve requires approved_hash and approval_token")
        if self.action == "edit" and self.edit is None:
            raise ValueError("edit requires an 'edit' payload")
        return self
