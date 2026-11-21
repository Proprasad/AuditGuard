"""
AuditGuard - Core Data Models (Pydantic v2)

Shared schemas used across all modules:
- InvestigationState  -> Typed state persisted in SQLite/PostgreSQL checkpoints
- DispositionWorksheet -> Citation-verified worksheet with SHA-256 payload hash
- Alert, Transaction, KYCProfile, FundFlowPath, Hypothesis
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────── Enums ────────────────────────────

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


# ─────────────────────────── Core Domain ──────────────────────

class Transaction(BaseModel):
    tx_id: str
    sender_account: str
    receiver_account: str
    amount_inr: float
    currency: str = "INR"
    timestamp: datetime
    bank_code: str = "HDFC"
    memo: Optional[str] = None
    channel: str = "NEFT"
    is_flagged: bool = False


class KYCProfile(BaseModel):
    account_id: str
    entity_name: str
    entity_type: Literal["individual", "company", "trust", "ngo"] = "individual"
    pan: Optional[str] = None
    gstin: Optional[str] = None
    risk_category: RiskLevel = RiskLevel.LOW
    registered_address: str = ""
    business_description: str = ""
    pep_flag: bool = False
    sanctions_flag: bool = False
    onboarded_at: datetime = Field(default_factory=_utc_now)


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: f"ALT-{uuid4().hex[:8].upper()}")
    rule_name: str = "SCATTER_GATHER"
    triggered_at: datetime = Field(default_factory=_utc_now)
    root_account: str = "ACC-IND-1042"
    network_accounts: list[str] = Field(default_factory=list)
    total_amount_inr: float = 900_000.0
    status: AlertStatus = AlertStatus.OPEN
    risk_level: RiskLevel = RiskLevel.MEDIUM


class FundFlowPath(BaseModel):
    """A candidate layering path reconstructed by graph-engine using Python Decimal."""
    path_id: str = Field(default_factory=lambda: uuid4().hex[:8])
    nodes: list[str]
    edges: list[Transaction] = Field(default_factory=list)
    edge_tx_ids: list[str] = Field(default_factory=list)
    total_amount: float
    total_outflow_inr: str = "0.00"
    total_consolidated_inr: str = "0.00"
    net_difference_inr: str = "0.00"
    retention_pct: str = "0.00"
    hop_count: int
    time_span_days: float
    amount_leaked_pct: float = 0.0


class Hypothesis(BaseModel):
    label: HypothesisLabel
    explanation: str
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    regulatory_citations: list[str] = Field(default_factory=list)


class InvestigationPlan(BaseModel):
    """Visible structured plan — Signature Challenge A."""
    plan_id: str = Field(default_factory=lambda: uuid4().hex[:8])
    steps: list[str]
    graph_params: dict[str, Any] = Field(
        default_factory=lambda: {
            "time_window_days": 7,
            "max_hops": 3,
            "amount_tolerance": 0.10,
        }
    )
    replan_count: int = 0
    replan_reason: Optional[str] = None


class DispositionWorksheet(BaseModel):
    """
    Citation-verified worksheet for mandatory human review.
    Signature Challenge B: SHA-256 canonical payload hash.
    Any edit to the worksheet invalidates the prior approval token.
    """
    worksheet_id: str = Field(default_factory=lambda: f"DWS-{uuid4().hex[:8].upper()}")
    alert_id: str
    created_at: datetime = Field(default_factory=_utc_now)
    investigator_agent: str = "auditguard-c1"

    # Evidence
    candidate_paths: list[FundFlowPath] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    regulatory_citations: list[str] = Field(default_factory=list)
    kyc_summaries: list[str] = Field(default_factory=list)

    # Recommendation
    recommended_disposition: DispositionDecision = DispositionDecision.PENDING
    recommendation_rationale: str = ""
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)

    # Human review
    reviewer_id: Optional[str] = None
    reviewer_decision: Optional[DispositionDecision] = None
    reviewer_notes: str = ""
    reviewed_at: Optional[datetime] = None

    # Integrity
    approval_token: Optional[str] = None

    @computed_field
    @property
    def payload_hash(self) -> str:
        """SHA-256 of canonical JSON payload. Excludes payload_hash & review metadata."""
        payload = self.model_dump(
            exclude={
                "payload_hash",
                "approval_token",
                "reviewer_id",
                "reviewer_decision",
                "reviewer_notes",
                "reviewed_at",
            }
        )
        canonical = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def is_approval_valid(self) -> bool:
        if not self.approval_token:
            return False
        return self.approval_token == f"APPROVED:{self.payload_hash}"


# ─────────────────────────── LangGraph Typed State ────────────

class InvestigationState(BaseModel):
    """
    Typed LangGraph state — durably checkpointed in SQLite/PostgreSQL per `thread_id`.
    """
    thread_id: str = Field(default_factory=lambda: f"thr-{uuid4().hex[:12]}")
    alert: Alert

    # Lifecycle & planning
    plan: Optional[InvestigationPlan] = None
    current_node: str = "start"
    current_step: int = 0
    replan_count: int = 0
    max_replans: int = 3

    # Immutable Evidence Registry & gathered records
    evidence_registry: dict[str, Any] = Field(default_factory=dict)
    retrieved_lessons: list[str] = Field(default_factory=list)
    transactions: list[dict[str, Any]] = Field(default_factory=list)
    kyc_profiles: list[dict[str, Any]] = Field(default_factory=list)
    fund_flow_paths: list[FundFlowPath] = Field(default_factory=list)
    regulatory_snippets: list[str] = Field(default_factory=list)

    # Hypotheses & critique
    active_hypotheses: list[Hypothesis] = Field(default_factory=list)
    critiques: list[str] = Field(default_factory=list)

    # Output
    worksheet: Optional[DispositionWorksheet] = None
    human_decision: Optional[DispositionDecision] = None

    # Budgets & telemetry
    tool_calls_used: int = 0
    max_tool_calls: int = 15
    total_tokens_used: int = 0
    estimated_cost_usd: float = 0.0
    budget_remaining_usd: float = 0.15

    # Short-term memory
    rolling_summary: str = ""
    messages: list[dict[str, Any]] = Field(default_factory=list)

    error: Optional[str] = None
    is_complete: bool = False


# ─────────────────────────── API Schemas ──────────────────────

class InvestigateRequest(BaseModel):
    alert_id: str
    rule_name: str = "SCATTER_GATHER"
    root_account: str = "ACC-IND-1042"
    network_accounts: list[str] = Field(default_factory=list)
    total_amount_inr: float = 900_000.0
    agent_mode: Literal["c0_fixed", "c1_single", "c2_multi"] = Field(
        default="c1_single", validation_alias="mode"
    )

    model_config = {"populate_by_name": True}


class InvestigateResponse(BaseModel):
    thread_id: str
    alert_id: str
    status: str
    payload_hash: Optional[str] = None
    worksheet: Optional[DispositionWorksheet] = None
    replan_count: int = 0
    tool_calls_used: int = 0
    cost_usd: float = 0.0
    tokens_used: int = 0


class HumanDecisionRequest(BaseModel):
    thread_id: Optional[str] = None
    worksheet_id: Optional[str] = None
    action: Literal["approve", "edit", "reject"] = "approve"
    decision: DispositionDecision = DispositionDecision.ESCALATE_STR
    approved_hash: Optional[str] = None
    edited_fields: Optional[dict[str, Any]] = None
    reviewer_id: str = "analyst_01"
    notes: str = ""
