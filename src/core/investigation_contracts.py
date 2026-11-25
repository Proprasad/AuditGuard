"""
Enhanced Investigation Intelligence Contracts (`src/core/investigation_contracts.py`).

Framework-free, strict Pydantic v2 contracts for:
  * Supervisor dynamic routing & coverage invariants (`SupervisorRoutingPlan`)
  * Competing suspicious vs. benign hypothesis investigation (`HypothesisEvaluation`, `CompetingHypothesisAssessment`)
  * Claim-level evidence provenance & verification (`EvidenceClaim`)
  * Evidence-driven replanning & before/after comparisons (`ReplanSnapshot`, `ReplanComparison`, `ReplanRecord`)
  * Independent semantic/structural critique separated from deterministic verification
    (`CriticChallenge`, `CriticAssessment`)
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from src.core.canonical import Ratio
from src.models import GraphParams, HypothesisLabel

HypothesisOutcome = Literal[
    "supported",
    "contradicted",
    "insufficient_evidence",
    "additional_investigation_required",
]
ClaimRelationship = Literal["supporting", "contradicting", "contextual"]
ClaimVerificationStatus = Literal["verified", "ungrounded", "wrong_case", "contradicted", "uncertain"]
EvidenceQuality = Literal["high", "moderate", "low", "none"]
ReplanValidationStatus = Literal["approved", "rejected_bounds", "rejected_budget", "rejected_disabled"]
ReplanExecutionStatus = Literal["executed", "failed", "skipped"]
CriticCategory = Literal[
    "unsupported_conclusion",
    "specialist_inconsistency",
    "contradictory_evidence",
    "misrepresented_evidence",
    "missing_regulatory_support",
    "unsupported_benign",
    "unjustified_suspicious",
    "incomplete_investigation",
]
SpecialistRole = Literal["flow_tracer", "benign_investigator", "regulatory_analyst", "reporter_critic"]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceClaim(_Contract):
    """Atomic material claim linked to immutable evidence references with deterministic verification status."""

    claim_id: str
    claim_text: str
    evidence_ids: list[str] = Field(default_factory=list)
    evidence_sources: list[str] = Field(default_factory=list)
    relationship: ClaimRelationship = "supporting"
    relevance_explanation: str = ""
    verification_status: ClaimVerificationStatus = "verified"
    issues: list[str] = Field(default_factory=list)


class HypothesisEvaluation(_Contract):
    """Structured evaluation of one competing hypothesis (suspicious or benign)."""

    hypothesis_id: str
    label: HypothesisLabel
    explanation: str
    candidate_typologies: list[str] = Field(default_factory=list)
    outcome: HypothesisOutcome
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    supporting_claims: list[str] = Field(default_factory=list)
    contradicting_claims: list[str] = Field(default_factory=list)
    evidence_quality: EvidenceQuality = "moderate"
    missing_information: list[str] = Field(default_factory=list)
    unresolved_contradictions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommended_next_step: str = ""
    score_note: str = (
        "Investigation assessment score reflects current evidence balance; "
        "it is not a calibrated probability or legal finding of guilt."
    )


class CompetingHypothesisAssessment(_Contract):
    """Standardized suspicious-vs-benign comparison shared across C1 and C2."""

    suspicious: HypothesisEvaluation
    benign: HypothesisEvaluation
    leading_hypothesis: Literal["suspicious", "benign", "tie_inconclusive"]
    overall_outcome: HypothesisOutcome
    distinction_note: str
    unresolved_contradictions: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    recommended_next_step: str = ""


class ReplanSnapshot(_Contract):
    """Point-in-time investigation coverage metrics used for before/after replan comparison."""

    time_window_days: int
    max_hops: int
    amount_tolerance: Ratio
    candidate_paths_count: int = 0
    multi_hop_paths_count: int = 0
    evidence_count: int = 0
    contradictions_count: int = 0
    unresolved_questions_count: int = 0
    completeness: Literal["complete", "partial", "insufficient"] = "partial"


class ReplanComparison(_Contract):
    """Measurable delta between original and replanned investigation passes."""

    before: ReplanSnapshot
    after: ReplanSnapshot
    new_path_ids: list[str] = Field(default_factory=list)
    evidence_delta: int = 0
    improved: bool = False
    improvement_summary: str = ""


class ReplanRecord(_Contract):
    """Auditable record of a proposed or executed evidence-driven replan."""

    replan_id: str
    trigger_condition: str
    contradiction_or_gap: str
    evidence_ids: list[str] = Field(default_factory=list)
    original_params: GraphParams
    proposed_params: GraphParams
    reason: str
    expected_benefit: str = ""
    validation_result: ReplanValidationStatus = "approved"
    validation_detail: str = ""
    execution_status: ReplanExecutionStatus = "executed"
    comparison: Optional[ReplanComparison] = None


class CriticChallenge(_Contract):
    """Single independent challenge raised by the Critic stage."""

    challenge_id: str
    category: CriticCategory
    severity: Literal["high", "medium", "low"] = "medium"
    description: str
    evidence_ids: list[str] = Field(default_factory=list)
    requires_human_review: bool = True


class CriticAssessment(_Contract):
    """Semantic/structural critique strictly separated from deterministic Verifier v2 checks."""

    assessment_type: Literal["semantic_and_structural_critique"] = "semantic_and_structural_critique"
    challenges: list[CriticChallenge] = Field(default_factory=list)
    inconsistencies_found: list[str] = Field(default_factory=list)
    ignored_contradictions: list[str] = Field(default_factory=list)
    regulatory_grounding_gaps: list[str] = Field(default_factory=list)
    uncertain_findings: list[str] = Field(default_factory=list)
    passed_independent_critique: bool = True
    requires_additional_investigation: bool = False


class SupervisorRoutingPlan(_Contract):
    """Validated C2 supervisor routing decision with mandatory coverage and budget invariants."""

    selected_specialists: list[SpecialistRole] = Field(min_length=1)
    execution_order: list[list[SpecialistRole]] = Field(min_length=1)
    selection_rationale: dict[str, str] = Field(default_factory=dict)
    dependencies: dict[str, list[str]] = Field(default_factory=dict)
    completion_conditions: list[str] = Field(default_factory=list)
    replan_conditions: list[str] = Field(default_factory=list)
    reserved_critic_budget: int = Field(default=2, ge=1)
    mandatory_coverage_verified: bool = True
