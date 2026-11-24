"""
Pluggable Typology Registry (`src/typology_registry.py`).

Decouples agent orchestration and deterministic citation-relevance verification from
typology-specific rules; graph bounds come from `PolicyConfig`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.config import get_policy

_SUSPICIOUS_CATEGORIES = [
    "layering",
    "structuring",
    "fee_skimming",
    "two_tier_layering",
    "dormant_reactivation",
    "shell_entities",
    "edd",
    "risk_categorization",
    "pep",
    "periodic_updation",
    "wire_transfers",
    "offence_definition",
    "record_keeping",
    "confidentiality",
    "str_obligation",
    "principal_officer",
    "filing_timeline",
    "chit_fund",
    "ngo_monitoring",
    "wire_traceability",
    "str_standard",
    "replanning",
    "decimal_math",
    "governance",
]

_BENIGN_CATEGORIES = [
    "commercial_verification",
    "ngo_monitoring",
    "marketplace_escrow",
    "chit_fund",
    "benign_lookalikes",
    "payroll_verification",
    "wedding_social",
    "edd",
    "risk_categorization",
    "record_keeping",
    "str_standard",
    "decimal_math",
    "governance",
]

_INCOMPLETE_CATEGORIES = [
    "incomplete_data",
    "wire_transfers",
    "wire_traceability",
    "periodic_updation",
    "edd",
    "risk_categorization",
    "commercial_verification",
    "shell_entities",
    "record_keeping",
    "replanning",
    "layering",
    "structuring",
    "fee_skimming",
    "two_tier_layering",
    "dormant_reactivation",
    "pep",
    "str_obligation",
    "str_standard",
    "benign_lookalikes",
    "chit_fund",
    "decimal_math",
    "governance",
]

_ALL_SCATTER_GATHER_CATEGORIES = sorted(
    {*_SUSPICIOUS_CATEGORIES, *_BENIGN_CATEGORIES, *_INCOMPLETE_CATEGORIES}
)


class TypologySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    typology_id: str
    name: str
    description: str
    required_checks: list[str]
    applicable_regulations: list[str]
    allowed_categories: list[str] = Field(default_factory=list)
    claim_category_map: dict[str, list[str]] = Field(default_factory=dict)

    @property
    def default_graph_params(self) -> dict[str, Any]:
        return get_policy().default_graph_params()


class TypologyRegistry:
    def __init__(self) -> None:
        self._registry: dict[str, TypologySpec] = {}

    def register(self, spec: TypologySpec) -> None:
        self._registry[spec.typology_id] = spec

    def get(self, typology_id: str) -> TypologySpec | None:
        return self._registry.get(typology_id)

    def list_typologies(self) -> list[str]:
        return list(self._registry.keys())

    def all_typology_categories(self, typology_id: str = "scatter_gather") -> frozenset[str]:
        spec = self._registry.get(typology_id)
        return frozenset(spec.allowed_categories) if spec else frozenset()

    def allowed_categories_for_claim(self, claim_type: str, typology_id: str = "scatter_gather") -> frozenset[str]:
        spec = self._registry.get(typology_id)
        if spec is None:
            return frozenset()
        cats = spec.claim_category_map.get(claim_type.lower())
        if cats is not None:
            return frozenset(cats)
        return frozenset(spec.allowed_categories)


typology_registry = TypologyRegistry()
typology_registry.register(
    TypologySpec(
        typology_id="scatter_gather",
        name="Scatter-Gather Layering & Benign Look-Alikes",
        description="Fan-out distribution from a seed account into intermediaries followed by fan-in consolidation.",
        required_checks=[
            "find_candidate_fund_flows",
            "get_kyc_profile",
            "check_commercial_registry",
            "search_regulations",
        ],
        applicable_regulations=["FIU-IND-RFI-BA-01", "RBI-KYC-2016-P35-P01", "PMLR-2005-R3-P03"],
        allowed_categories=_ALL_SCATTER_GATHER_CATEGORIES,
        claim_category_map={
            "escalate_str": _SUSPICIOUS_CATEGORIES,
            "suspicious": _SUSPICIOUS_CATEGORIES,
            "close_benign": _BENIGN_CATEGORIES,
            "benign": _BENIGN_CATEGORIES,
            "request_info": _INCOMPLETE_CATEGORIES,
            "pending": _ALL_SCATTER_GATHER_CATEGORIES,
        },
    )
)
