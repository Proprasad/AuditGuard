"""
Pluggable Typology Registry (Section 3.8).
Decouples agent orchestration from typology-specific rules; bounds come from `PolicyConfig`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from src.config import get_policy


class TypologySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    typology_id: str
    name: str
    description: str
    required_checks: list[str]
    applicable_regulations: list[str]

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
        applicable_regulations=["REG-FIU-RF-014", "REG-RBI-KYC-P35", "REG-PMLA-R3"],
    )
)
