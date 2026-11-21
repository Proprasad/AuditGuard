"""
Pluggable Typology Registry (Section 3.8)
Decouples agent orchestration from typology-specific rules.
Phase 1 registers `scatter_gather`. Future phases register fan_in, structuring, etc.
"""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel


class TypologySpec(BaseModel):
    typology_id: str
    name: str
    description: str
    default_graph_params: dict[str, Any]
    required_checks: list[str]
    applicable_regulations: list[str]


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
        default_graph_params={
            "time_window_days": 7,
            "max_hops": 3,
            "amount_tolerance": 0.10,
            "min_intermediaries": 2,
        },
        required_checks=[
            "find_candidate_fund_flows",
            "get_kyc_profile",
            "check_commercial_registry",
            "search_regulations",
        ],
        applicable_regulations=["REG-FIU-RF-014", "REG-RBI-KYC-P35", "REG-PMLA-R3"],
    )
)
