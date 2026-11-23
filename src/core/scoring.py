"""
Pure, framework-free hypothesis scoring (offline mode) and disposition decision.

Confidences are *computed from evidence features* with weights loaded from `config/models.yaml` (`scoring:`);
there are no per-case constants. When a live LLM scores the hypotheses instead, this module is not used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

from src.core.policy import ScoringConfig


@dataclass(frozen=True)
class EvidenceFeatures:
    multi_hop_path: bool = False
    flagged_path: bool = False
    income_mismatch: bool = False
    high_kyc_risk: bool = False
    unregistered_root: bool = False
    registered_root: bool = False
    verified_merchants_low_risk: bool = False
    low_kyc_risk: bool = False

    def active_suspicious(self) -> list[str]:
        return [
            k
            for k in (
                "multi_hop_path",
                "flagged_path",
                "income_mismatch",
                "high_kyc_risk",
                "unregistered_root",
            )
            if getattr(self, k)
        ]

    def active_benign(self) -> list[str]:
        return [k for k in ("registered_root", "verified_merchants_low_risk", "low_kyc_risk") if getattr(self, k)]


@dataclass(frozen=True)
class RubricResult:
    suspicious: Decimal
    benign: Decimal
    trace: list[str] = field(default_factory=list)


def _clamp(value: Decimal, cfg: ScoringConfig) -> Decimal:
    return max(cfg.min_confidence, min(cfg.max_confidence, value))


def rubric_scores(features: EvidenceFeatures, cfg: ScoringConfig) -> RubricResult:
    score = cfg.prior
    trace = [f"prior={cfg.prior}"]
    for name in features.active_suspicious():
        weight = cfg.suspicious_weights.get(name, Decimal("0"))
        score += weight
        trace.append(f"+{weight} {name}")
    for name in features.active_benign():
        weight = cfg.benign_weights.get(name, Decimal("0"))
        score -= weight
        trace.append(f"-{weight} {name}")
    suspicious = _clamp(score, cfg)
    return RubricResult(suspicious=suspicious, benign=_clamp(Decimal("1") - suspicious, cfg), trace=trace)


def decide(suspicious: float, benign: float, degraded: bool, cfg: ScoringConfig) -> tuple[str, float]:
    """Return (disposition value, confidence). Degraded/ambiguous evidence never yields a confident closure."""
    threshold = float(cfg.disposition_threshold)
    floor = float(cfg.request_info_floor)
    if degraded and suspicious < threshold and benign < threshold:
        return "request_info", max(suspicious, benign, floor)
    if suspicious >= threshold:
        return "escalate_str", suspicious
    if benign >= threshold:
        return "close_benign", benign
    return "request_info", max(suspicious, benign, floor)
