"""
Pure, framework-free hypothesis scoring (offline mode) and disposition decision.

Confidences are *computed from evidence features* with weights loaded from `config/models.yaml` (`scoring:`);
there are no per-case constants. When a live LLM scores the hypotheses instead, this module is not used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

from src.core.canonical import to_ratio
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
    if not features.multi_hop_path and score >= cfg.disposition_threshold:
        score = cfg.disposition_threshold - cfg.no_multi_hop_margin
        trace.append("cap<threshold (no_multi_hop_consolidation)")
    suspicious = _clamp(score, cfg)
    return RubricResult(suspicious=suspicious, benign=_clamp(Decimal("1") - suspicious, cfg), trace=trace)


def decide(
    suspicious: Decimal | str | int,
    benign: Decimal | str | int,
    degraded: bool,
    cfg: ScoringConfig,
    *,
    critical_missing: bool = False,
) -> tuple[str, Decimal]:
    """Return `(disposition, Decimal confidence)`. Missing critical evidence or ambiguity never yields closure."""
    susp_d = to_ratio(suspicious)
    ben_d = to_ratio(benign)
    threshold = cfg.disposition_threshold
    floor = cfg.request_info_floor
    if critical_missing:
        return "request_info", max(susp_d, ben_d, floor)
    if degraded and susp_d < threshold and ben_d < threshold:
        return "request_info", max(susp_d, ben_d, floor)
    if susp_d >= threshold:
        return "escalate_str", susp_d
    if ben_d >= threshold and not degraded:
        return "close_benign", ben_d
    return "request_info", max(susp_d, ben_d, floor)
