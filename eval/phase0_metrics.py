"""
Backward-compatible re-exports delegating to `eval/metrics.py` (`Phase 5` canonical metric definitions).
"""

from __future__ import annotations

from eval.metrics import (
    SUPPORTED_CASE_METRICS,
    SUPPORTED_RED_TEAM_METRICS,
    aggregate_mode_metrics as aggregate_repeat_metrics,
    cited_evidence_ids,
    compute_case_quality,
    gold_evidence_ids,
    validate_requested_metrics,
)

__all__ = [
    "SUPPORTED_CASE_METRICS",
    "SUPPORTED_RED_TEAM_METRICS",
    "aggregate_repeat_metrics",
    "cited_evidence_ids",
    "compute_case_quality",
    "gold_evidence_ids",
    "validate_requested_metrics",
]
