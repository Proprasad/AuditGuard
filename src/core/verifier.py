"""
Deterministic verifier core (pure): INR arithmetic, prohibited-claim screening, citation/evidence checks
and the canonical SHA-256 payload hash. `src/guardrails/verifier.py` re-exports this module.
"""
from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

from pydantic import BaseModel

from src.core.canonical import NumericError, canonical_sha256, to_decimal, to_money

PROHIBITED_PHRASES = [
    "money laundering has occurred",
    "is guilty",
    "is a money launderer",
    "definitively laundering",
    "confirms money laundering",
    "proves fraud",
    "criminal activity confirmed",
]

_REVIEW_FIELDS = {"approval_token", "reviewer_id", "reviewer_decision", "reviewer_notes", "reviewed_at", "payload_hash", "_payload_hash"}
_CITATION_PATTERN = re.compile(r"^[A-Z][A-Z0-9\-]+$")
_VALID_DISPOSITIONS = {"escalate_str", "close_benign", "request_info", "pending"}


class VerificationResult(BaseModel):
    passed: bool
    checks: dict[str, bool]
    errors: list[str]
    payload_hash: str


def verify_inr_math(outflow: str | Decimal | int, inflow: str | Decimal | int, tolerance: str | Decimal = "0.05") -> tuple[bool, str]:
    """Exact Decimal conservation check: |out - in| / out <= tolerance."""
    try:
        out = to_money(outflow)
        infl = to_money(inflow)
        tol = to_decimal(tolerance, Decimal("0.0001"))
    except NumericError as exc:
        return False, f"Decimal arithmetic error: {exc}"
    diff = abs(out - infl)
    pct = diff / out if out > 0 else Decimal("0")
    return pct <= tol, f"out={out} inflow={infl} diff={diff} ({pct:.2%})"


def check_prohibited_claims(text: str) -> list[str]:
    lowered = text.lower()
    return [phrase for phrase in PROHIBITED_PHRASES if phrase in lowered]


def compute_canonical_hash(payload: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON form (the only hash function used for worksheets)."""
    return canonical_sha256({k: v for k, v in payload.items() if k not in _REVIEW_FIELDS})


def verify_worksheet(worksheet: dict[str, Any], evidence_registry: dict[str, Any] | None = None) -> VerificationResult:
    errors: list[str] = []
    checks: dict[str, bool] = {}

    prohibited = check_prohibited_claims(str(worksheet.get("recommendation_rationale", "")))
    checks["no_prohibited_claims"] = not prohibited
    if prohibited:
        errors.append(f"Prohibited claims found: {prohibited}")

    confidence = worksheet.get("confidence_score", 0)
    checks["confidence_in_range"] = 0.0 <= float(confidence) <= 1.0
    if not checks["confidence_in_range"]:
        errors.append(f"Confidence score out of range: {confidence}")

    citations = worksheet.get("regulatory_citations", [])
    checks["has_citations"] = len(citations) > 0
    if not checks["has_citations"]:
        errors.append("No regulatory citations found in worksheet")

    invalid = [c for c in citations if not _CITATION_PATTERN.match(str(c))]
    checks["citation_format_valid"] = not invalid
    if invalid:
        errors.append(f"Invalid citation format: {invalid}")

    if evidence_registry is not None:
        ids = [p.get("path_id", "") for p in worksheet.get("candidate_paths", []) if isinstance(p, dict)]
        missing = [i for i in ids if i and i not in evidence_registry]
        checks["all_evidence_ids_registered"] = not missing
        if missing:
            errors.append(f"Evidence IDs not found in registry: {missing}")
    else:
        checks["all_evidence_ids_registered"] = True

    checks["valid_disposition"] = worksheet.get("recommended_disposition", "") in _VALID_DISPOSITIONS
    if not checks["valid_disposition"]:
        errors.append(f"Invalid disposition: {worksheet.get('recommended_disposition')}")

    return VerificationResult(
        passed=all(checks.values()) and not errors,
        checks=checks,
        errors=errors,
        payload_hash=compute_canonical_hash(worksheet),
    )
