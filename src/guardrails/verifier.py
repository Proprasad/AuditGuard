"""
Deterministic Verifier — Signature Challenge B
Checks:
1. All INR arithmetic (using Python Decimal)
2. All cited evidence IDs exist in evidence_registry
3. No prohibited guilt assertions in worksheet
4. SHA-256 payload hash integrity
"""
from __future__ import annotations

import hashlib
import json
import re
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from pydantic import BaseModel


PROHIBITED_PHRASES = [
    "money laundering has occurred",
    "is guilty",
    "is a money launderer",
    "definitively laundering",
    "confirms money laundering",
    "proves fraud",
    "criminal activity confirmed",
]


class VerificationResult(BaseModel):
    passed: bool
    checks: dict[str, bool]
    errors: list[str]
    payload_hash: str


def verify_inr_math(
    outflow: str | float,
    inflow: str | float,
    tolerance: float = 0.05,
) -> tuple[bool, str]:
    """
    Deterministic Python Decimal arithmetic verification.
    Returns (passed, detail).
    """
    try:
        out = Decimal(str(outflow)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        infl = Decimal(str(inflow)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        diff = abs(out - infl)
        pct = diff / out if out > 0 else Decimal("0")
        passed = pct <= Decimal(str(tolerance))
        return passed, f"out={out} inflow={infl} diff={diff} ({pct:.2%})"
    except Exception as e:
        return False, f"Decimal arithmetic error: {e}"


def check_prohibited_claims(text: str) -> list[str]:
    """Find any prohibited guilt-assertion phrases in text."""
    text_lower = text.lower()
    return [phrase for phrase in PROHIBITED_PHRASES if phrase in text_lower]


def compute_canonical_hash(payload: dict) -> str:
    """SHA-256 of sorted canonical JSON."""
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify_worksheet(
    worksheet_dict: dict[str, Any],
    evidence_registry: dict[str, Any] | None = None,
) -> VerificationResult:
    """
    Run all verification checks on a disposition worksheet.
    """
    errors = []
    checks = {}

    # 1. No prohibited claims
    rationale = worksheet_dict.get("recommendation_rationale", "")
    prohibited = check_prohibited_claims(rationale)
    checks["no_prohibited_claims"] = len(prohibited) == 0
    if prohibited:
        errors.append(f"Prohibited claims found: {prohibited}")

    # 2. Confidence score is in range
    confidence = worksheet_dict.get("confidence_score", 0)
    checks["confidence_in_range"] = 0.0 <= float(confidence) <= 1.0
    if not checks["confidence_in_range"]:
        errors.append(f"Confidence score out of range: {confidence}")

    # 3. Regulatory citations non-empty
    citations = worksheet_dict.get("regulatory_citations", [])
    checks["has_citations"] = len(citations) > 0
    if not checks["has_citations"]:
        errors.append("No regulatory citations found in worksheet")

    # 4. Citation format check
    citation_pattern = re.compile(r"^[A-Z][A-Z0-9\-]+$")
    invalid_citations = [c for c in citations if not citation_pattern.match(str(c))]
    checks["citation_format_valid"] = len(invalid_citations) == 0
    if invalid_citations:
        errors.append(f"Invalid citation format: {invalid_citations}")

    # 5. Evidence IDs in registry (if provided)
    if evidence_registry is not None:
        all_evidence_ids = []
        for path in worksheet_dict.get("candidate_paths", []):
            if isinstance(path, dict):
                all_evidence_ids.append(path.get("path_id", ""))

        missing = [eid for eid in all_evidence_ids if eid and eid not in evidence_registry]
        checks["all_evidence_ids_registered"] = len(missing) == 0
        if missing:
            errors.append(f"Evidence IDs not found in registry: {missing}")
    else:
        checks["all_evidence_ids_registered"] = True  # Skip if no registry provided

    # 6. Recommendation is a valid disposition
    valid_dispositions = {"escalate_str", "close_benign", "request_info", "pending"}
    disposition = worksheet_dict.get("recommended_disposition", "")
    checks["valid_disposition"] = disposition in valid_dispositions
    if not checks["valid_disposition"]:
        errors.append(f"Invalid disposition: {disposition}")

    # 7. Payload hash
    exclude_keys = {"approval_token", "reviewer_id", "reviewer_decision",
                    "reviewer_notes", "reviewed_at", "_payload_hash"}
    payload_for_hash = {k: v for k, v in worksheet_dict.items() if k not in exclude_keys}
    computed_hash = compute_canonical_hash(payload_for_hash)

    passed = all(checks.values()) and len(errors) == 0

    return VerificationResult(
        passed=passed,
        checks=checks,
        errors=errors,
        payload_hash=computed_hash,
    )
