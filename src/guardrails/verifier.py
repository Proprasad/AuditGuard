"""Backward-compatible import path; the implementation lives in `src.core.verifier`."""

from src.core.verifier import (  # noqa: F401
    PROHIBITED_PHRASES,
    VerificationResult,
    check_prohibited_claims,
    compute_canonical_hash,
    verify_inr_math,
    verify_worksheet,
)
