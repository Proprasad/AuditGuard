"""Backward-compatible import path; the Verifier v2 implementation lives in `src.core.verifier`."""

from src.core.verifier import (  # noqa: F401
    MONEY_TOLERANCE,
    PROHIBITED_PHRASES,
    Discrepancy,
    VerificationResult,
    check_prohibited_claims,
    compute_canonical_hash,
    extract_prose_amounts,
    extract_prose_percentages,
    load_corpus_category_map,
    verify_inr_math,
    verify_worksheet,
)
