"""
Input/Output Guardrails — AuditGuard Security Layer
- PII masking (synthetic PAN/account digits)
- Prompt injection detection
- Output scrubbing
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# PII Patterns (India-specific synthetic data)
# ---------------------------------------------------------------------------
PII_PATTERNS = {
    "pan": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "account_number": re.compile(r"\b\d{9,18}\b"),
    "phone": re.compile(r"\b[6-9]\d{9}\b"),
    "aadhaar": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    "gstin": re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b"),
}

INJECTION_PATTERNS = [
    re.compile(r"ignore previous instructions", re.IGNORECASE),
    re.compile(r"you are now", re.IGNORECASE),
    re.compile(r"forget your", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"system prompt:", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN mode", re.IGNORECASE),
    re.compile(r"pretend you", re.IGNORECASE),
    re.compile(r"act as if", re.IGNORECASE),
    re.compile(r"override.*instructions", re.IGNORECASE),
]


class GuardrailResult(BaseModel):
    allowed: bool
    scrubbed_text: str
    blocked_reason: str = ""
    pii_found: list[str] = []
    injection_detected: bool = False


def mask_pii(text: str) -> tuple[str, list[str]]:
    """Replace PII with masked versions. Returns (masked_text, found_pii_types)."""
    found = []
    masked = text

    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(masked):
            found.append(pii_type)
            # Mask but preserve length hint
            def _mask_match(m):
                v = m.group(0)
                return f"[{pii_type.upper()}:{v[:2]}***{v[-2:]}]"
            masked = pattern.sub(_mask_match, masked)

    return masked, found


def detect_injection(text: str) -> bool:
    """Return True if any injection pattern is detected."""
    return any(pat.search(text) for pat in INJECTION_PATTERNS)


def tag_untrusted(text: str) -> str:
    """Wrap external data in <untrusted_data> tags."""
    return f"<untrusted_data>{text}</untrusted_data>"


def apply_input_guardrails(text: str, is_external_data: bool = False) -> GuardrailResult:
    """
    Apply input guardrails:
    1. PII masking
    2. Injection detection
    3. Untrusted data tagging (for transaction memos, KYC text)
    """
    # Injection check first
    if detect_injection(text):
        return GuardrailResult(
            allowed=False,
            scrubbed_text="[BLOCKED: Prompt injection detected]",
            blocked_reason="prompt_injection_detected",
            injection_detected=True,
        )

    # PII masking
    scrubbed, pii_found = mask_pii(text)

    # Tag external data
    if is_external_data:
        scrubbed = tag_untrusted(scrubbed)

    return GuardrailResult(
        allowed=True,
        scrubbed_text=scrubbed,
        pii_found=pii_found,
    )


def apply_output_guardrails(text: str) -> GuardrailResult:
    """
    Apply output guardrails:
    1. Remove any PII that may have leaked through
    2. Check for prohibited guilt assertions
    """
    from src.guardrails.verifier import PROHIBITED_PHRASES, check_prohibited_claims

    scrubbed, pii_found = mask_pii(text)

    prohibited = check_prohibited_claims(scrubbed)
    if prohibited:
        return GuardrailResult(
            allowed=False,
            scrubbed_text="[BLOCKED: Output contains prohibited guilt assertions]",
            blocked_reason=f"prohibited_claims: {prohibited}",
            pii_found=pii_found,
        )

    return GuardrailResult(
        allowed=True,
        scrubbed_text=scrubbed,
        pii_found=pii_found,
    )
