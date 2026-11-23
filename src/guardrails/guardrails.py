"""
Input/Output Guardrails - AuditGuard Security Layer
- PII masking (synthetic PAN / account / phone / Aadhaar / GSTIN)
- Unicode-normalised prompt-injection detection (NFKC, case-fold, zero-width strip, confusable fold)
- Untrusted-data containment: payloads are XML-escaped so `</untrusted_data>` breakout is impossible
- Output screening for guilt assertions (shared normalised families from `src.core.verifier`)
"""

from __future__ import annotations

import html
import re
import unicodedata

from pydantic import BaseModel

PII_PATTERNS = {
    "pan": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "account_number": re.compile(r"\b\d{9,18}\b"),
    "phone": re.compile(r"\b[6-9]\d{9}\b"),
    "aadhaar": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    "gstin": re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b"),
}

_ZERO_WIDTH = {ord(c): None for c in "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e"}
# Common Cyrillic / Greek look-alikes folded to Latin so homoglyph evasion does not bypass detection.
_CONFUSABLES = {
    ord(k): v
    for k, v in {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ѕ": "s",
        "ј": "j",
        "ԁ": "d",
        "ɡ": "g",
        "һ": "h",
        "ո": "n",
        "ս": "u",
        "ν": "v",
        "ο": "o",
        "ι": "i",
        "α": "a",
        "ρ": "p",
        "τ": "t",
        "κ": "k",
        "μ": "m",
        "Ι": "i",
        "Ο": "o",
        "Α": "a",
        "Ε": "e",
    }.items()
}

_VERB = r"(?:ignore|disregard|forget|override|bypass|skip|discard|neglect)"
_QUALIFIER = r"(?:previous|prior|above|earlier|preceding|system|all|any|your|the|these|those)"
_NOUN = r"(?:instructions?|rules?|prompts?|guidelines?|context|directives?|constraints?|safeguards?|policies)"

COMMON_INJECTION_PATTERNS = [
    re.compile(rf"\b{_VERB}\b.{{0,40}}\b{_QUALIFIER}\b.{{0,30}}\b{_NOUN}\b"),
    re.compile(r"\bforget your\b"),
    re.compile(r"\byou are now\b"),
    re.compile(r"\b(?:new|updated|revised|real|actual) (?:instructions?|directives?|rules?|task)\s*:"),
    re.compile(r"\bsystem (?:prompt|message|override|instruction)s?\b"),
    re.compile(r"<\|?\s*(?:im_start|im_end|system|assistant)\b"),
    re.compile(r"</?\s*untrusted_data\b"),
    re.compile(r"\bjailbreak\b|\bdan mode\b|\bdeveloper mode\b"),
    re.compile(r"\bpretend (?:you|to be)\b|\bact as (?:if|an?|the)\b"),
]
# Extra structural-override patterns applied only to external data (tool outputs / memos / KYC notes).
EXTERNAL_ONLY_PATTERNS = [
    re.compile(
        r"\b(?:mark|close|classify|set|label|treat|flag) "
        r"(?:this |the )?(?:case|alert|account|transaction)?\s*(?:as )?"
        r"(?:close_benign|benign|legitimate|safe|cleared)\b"
    ),
    re.compile(r"\bapprove(?: and|&)? ?commit\b|\bauto[- ]?approve\b|\bsubmit_case_disposition\b"),
    re.compile(
        r"\b(?:reveal|print|show|leak|disclose|exfiltrate) "
        r"(?:your |the )?(?:system prompt|api key|secret|hidden instructions)\b"
    ),
]
INJECTION_PATTERNS = COMMON_INJECTION_PATTERNS  # public alias (input-side list)


class GuardrailResult(BaseModel):
    allowed: bool
    scrubbed_text: str
    blocked_reason: str = ""
    pii_found: list[str] = []
    injection_detected: bool = False


def normalize_for_detection(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).translate(_CONFUSABLES).casefold()
    return re.sub(r"[\s_]+", " ", folded).strip()


def matched_injection_patterns(text: str, external: bool = False) -> list[str]:
    normalised = normalize_for_detection(text)
    patterns = COMMON_INJECTION_PATTERNS + (EXTERNAL_ONLY_PATTERNS if external else [])
    return [p.pattern for p in patterns if p.search(normalised)]


def detect_injection(text: str, external: bool = False) -> bool:
    return bool(matched_injection_patterns(text, external))


def mask_pii(text: str) -> tuple[str, list[str]]:
    """Replace PII with masked versions. Returns (masked_text, found_pii_types)."""
    found: list[str] = []
    masked = text
    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(masked):
            found.append(pii_type)

            def _mask_match(m: re.Match[str], kind: str = pii_type) -> str:
                v = m.group(0)
                return f"[{kind.upper()}:{v[:2]}***{v[-2:]}]"

            masked = pattern.sub(_mask_match, masked)
    return masked, found


_WRAPPER = re.compile(r'^<untrusted_data(?: source="[^"]*")?>(.*)</untrusted_data>$', re.DOTALL)


def wrap_untrusted_data(value: str, source_id: str = "unknown") -> str:
    """XML-escape (`&`, `<`, `>`) the payload and wrap it so containment cannot be broken from inside."""
    safe_source = re.sub(r"[^A-Za-z0-9_.:\-]", "_", source_id)[:80] or "unknown"
    return f'<untrusted_data source="{safe_source}">{html.escape(value, quote=False)}</untrusted_data>'


def unwrap_untrusted_data(value: str) -> str:
    """Inverse of `wrap_untrusted_data` (for passing a plain identifier back into a parameterised tool call)."""
    match = _WRAPPER.match(value)
    return html.unescape(match.group(1)) if match else value


def tag_untrusted(text: str, source_id: str = "unknown") -> str:
    return wrap_untrusted_data(text, source_id)


def apply_input_guardrails(text: str, is_external_data: bool = False) -> GuardrailResult:
    if detect_injection(text, external=is_external_data):
        return GuardrailResult(
            allowed=False,
            scrubbed_text="[BLOCKED: Prompt injection detected]",
            blocked_reason="prompt_injection_detected",
            injection_detected=True,
        )
    scrubbed, pii_found = mask_pii(text)
    if is_external_data:
        scrubbed = wrap_untrusted_data(scrubbed, "external_input")
    return GuardrailResult(allowed=True, scrubbed_text=scrubbed, pii_found=pii_found)


def apply_output_guardrails(text: str) -> GuardrailResult:
    from src.core.verifier import check_prohibited_claims

    scrubbed, pii_found = mask_pii(text)
    prohibited = check_prohibited_claims(scrubbed)
    if prohibited:
        return GuardrailResult(
            allowed=False,
            scrubbed_text="[BLOCKED: Output contains prohibited guilt assertions]",
            blocked_reason=f"prohibited_claims: {prohibited}",
            pii_found=pii_found,
        )
    return GuardrailResult(allowed=True, scrubbed_text=scrubbed, pii_found=pii_found)
