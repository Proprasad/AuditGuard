"""
Input/Output Guardrails - AuditGuard Security Layer (`src/guardrails/guardrails.py`).
- Extended PII masking: case-insensitive PAN & GSTIN, `+91`/`0091`/hyphenated phones, email, Aadhaar, account numbers
- Unicode-normalised prompt-injection detection (NFKC, case-fold, zero-width strip, homoglyph fold,
  dot/dash de-splitting, targeted leetspeak fold, paraphrase & Hinglish/multilingual override patterns)
- False-positive hardened against benign banking phrases ("You are now registered...", "Jailbreak Fitness Studio")
- Untrusted-data containment: payloads are XML-escaped so `</untrusted_data>` breakout is impossible
- Output screening for guilt assertions (shared normalised families from `src.core.verifier`)
"""

from __future__ import annotations

import html
import re
import unicodedata

from pydantic import BaseModel, ConfigDict

# Ordered from most-specific structured tokens down to generic digit runs so phones/Aadhaar/PAN/email
# are masked with their exact PII class before `account_number`.
PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "gstin": re.compile(r"\b\d{2}[A-Za-z]{5}\d{4}[A-Za-z][1-9A-Za-z][Zz][0-9A-Za-z]\b"),
    "pan": re.compile(r"\b[A-Za-z]{5}[0-9]{4}[A-Za-z]\b"),
    "aadhaar": re.compile(r"\b\d{4}[-\s]\d{4}[-\s]\d{4}\b|\b\d{12}\b"),
    "phone": re.compile(r"(?:(?:\+91|0091)[\s\-]?)?(?<![0-9])[6-9]\d{4}[\s\-]?\d{5}(?![0-9])"),
    "account_number": re.compile(r"\b\d{9,18}\b"),
}

_ZERO_WIDTH = {
    ord(c): None
    for c in "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e\u034f\u202a\u202b\u202c\u202d\u202e"
}
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
_SPLIT_CHARS_RE = re.compile(r"\b([a-z])(?:[.\-*~`'|/\\]([a-z])){3,}\b")
_LEET_WORDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b1gn0r[3e]\b|\bign0r[3e]\b|\b1gnore\b"), "ignore"),
    (re.compile(r"\bd1sr[3e]g[4a]rd\b"), "disregard"),
    (re.compile(r"\b0v[3e]rr[1i]d[3e]\b"), "override"),
    (re.compile(r"\bbyp[4a]ss\b|\bbyp@ss\b"), "bypass"),
    (re.compile(r"\bf0rg[3e]t\b"), "forget"),
    (re.compile(r"\bsyst[3e]m\b"), "system"),
    (re.compile(r"\bpr0mpt\b"), "prompt"),
    (re.compile(r"\bj[4a][1i]lbr[3e][4a]k\b"), "jailbreak"),
    (re.compile(r"\b1nstruct[1i]0ns?\b"), "instructions"),
)

_VERB = r"(?:ignore|disregard|forget|override|bypass|skip|discard|neglect|set aside|abandon)"
_QUALIFIER = r"(?:previous|prior|above|earlier|preceding|system|all|any|your|the|these|those|every)"
_NOUN = (
    r"(?:instructions?|rules?|prompts?|guidelines?|context|directives?|constraints?|"
    r"safeguards?|policies|checks?|thresholds?|verification)"
)

COMMON_INJECTION_PATTERNS = [
    re.compile(rf"\b{_VERB}\b.{{0,45}}\b{_QUALIFIER}\b.{{0,35}}\b{_NOUN}\b"),
    re.compile(rf"\b{_VERB}\b\s+(?:everything|anything)\s+(?:above|before|prior)\b"),
    re.compile(r"\b(?:do not|don't|never)\s+follow\s+(?:any\s+)?(?:prior|previous|system|above)\b"),
    re.compile(r"\bforget your (?:compliance|aml|system|prior|previous|instructions?|rules?|role)\b"),
    re.compile(
        r"\byou are now (?:in |an? |the )?"
        r"(?:dan|developer|unrestricted|unfiltered|god|admin|root|principal officer|"
        r"compliance head|rogue|free from|operating without)\b"
    ),
    re.compile(r"\b(?:new|updated|revised|real|actual|hidden) (?:instructions?|directives?|rules?|task)\s*:"),
    re.compile(r"\bsystem (?:prompt|message|override|instruction|directive)s?\b"),
    re.compile(r"<\|?\s*(?:im[\s_]?start|im[\s_]?end|system|assistant|endoftext)\b"),
    re.compile(r"(?:^|\s)(?:\[\s*system\s*\]|###\s*(?:system|instruction)\s*:|</?\s*system[\s_]?instruction\s*>)"),
    re.compile(r'"role"\s*:\s*"system"'),
    re.compile(r"</?\s*untrusted_data\b"),
    re.compile(
        r"\bjailbreak(?:ed|ing)?\s+(?:active|mode|prompt|override|this|the|all|aml|guardrails?|system|filter)\b"
        r"|\bdan mode\b|\bdeveloper mode\b"
    ),
    re.compile(r"\bpretend (?:you|to be|that)\b|\bact as (?:if|an?|the)\b"),
    # Multilingual & Hinglish override directives
    re.compile(
        r"\b(?:purane|pichle|saare|sabhi)\s+(?:nirdesh|niyam|rules?|instructions?)\s*"
        r"(?:bhool|hatao|ignore|chhod|band)\b"
    ),
    re.compile(r"पिछले\s*निर्देश|सभी\s*नियम\s*(?:भूल|अनदेखा)"),
    re.compile(r"\bignora(?:r)?\s+(?:todas\s+)?las\s+instrucciones\b|\bolvida\s+tus\s+reglas\b"),
    re.compile(r"\bignorez\s+(?:toutes\s+)?les\s+instructions\b|\boubliez\s+vos\s+(?:instructions|regles|règles)\b"),
    re.compile(
        r"\bignoriere\s+(?:alle\s+)?(?:vorherigen\s+)?anweisungen\b|\bvergiss\s+(?:alle\s+)?(?:regeln|anweisungen)\b"
    ),
]

# Extra structural-override patterns applied only to external data (tool outputs / memos / KYC notes).
EXTERNAL_ONLY_PATTERNS = [
    re.compile(
        r"\b(?:mark|close|classify|set|label|treat|flag|return|output|force)\s+"
        r"(?:this |the )?(?:case|alert|account|transaction|disposition|status)?\s*(?:as |to |= )?"
        r"(?:close_benign|benign|legitimate|safe|cleared|no_action)\b"
    ),
    re.compile(
        r"\b(?:do not|don't|never)\s+(?:escalate|file\s+str|flag\s+this|check\s+registry|run\s+verifier)\b"
        r"|\bskip\s+(?:graph|kyc|registry|str)\s+(?:verification|check|filing|scan)\b"
    ),
    re.compile(
        r"\b(?:case|alert)\s+ko\s+(?:benign|close|safe|approve)\s+(?:karo|mark\s+karo|kar\s+do)\b"
        r"|\bbina\s+janch\s+ke\s+approve\b"
    ),
    re.compile(
        r"\bapprove(?: and|&)? ?commit\b|\bauto[- ]?(?:approve|commit|close)\b"
        r"|\bsubmit_case_disposition\b|\bdraft_disposition_report\b"
    ),
    re.compile(
        r"\b(?:wipe|delete|drop|truncate)\s+(?:the\s+)?audit[\s_]?logs?\b"
        r"|\bdisable\s+(?:sha[- ]?256|guardrails?|rbac|verifier)\b"
    ),
    re.compile(
        r"\b(?:reveal|print|show|leak|disclose|exfiltrate|dump)\s+"
        r"(?:your |the )?(?:system prompt|api key|secret|hidden instructions|bearer token)\b"
    ),
]
INJECTION_PATTERNS = COMMON_INJECTION_PATTERNS  # public alias (input-side list)


class GuardrailResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    scrubbed_text: str
    blocked_reason: str = ""
    pii_found: list[str] = []
    injection_detected: bool = False


def normalize_for_detection(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).translate(_CONFUSABLES).casefold()
    desplit = _SPLIT_CHARS_RE.sub(lambda m: re.sub(r"[.\-*~`'|/\\]", "", m.group(0)), folded)
    collapsed = re.sub(r"[\s]+", " ", desplit).strip()
    for pat, repl in _LEET_WORDS:
        collapsed = pat.sub(repl, collapsed)
    return collapsed


def matched_injection_patterns(text: str, external: bool = False) -> list[str]:
    normalised = normalize_for_detection(text)
    patterns = COMMON_INJECTION_PATTERNS + (EXTERNAL_ONLY_PATTERNS if external else [])
    return [p.pattern for p in patterns if p.search(normalised)]


def detect_injection(text: str, external: bool = False) -> bool:
    return bool(matched_injection_patterns(text, external))


def mask_pii(text: str) -> tuple[str, list[str]]:
    """Replace PII with masked tokens (`[KIND:xx***yy]`). Returns `(masked_text, found_pii_types)`."""
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
