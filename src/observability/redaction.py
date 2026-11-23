"""
Log / telemetry redaction. Everything shipped to Loki (or any external sink) passes through `redact_for_logs`:
PII (PAN/phone/Aadhaar/GSTIN/long numbers), account identifiers, JWTs, approval tokens, API keys and
free-text analyst notes are masked or dropped. High-cardinality IDs are never used as metric labels.
"""

from __future__ import annotations

import re
from typing import Any

from src.guardrails.guardrails import mask_pii

REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = {
    "notes",
    "reviewer_notes",
    "analyst_notes",
    "recommendation_rationale",
    "rationale",
    "memo",
    "memo_text",
    "kyc_notes",
    "password",
    "token",
    "access_token",
    "approval_token",
    "hmac_token",
    "secret",
    "authorization",
    "api_key",
    "kyc_summaries",
    "entity_name",
    "full_name",
}
_ACCOUNT_ID = re.compile(r"\bACC-[A-Z0-9\-]+\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")
_APPROVAL = re.compile(r"\bAPPROVE:[A-Za-z0-9:\-_]+")
_API_KEY = re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}\b")


def _mask_account(match: re.Match[str]) -> str:
    value = match.group(0)
    return f"ACC-***{value[-4:]}"


def redact_text(text: str) -> str:
    out = _JWT.sub(REDACTED, text)
    out = _APPROVAL.sub(REDACTED, out)
    out = _API_KEY.sub(REDACTED, out)
    out = _ACCOUNT_ID.sub(_mask_account, out)
    masked, _ = mask_pii(out)
    return masked


def redact_for_logs(value: Any, key: str = "") -> Any:
    if key.lower() in _SENSITIVE_KEYS:
        return REDACTED
    if isinstance(value, dict):
        return {k: redact_for_logs(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_for_logs(v, key) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
