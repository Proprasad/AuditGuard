"""
Canonical serialisation, hashing and exact-number helpers.

Pure and framework-free: no FastAPI, FastMCP or LLM SDK imports are allowed in `src/core/`.

Rules enforced here for the whole code-base:
  * Currency / ratios are `decimal.Decimal`, created only from `str`, `int` or `Decimal`
    (binary `float` input is rejected with `NumericError`).
  * Money is quantised to 0.01 (ROUND_HALF_UP); ratios to 0.0001; USD cost to 0.000001.
  * There is exactly ONE canonical JSON serialiser and ONE SHA-256 hasher (`canonical_sha256`).
    Decimals serialise as fixed-point strings (never scientific notation), datetimes as UTC ISO-8601,
    sets as sorted lists, keys sorted.
"""

from __future__ import annotations

import enum
import hashlib
import json
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Annotated, Any

from pydantic import BeforeValidator, PlainSerializer

CENT = Decimal("0.01")
RATIO_Q = Decimal("0.0001")
USD_Q = Decimal("0.000001")


class NumericError(ValueError):
    """Raised for float / malformed numeric input where exact decimals are required."""


class TimestampError(ValueError):
    """Raised for malformed timestamps (never silently replaced by 'now')."""


def to_decimal(value: Any, quantum: Decimal = CENT) -> Decimal:
    """Convert `str | int | Decimal` to a quantised Decimal. Binary floats are rejected."""
    if isinstance(value, (bool, float)):
        raise NumericError(f"binary float/bool not accepted for exact decimal field: {value!r}")
    try:
        if isinstance(value, Decimal):
            dec = value
        elif isinstance(value, int):
            dec = Decimal(value)
        elif isinstance(value, str):
            dec = Decimal(value.strip())
        else:
            raise NumericError(f"unsupported numeric type {type(value).__name__}")
    except InvalidOperation as exc:
        raise NumericError(f"malformed decimal literal: {value!r}") from exc
    if not dec.is_finite():
        raise NumericError(f"non-finite decimal: {value!r}")
    return dec.quantize(quantum, rounding=ROUND_HALF_UP)


def to_money(value: Any) -> Decimal:
    return to_decimal(value, CENT)


def to_ratio(value: Any) -> Decimal:
    return to_decimal(value, RATIO_Q)


def to_usd(value: Any) -> Decimal:
    return to_decimal(value, USD_Q)


def dec_str(value: Decimal) -> str:
    """Fixed-point string (no exponent)."""
    return format(value, "f")


def _serialise_decimal(value: Decimal) -> str:
    return dec_str(value)


# Pydantic field types: validate from str/int/Decimal only; serialise to fixed-point strings in JSON mode.
Money = Annotated[
    Decimal,
    BeforeValidator(to_money),
    PlainSerializer(_serialise_decimal, return_type=str, when_used="json"),
]
Ratio = Annotated[
    Decimal,
    BeforeValidator(to_ratio),
    PlainSerializer(_serialise_decimal, return_type=str, when_used="json"),
]
Usd = Annotated[
    Decimal,
    BeforeValidator(to_usd),
    PlainSerializer(_serialise_decimal, return_type=str, when_used="json"),
]


def parse_utc_timestamp(value: Any) -> datetime:
    """Parse ISO-8601 into a timezone-aware UTC datetime; naive inputs are interpreted as UTC."""
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise TimestampError(f"malformed timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _default(obj: Any) -> Any:
    if isinstance(obj, Decimal):
        return dec_str(obj)
    if isinstance(obj, datetime):
        return parse_utc_timestamp(obj).isoformat()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    if isinstance(obj, enum.Enum):
        return obj.value
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="python")
    raise TypeError(f"not canonically serialisable: {type(obj).__name__}")


def canonical_json(payload: Any) -> str:
    """The one canonical JSON form used for every hash in the system."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=_default, ensure_ascii=True)


def canonical_sha256(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def dumps_json(payload: Any) -> str:
    """Storage JSON (Decimal -> exact string, datetime -> UTC ISO)."""
    return json.dumps(payload, default=_default)


def loads_json(text: str) -> Any:
    """Load JSON keeping every non-integer number an exact Decimal (never a binary float)."""
    return json.loads(text, parse_float=Decimal)
