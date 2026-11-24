"""
Regex patterns, guilt-claim detection (with clause-scoped negation guard), corpus loader,
and prose INR / percentage extractors used by Verifier v2 (`src/core/verifier.py`).
"""

from __future__ import annotations

from decimal import Decimal
from functools import lru_cache
import json
from pathlib import Path
import re
import unicodedata

from src.core.canonical import CENT, NumericError, to_decimal, to_money

PROHIBITED_PHRASES = [
    "money laundering has occurred",
    "is guilty",
    "is a money launderer",
    "is a criminal",
    "has clearly laundered",
    "clearly laundered",
    "definitively laundering",
    "confirms money laundering",
    "proves fraud",
    "criminal activity confirmed",
]

_ADV = (
    r"(?:clearly|definitely|definitively|obviously|plainly|undoubtedly|"
    r"certainly|actively|blatantly|proven\s+to\s+have)\s+"
)
GUILT_FAMILIES = [
    re.compile(
        rf"money laundering (?:has |have |had )?(?:been )?(?:{_ADV})*"
        r"(?:occurred|confirmed|proven|proved|established|committed|perpetrated)"
    ),
    re.compile(
        rf"\b(?:laundering|fraud|offen[cs]e|crime) (?:is|was|has been|have been) (?:{_ADV})*"
        r"(?:confirmed|proven|proved|established|committed|occurred)"
    ),
    re.compile(r"\b(?:confirmed|proven|definitive|undeniable|established) (?:money )?laundering\b"),
    re.compile(
        rf"\b(?:is|are|was|were) (?:{_ADV})*(?:a |an )?"
        r"(?:guilty|criminals?|money launderers?|launderers?|fraudsters?|felons?)\b"
    ),
    re.compile(r"\bguilty of\b"),
    re.compile(rf"\b(?:has|have|had) (?:{_ADV})+launder(?:ed|s|ing)?\b"),
    re.compile(
        rf"\b(?:customer|account holder|accused|subject|entity|originator|beneficiary|he|she|they) "
        rf"(?:(?:has|have|had) )?(?:{_ADV})*launder(?:ed|s)\b"
    ),
    re.compile(rf"\b(?:{_ADV})*laundered (?:the |these |illicit |tainted )?(?:funds|money|proceeds)\b"),
    re.compile(
        rf"\b(?:commit(?:ted|s)|perpetrat(?:ed|es)) (?:{_ADV})*(?:money laundering|fraud|a crime|criminal)\b"
    ),
    re.compile(
        rf"\bcriminal (?:intent|activity|conduct|guilt) (?:is |was |has been )?(?:{_ADV})*"
        r"(?:confirmed|proven|proved|established)\b"
    ),
    re.compile(
        r"\bconfirms? (?:the )?(?:money )?laundering\b|"
        r"\bproves? (?:the )?(?:money laundering|fraud)\b|\bdefinitive(?:ly)? launder"
    ),
]
_NEGATION_CLAUSE_RE = re.compile(
    r"\b(?:no|not|never|without|cannot|neither|nor|does not|do not|did not|is not|are not)\b"
    r"(?:\s+\w+){0,14}\s*$"
)

REF_PATTERN = re.compile(
    r"\b(?:(?:TXN|KYC|CALC|PATH|REGISTRY|CP|REG|SOP)-[A-Za-z0-9][A-Za-z0-9\-_]*"
    r"|(?:PMLA|PMLR|CHIT)-[0-9]{4}-[A-Za-z0-9\-]+"
    r"|RBI-(?:KYC|PA)-[0-9]{4}-[A-Za-z0-9\-]+"
    r"|FIU-IND-RFI-[A-Za-z0-9\-]+"
    r"|FATF-R[0-9]+-[A-Za-z0-9\-]+)"
)
DATA_EVIDENCE_PATTERN = re.compile(r"\b(?:TXN|KYC|CALC|PATH|REGISTRY|CP)-[A-Za-z0-9][A-Za-z0-9\-_]*")
CLAUSE_ID_PREFIXES = ("REG-", "SOP-", "PMLA-", "PMLR-", "RBI-", "FIU-", "FATF-", "CHIT-")
CITATION_FORMAT = re.compile(r"^[A-Z][A-Z0-9\-]+$")

_PROSE_CURRENCY_RE = re.compile(
    r"(?:(INR|₹|Rs\.?)\s*([0-9][0-9,]*(?:\.[0-9]+)?)(?:\s*(lakhs?|lacs?|crores?|rupees?))?(?!\w))"
    r"|(?:(?<!\w)([0-9][0-9,]*(?:\.[0-9]+)?)\s*(rupees?|rs\.?|inr|lakhs?|lacs?|crores?)(?!\w))",
    re.IGNORECASE,
)
_PROSE_PCT_RE = re.compile(r"(?<![A-Za-z0-9_])([0-9]+(?:\.[0-9]+)?)\s*%")
_UNIT_MULTIPLIERS = {
    "lakh": Decimal("100000"),
    "lakhs": Decimal("100000"),
    "lac": Decimal("100000"),
    "lacs": Decimal("100000"),
    "crore": Decimal("10000000"),
    "crores": Decimal("10000000"),
}


@lru_cache
def load_corpus_category_map() -> dict[str, str]:
    """Load `{passage_id: category}` directly from `data/regulatory_corpus/indian_aml_corpus.jsonl`."""
    corpus_path = Path(__file__).resolve().parents[2] / "data" / "regulatory_corpus" / "indian_aml_corpus.jsonl"
    mapping: dict[str, str] = {}
    if not corpus_path.exists():
        return mapping
    for raw_line in corpus_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line:
            rec = json.loads(line)
            mapping[str(rec["passage_id"])] = str(rec.get("category", ""))
    return mapping


def normalise_for_guilt(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).casefold()
    folded = re.sub(r"[\-_/,;:()\[\]\"']+", " ", folded)
    return re.sub(r"\s+", " ", folded).strip()


def _is_negated_in_clause(raw_text: str, norm_text: str, start_idx: int) -> bool:
    prefix = norm_text[:start_idx]
    # Restrict negation scope to the current sentence boundary in original text (approximated by `.` / `!` / `?`)
    sentence_tail = prefix.rsplit(".", 1)[-1]
    _ = raw_text
    return bool(_NEGATION_CLAUSE_RE.search(sentence_tail))


def check_prohibited_claims(text: str) -> list[str]:
    """Return matched prohibited guilt phrases/families (empty list = clean)."""
    folded = unicodedata.normalize("NFKC", text).casefold()
    # Preserve `.` for sentence-scoped negation checks, collapse other punctuation
    norm = re.sub(r"[\-_/,;:()\[\]\"']+", " ", folded)
    norm = re.sub(r"\s+", " ", norm).strip()
    hits: list[str] = []
    for phrase in PROHIBITED_PHRASES:
        idx = norm.find(phrase)
        if idx != -1 and not _is_negated_in_clause(text, norm, idx):
            hits.append(phrase)
    for pat in GUILT_FAMILIES:
        for m in pat.finditer(norm):
            if not _is_negated_in_clause(text, norm, m.start()):
                hits.append(pat.pattern)
                break
    return hits


def as_pct(value: object) -> Decimal | None:
    raw = str(value).strip().rstrip("%").strip() if value is not None else ""
    if not raw:
        return None
    try:
        return to_decimal(raw, Decimal("0.0001")).quantize(CENT)
    except NumericError:
        return None


def extract_prose_amounts(text: str) -> list[tuple[str, Decimal | None]]:
    found: list[tuple[str, Decimal | None]] = []
    for m in _PROSE_CURRENCY_RE.finditer(text):
        prefix, p_num, p_unit, s_num, s_unit = m.groups()
        raw_num = p_num if p_num is not None else s_num
        unit = (p_unit or s_unit or "").lower().rstrip(".")
        mult = _UNIT_MULTIPLIERS.get(unit, Decimal("1"))
        try:
            scaled = to_money(to_decimal(raw_num.replace(",", ""), Decimal("0.0001")) * mult)
        except NumericError:
            scaled = None
        label = f"{prefix} {raw_num}".strip() if prefix else f"{raw_num} {s_unit}"
        if p_unit:
            label = f"{label} {p_unit}"
        found.append((label, scaled))
    return found


def extract_prose_percentages(text: str) -> list[tuple[str, Decimal | None]]:
    return [(f"{m.group(1)}%", as_pct(m.group(1))) for m in _PROSE_PCT_RE.finditer(text)]
