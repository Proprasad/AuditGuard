"""
Deterministic, FAIL-CLOSED verifier core (pure).

Checks every worksheet against the run's `evidence_registry`:
  * guilt-assertion families (normalised) across ALL narrative fields
  * every cited / referenced evidence ID (TXN-, KYC-, CALC-, PATH-, REGISTRY-, REG-, SOP-) must resolve
  * all INR math recomputed in `Decimal` (path net / retention / registry cross-check / narrative figures)
  * canonical SHA-256 payload hash
`evidence_registry=None` is itself a failure. Failures carry structured discrepancies used as critique feedback.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict

from src.core.canonical import CENT, NumericError, canonical_sha256, to_decimal, to_money

DEFAULT_CONSERVATION_TOLERANCE = Decimal("0.05")

# Back-compat literal list (also screened) + normalised regex families.
PROHIBITED_PHRASES = [
    "money laundering has occurred",
    "is guilty",
    "is a money launderer",
    "definitively laundering",
    "confirms money laundering",
    "proves fraud",
    "criminal activity confirmed",
]
_GUILT_FAMILIES = [
    re.compile(
        r"money laundering (?:has |have )?(?:been )?(?:occurred|"
        r"confirmed|proven|proved|established|committed)"
    ),
    re.compile(
        r"\b(?:laundering|fraud|offen[cs]e) (?:is|was|has been|have been) "
        r"(?:confirmed|proven|proved|established|committed|occurred)"
    ),
    re.compile(r"\b(?:confirmed|proven|definitive|undeniable) (?:money )?laundering\b"),
    re.compile(r"\b(?:is|are|was|were) (?:a |an )?(?:guilty|criminal|money launderers?|launderers?|fraudsters?)\b"),
    re.compile(r"\bguilty of\b"),
    re.compile(r"\b(?:customer|account holder|accused|subject|entity|he|she|they) (?:has |have )?launder(?:ed|s)\b"),
    re.compile(r"\blaundered (?:the |these )?(?:funds|money|proceeds)\b"),
    re.compile(
        r"\bcriminal (?:intent|activity|conduct) (?:is |"
        r"was |has been )?(?:confirmed|proven|proved|established)\b"
    ),
    re.compile(
        r"\bconfirms? (?:the )?(?:money )?laundering\b|"
        r"\bproves? (?:the )?(?:money laundering|fraud)\b|\bdefinitive(?:ly)? launder"
    ),
]

_REF_PATTERN = re.compile(r"\b(?:TXN|KYC|CALC|PATH|REGISTRY|REG|SOP)-[A-Za-z0-9][A-Za-z0-9\-_]*")
_AMOUNT_PATTERN = re.compile(r"(?:INR|₹|Rs\.?)\s*([0-9][0-9,]*(?:\.[0-9]+)?)")
_SUFFIX_AMOUNT_PATTERN = re.compile(
    r"\b([0-9][0-9,]*(?:\.[0-9]+)?)\s*(rupees?|rs\.?|inr|lakhs?|lacs?|crores?)\b",
    re.IGNORECASE,
)
_UNIT_MULTIPLIERS = {
    "lakh": Decimal("100000"),
    "lakhs": Decimal("100000"),
    "lac": Decimal("100000"),
    "lacs": Decimal("100000"),
    "crore": Decimal("10000000"),
    "crores": Decimal("10000000"),
}
_CITATION_FORMAT = re.compile(r"^[A-Z][A-Z0-9\-]+$")
_VALID_DISPOSITIONS = {"escalate_str", "close_benign", "request_info", "pending"}
_HASH_EXCLUDED = {
    "approval_token",
    "reviewer_id",
    "reviewer_decision",
    "reviewer_notes",
    "reviewed_at",
    "payload_hash",
    "_payload_hash",
}


class Discrepancy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    field: str
    detail: str


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: bool
    checks: dict[str, bool]
    errors: list[str]
    discrepancies: list[Discrepancy]
    payload_hash: str


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text).casefold())


def check_prohibited_claims(text: str) -> list[str]:
    """Return matched prohibited phrases/families (empty list = clean)."""
    norm = _normalise(text)
    hits = [phrase for phrase in PROHIBITED_PHRASES if phrase in norm]
    hits += [p.pattern for p in _GUILT_FAMILIES if p.search(norm)]
    return hits


def verify_inr_math(
    outflow: str | Decimal | int,
    inflow: str | Decimal | int,
    tolerance: str | Decimal = DEFAULT_CONSERVATION_TOLERANCE,
) -> tuple[bool, str]:
    """Exact Decimal conservation check: |out - in| / out <= tolerance."""
    try:
        out, infl = to_money(outflow), to_money(inflow)
        tol = to_decimal(tolerance, Decimal("0.0001"))
    except NumericError as exc:
        return False, f"Decimal arithmetic error: {exc}"
    diff = abs(out - infl)
    pct = diff / out if out > 0 else Decimal("0")
    return pct <= tol, f"out={out} inflow={infl} diff={diff} ({pct:.2%})"


def compute_canonical_hash(payload: Mapping[str, Any]) -> str:
    return canonical_sha256({k: v for k, v in payload.items() if k not in _HASH_EXCLUDED})


# ------------------------------------------------------------------------------------------------
def _narrative_fields(ws: Mapping[str, Any]) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = [
        ("recommendation_rationale", str(ws.get("recommendation_rationale", ""))),
        ("analyst_notes", str(ws.get("analyst_notes", ""))),
    ]
    fields += [(f"kyc_summaries[{i}]", str(s)) for i, s in enumerate(ws.get("kyc_summaries", []))]
    for i, hyp in enumerate(ws.get("hypotheses", [])):
        if not isinstance(hyp, Mapping):
            continue
        fields.append((f"hypotheses[{i}].explanation", str(hyp.get("explanation", ""))))
        for key in ("supporting_evidence", "contradicting_evidence"):
            fields += [(f"hypotheses[{i}].{key}", str(e)) for e in hyp.get(key, [])]
    return [(name, text) for name, text in fields if text]


def _as_money(value: Any) -> Decimal | None:
    try:
        return to_money(value)
    except NumericError:
        return None


def _path_totals(ws: Mapping[str, Any]) -> set[Decimal]:
    """Every per-path amount plus the sums across paths (the only figures a narrative may quote from graph results)."""
    known: set[Decimal] = set()
    series: dict[str, list[Decimal]] = {"total_outflow_inr": [], "total_consolidated_inr": [], "net_difference_inr": []}
    for path in ws.get("candidate_paths", []):
        for key, acc in series.items():
            if (m := _as_money(path.get(key))) is not None:
                known.add(m)
                acc.append(m)
    known.update(sum(values, Decimal("0.00")) for values in series.values() if values)
    return known


def _known_amounts(ws: Mapping[str, Any], registry: Mapping[str, Any]) -> set[Decimal]:
    known = _path_totals(ws)
    if (alert_amount := _as_money(ws.get("alert_amount_inr"))) is not None:
        known.add(alert_amount)
    for item in registry.values():
        if isinstance(item, Mapping):
            known.update(
                m
                for key, value in item.items()
                if "inr" in key or "amount" in key
                if (m := _as_money(value)) is not None
            )
    return known


def _check_paths(ws: Mapping[str, Any], registry: Mapping[str, Any], out: list[Discrepancy]) -> bool:
    ok = True
    for i, path in enumerate(ws.get("candidate_paths", [])):
        pid = str(path.get("path_id", ""))
        field = f"candidate_paths[{i}]"
        try:
            outflow, cons = to_money(path["total_outflow_inr"]), to_money(path["total_consolidated_inr"])
            net, retention = to_money(path["net_difference_inr"]), to_money(path["retention_pct"])
        except (KeyError, NumericError) as exc:
            out.append(Discrepancy(code="MALFORMED_PATH_AMOUNTS", field=field, detail=str(exc)))
            ok = False
            continue
        if net != (outflow - cons).quantize(CENT):
            out.append(
                Discrepancy(
                    code="INR_NET_MISMATCH", field=field, detail=f"net {net} != outflow {outflow} - consolidated {cons}"
                )
            )
            ok = False
        expected_ret = (net / outflow * 100).quantize(CENT) if outflow > 0 else Decimal("0.00")
        if retention != expected_ret:
            out.append(
                Discrepancy(
                    code="INR_RETENTION_MISMATCH",
                    field=field,
                    detail=f"retention {retention}% != recomputed {expected_ret}%",
                )
            )
            ok = False
        reg_path = registry.get(pid)
        if not isinstance(reg_path, Mapping):
            out.append(
                Discrepancy(code="UNRESOLVED_EVIDENCE_ID", field=field, detail=f"path {pid!r} not in evidence_registry")
            )
            ok = False
            continue
        for label, stated, key in (
            ("outflow", outflow, "total_outflow_inr"),
            ("consolidated", cons, "total_consolidated_inr"),
        ):
            same, detail = verify_inr_math(stated, reg_path.get(key, "0"), tolerance="0")
            if not same:
                out.append(Discrepancy(code="INR_REGISTRY_MISMATCH", field=field, detail=f"{label}: {detail}"))
                ok = False
    return ok


def _referenced_ids(ws: Mapping[str, Any]) -> Iterable[tuple[str, str]]:
    for name, text in _narrative_fields(ws):
        for ref in _REF_PATTERN.findall(text):
            yield name, ref.rstrip("-_.")
    for i, hyp in enumerate(ws.get("hypotheses", [])):
        if isinstance(hyp, Mapping):
            for ref in [*hyp.get("evidence_ids", []), *hyp.get("regulatory_citations", [])]:
                yield f"hypotheses[{i}]", str(ref)


_FailFn = Callable[[str, str, str, str], None]


def _check_citations(ws: Mapping[str, Any], registry: Mapping[str, Any], disposition: Any, fail: _FailFn) -> None:
    citations = list(ws.get("regulatory_citations", []))
    if not citations and not (bool(ws.get("degraded_evidence")) and disposition == "request_info"):
        fail("has_citations", "NO_CITATIONS", "regulatory_citations", "at least one resolvable citation is required")
    for cite in citations:
        if not _CITATION_FORMAT.match(str(cite)):
            fail("citation_format_valid", "BAD_CITATION_FORMAT", "regulatory_citations", str(cite))
        elif cite not in registry:
            fail(
                "citations_resolved",
                "UNRESOLVED_CITATION",
                "regulatory_citations",
                f"{cite!r} not in evidence_registry",
            )


def _extract_prose_amounts(text: str) -> list[tuple[str, Decimal | None]]:
    found: list[tuple[str, Decimal | None]] = []
    for raw in _AMOUNT_PATTERN.findall(text):
        found.append((f"INR {raw}", _as_money(raw.replace(",", ""))))
    for raw_num, unit in _SUFFIX_AMOUNT_PATTERN.findall(text):
        cleaned = raw_num.replace(",", "")
        mult = _UNIT_MULTIPLIERS.get(unit.lower().rstrip("."), Decimal("1"))
        try:
            scaled = to_money(to_decimal(cleaned, Decimal("0.0001")) * mult)
        except NumericError:
            scaled = None
        found.append((f"{raw_num} {unit}", scaled))
    return found


def _check_narrative_amounts(ws: Mapping[str, Any], registry: Mapping[str, Any], fail: _FailFn) -> None:
    known = _known_amounts(ws, registry)
    for name, text in _narrative_fields(ws):
        for label, amount in _extract_prose_amounts(text):
            if amount is None or amount not in known:
                fail(
                    "narrative_amounts_grounded",
                    "UNGROUNDED_AMOUNT",
                    name,
                    f"{label} does not match any verified amount",
                )


def verify_worksheet(
    worksheet: Mapping[str, Any], evidence_registry: Mapping[str, Any] | None = None
) -> VerificationResult:
    issues: list[Discrepancy] = []
    checks: dict[str, bool] = {}

    def fail(check: str, code: str, field: str, detail: str) -> None:
        checks[check] = False
        issues.append(Discrepancy(code=code, field=field, detail=detail))

    registry: Mapping[str, Any] = evidence_registry if evidence_registry is not None else {}
    checks["evidence_registry_present"] = evidence_registry is not None
    if evidence_registry is None:
        fail(
            "evidence_registry_present",
            "EVIDENCE_REGISTRY_MISSING",
            "evidence_registry",
            "verification requires the run's evidence registry",
        )

    for name, text in _narrative_fields(worksheet):
        if hits := check_prohibited_claims(text):
            fail("no_prohibited_claims", "PROHIBITED_CLAIM", name, f"guilt assertion matched: {hits}")
    checks.setdefault("no_prohibited_claims", True)

    try:
        conf_ok = 0.0 <= float(worksheet.get("confidence_score", 0)) <= 1.0
    except (TypeError, ValueError):
        conf_ok = False
    checks["confidence_in_range"] = conf_ok
    if not conf_ok:
        fail(
            "confidence_in_range", "CONFIDENCE_OUT_OF_RANGE", "confidence_score", str(worksheet.get("confidence_score"))
        )

    disposition = worksheet.get("recommended_disposition", "")
    if disposition not in _VALID_DISPOSITIONS:
        fail("valid_disposition", "INVALID_DISPOSITION", "recommended_disposition", str(disposition))
    checks.setdefault("valid_disposition", True)

    _check_citations(worksheet, registry, disposition, fail)
    for name in ("has_citations", "citation_format_valid", "citations_resolved"):
        checks.setdefault(name, True)

    for field, ref in _referenced_ids(worksheet):
        if ref not in registry:
            fail(
                "evidence_ids_resolved", "UNRESOLVED_EVIDENCE_ID", field, f"{ref!r} not in this run's evidence_registry"
            )
    checks.setdefault("evidence_ids_resolved", True)

    path_issues: list[Discrepancy] = []
    checks["inr_math_verified"] = _check_paths(worksheet, registry, path_issues)
    issues += path_issues

    _check_narrative_amounts(worksheet, registry, fail)
    checks.setdefault("narrative_amounts_grounded", True)

    return VerificationResult(
        passed=all(checks.values()) and not issues,
        checks=checks,
        errors=[f"{d.code}: {d.field}: {d.detail}" for d in issues],
        discrepancies=issues,
        payload_hash=compute_canonical_hash(worksheet),
    )
