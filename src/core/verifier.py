"""
Verifier v2 — Deterministic, FAIL-CLOSED Compliance Worksheet Verifier (`src/core/verifier.py`).

Checks every worksheet and records each as a named boolean in `VerificationResult.checks`:
  1. `numbers_match_calc`      : prose INR amounts, percentages, and path math match `calc_log`/tool outputs
                                 within ₹0.01 (`Decimal`); calls `verify_inr_math`; records `inr_error_count`
                                 and `inr_numbers_total`.
  2. `citations_exist`         : every cited clause ID exists in the regulatory corpus index (and `evidence_registry`).
  3. `citations_relevant`      : cited clause category belongs to the allowed set from `typology_registry`
                                 OR `judge_citation_relevant` (Phase 4); stores both signals separately.
  4. `evidence_ids_registered` : every `TXN-*/KYC-*/REGISTRY-*/CALC-*/PATH-*/CP-*` mentioned is in `evidence_registry`,
                                 and each material claim carries >= 1 registered ID.
  5. `no_guilt_claims`         : expanded phrase + normalized-whitespace/lemma matching (with negation guard).
  6. `both_hypotheses_present` & `missing_evidence_stated`.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from decimal import Decimal
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from src.core.canonical import CENT, NumericError, canonical_sha256, to_confidence, to_decimal, to_money
from src.core.verifier_patterns import (
    CITATION_FORMAT,
    CLAUSE_ID_PREFIXES,
    DATA_EVIDENCE_PATTERN,
    PROHIBITED_PHRASES,
    REF_PATTERN,
    as_pct,
    check_prohibited_claims,
    extract_prose_amounts,
    extract_prose_percentages,
    load_corpus_category_map,
)
from src.typology_registry import typology_registry

DEFAULT_CONSERVATION_TOLERANCE = Decimal("0.05")
MONEY_TOLERANCE = Decimal("0.01")
_VALID_DISPOSITIONS = {"escalate_str", "close_benign", "request_info", "pending"}
_MISSING_CUES = (
    "missing evidence",
    "degraded evidence",
    "unavailable",
    "not available",
    "insufficient_data",
    "out-of-network",
    "out-of-bank",
    "pending verification",
)
_HASH_EXCLUDED = {
    "approval_token",
    "reviewer_id",
    "reviewer_decision",
    "reviewer_notes",
    "reviewed_at",
    "payload_hash",
    "_payload_hash",
    "judge_citation_relevant",
    "enforce_verifier_gate",
}

__all__ = [
    "DEFAULT_CONSERVATION_TOLERANCE",
    "MONEY_TOLERANCE",
    "PROHIBITED_PHRASES",
    "Discrepancy",
    "VerificationResult",
    "check_prohibited_claims",
    "compute_canonical_hash",
    "extract_prose_amounts",
    "extract_prose_percentages",
    "load_corpus_category_map",
    "verify_inr_math",
    "verify_worksheet",
]


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
    inr_error_count: int = 0
    inr_numbers_total: int = 0
    deterministic_citation_relevant: bool = True
    judge_citation_relevant: Optional[bool] = None


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
    if out == 0:
        return infl == 0, f"out={out} inflow={infl} diff={diff}"
    pct = diff / out
    return (pct <= tol or diff <= MONEY_TOLERANCE), f"out={out} inflow={infl} diff={diff} ({pct:.2%})"


def compute_canonical_hash(payload: Mapping[str, Any]) -> str:
    clean = {k: v for k, v in payload.items() if k not in _HASH_EXCLUDED}
    clean.setdefault("missing_evidence", [])
    return canonical_sha256(clean)


def _narrative_fields(ws: Mapping[str, Any]) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = [
        ("recommendation_rationale", str(ws.get("recommendation_rationale", ""))),
        ("analyst_notes", str(ws.get("analyst_notes", "") or "")),
    ]
    fields += [(f"kyc_summaries[{i}]", str(s)) for i, s in enumerate(ws.get("kyc_summaries", []))]
    for i, hyp in enumerate(ws.get("hypotheses", [])):
        if isinstance(hyp, Mapping):
            fields.append((f"hypotheses[{i}].explanation", str(hyp.get("explanation", ""))))
            for key in ("supporting_evidence", "contradicting_evidence"):
                fields += [(f"hypotheses[{i}].{key}", str(e)) for e in hyp.get(key, [])]
    return [(name, text) for name, text in fields if text]


def _as_money(value: Any) -> Decimal | None:
    try:
        return to_money(value)
    except NumericError:
        return None


def _ingest_mapping_numbers(source: Mapping[str, Any], amounts: set[Decimal], pcts: set[Decimal]) -> None:
    for key, value in source.items():
        lk = str(key).lower()
        if ("inr" in lk or "amount" in lk) and (m := _as_money(value)) is not None:
            amounts.add(m)
        elif ("pct" in lk or "percent" in lk) and (p := as_pct(value)) is not None:
            pcts.add(p)
        elif "leakage_ratio" in lk and (lr := as_pct(value)) is not None:
            pcts.add((lr * Decimal("100")).quantize(CENT))


def _collect_known_numbers(
    ws: Mapping[str, Any],
    registry: Mapping[str, Any],
    calc_log: Sequence[Mapping[str, Any]],
) -> tuple[set[Decimal], set[Decimal]]:
    amounts: set[Decimal] = set()
    pcts: set[Decimal] = set()
    series: dict[str, list[Decimal]] = {"total_outflow_inr": [], "total_consolidated_inr": [], "net_difference_inr": []}
    for path in ws.get("candidate_paths", []):
        if isinstance(path, Mapping):
            for key, acc in series.items():
                if (m := _as_money(path.get(key))) is not None:
                    amounts.add(m)
                    acc.append(m)
            if (rp := as_pct(path.get("retention_pct"))) is not None:
                pcts.add(rp)
            if (lr := as_pct(path.get("amount_leaked_ratio"))) is not None:
                pcts.add((lr * Decimal("100")).quantize(CENT))
    amounts.update(sum(vals, Decimal("0.00")) for vals in series.values() if vals)
    if (alert_amt := _as_money(ws.get("alert_amount_inr"))) is not None:
        amounts.add(alert_amt)
    for src in [*registry.values(), *calc_log]:
        if isinstance(src, Mapping):
            _ingest_mapping_numbers(src, amounts, pcts)
    return amounts, pcts


def _matches_within_cent(val: Decimal | None, known: Collection[Decimal]) -> bool:
    return val is not None and any(abs(val - k) <= MONEY_TOLERANCE for k in known)


def _check_paths_math(
    ws: Mapping[str, Any], registry: Mapping[str, Any], out: list[Discrepancy]
) -> tuple[bool, int, int]:
    ok, errors, total = True, 0, 0
    for i, path in enumerate(ws.get("candidate_paths", [])):
        pid, field = str(path.get("path_id", "")), f"candidate_paths[{i}]"
        total += 2
        try:
            outflow, cons = to_money(path["total_outflow_inr"]), to_money(path["total_consolidated_inr"])
            net, retention = to_money(path["net_difference_inr"]), to_money(path["retention_pct"])
        except (KeyError, NumericError) as exc:
            out.append(Discrepancy(code="MALFORMED_PATH_AMOUNTS", field=field, detail=str(exc)))
            return False, errors + 1, total
        if abs(net - (outflow - cons).quantize(CENT)) > MONEY_TOLERANCE:
            out.append(Discrepancy(code="INR_NET_MISMATCH", field=field, detail=f"net {net} != {outflow} - {cons}"))
            ok, errors = False, errors + 1
        expected_ret = (net / outflow * 100).quantize(CENT) if outflow > 0 else Decimal("0.00")
        if abs(retention - expected_ret) > MONEY_TOLERANCE:
            out.append(
                Discrepancy(code="INR_RETENTION_MISMATCH", field=field, detail=f"{retention}% != {expected_ret}%")
            )
            ok, errors = False, errors + 1
        reg_path = registry.get(pid)
        if not isinstance(reg_path, Mapping):
            out.append(Discrepancy(code="UNRESOLVED_EVIDENCE_ID", field=field, detail=f"path {pid!r} not in registry"))
            ok = False
            continue
        pairs = (("outflow", outflow, "total_outflow_inr"), ("consolidated", cons, "total_consolidated_inr"))
        for label, stated, key in pairs:
            total += 1
            same, detail = verify_inr_math(stated, reg_path.get(key, "0"), tolerance="0")
            if not same:
                out.append(Discrepancy(code="INR_REGISTRY_MISMATCH", field=field, detail=f"{label}: {detail}"))
                ok, errors = False, errors + 1
    return ok, errors, total


def _check_prose_numbers(
    ws: Mapping[str, Any], known_amounts: set[Decimal], known_pcts: set[Decimal], out: list[Discrepancy]
) -> tuple[bool, int, int]:
    ok, errors, total = True, 0, 0
    for name, text in _narrative_fields(ws):
        for label, amount in extract_prose_amounts(text):
            total += 1
            if not _matches_within_cent(amount, known_amounts):
                out.append(Discrepancy(code="UNGROUNDED_AMOUNT", field=name, detail=f"{label} not in calc_log/outputs"))
                ok, errors = False, errors + 1
        for p_label, pct in extract_prose_percentages(text):
            total += 1
            if not _matches_within_cent(pct, known_pcts):
                out.append(
                    Discrepancy(code="UNGROUNDED_PERCENTAGE", field=name, detail=f"{p_label} not in calc_log/outputs")
                )
                ok, errors = False, errors + 1
    return ok, errors, total


def _resolve_corpus_map(
    corpus_ids: Collection[str] | Mapping[str, Any] | None, registry: Mapping[str, Any]
) -> dict[str, str]:
    default_map = load_corpus_category_map()
    if corpus_ids is None:
        merged = dict(default_map)
    elif isinstance(corpus_ids, Mapping):
        merged = {
            str(k): (str(v.get("category", "")) if isinstance(v, Mapping) else str(v or default_map.get(str(k), "")))
            for k, v in corpus_ids.items()
        }
    else:
        merged = {str(cid): default_map.get(str(cid), "") for cid in corpus_ids}
    for k, v in registry.items():
        if isinstance(v, Mapping) and str(k) in merged and not merged[str(k)] and v.get("category"):
            merged[str(k)] = str(v["category"])
    return merged


_FailFn = Callable[[str, str, str, str], None]


def _all_cited_clauses(ws: Mapping[str, Any]) -> list[str]:
    citations = [str(c) for c in ws.get("regulatory_citations", [])]
    for hyp in ws.get("hypotheses", []):
        if isinstance(hyp, Mapping):
            for hc in hyp.get("regulatory_citations", []):
                if str(hc) not in citations:
                    citations.append(str(hc))
    return citations


def _validate_single_citation(
    cs: str, corpus_map: Mapping[str, str], registry: Mapping[str, Any], fail: _FailFn
) -> bool:
    if not CITATION_FORMAT.match(cs):
        fail("citation_format_valid", "BAD_CITATION_FORMAT", "regulatory_citations", cs)
        fail("citations_exist", "BAD_CITATION_FORMAT", "regulatory_citations", cs)
        return False
    if cs not in corpus_map:
        fail("citations_exist", "UNRESOLVED_CITATION", "regulatory_citations", f"{cs!r} not in corpus index")
        fail("citations_resolved", "UNRESOLVED_CITATION", "regulatory_citations", f"{cs!r} not in corpus index")
        return False
    if cs not in registry:
        fail("citations_resolved", "UNRESOLVED_CITATION", "regulatory_citations", f"{cs!r} not in registry")
        fail("citations_exist", "UNRESOLVED_CITATION", "regulatory_citations", f"{cs!r} not in registry")
        return False
    return True


def _check_citations_v2(
    ws: Mapping[str, Any],
    registry: Mapping[str, Any],
    corpus_map: Mapping[str, str],
    disposition: str,
    judge_relevant: Optional[bool],
    fail: _FailFn,
) -> bool:
    citations = _all_cited_clauses(ws)
    exempt_empty = bool(ws.get("degraded_evidence")) and disposition == "request_info"
    if not citations:
        if not exempt_empty:
            fail("has_citations", "NO_CITATIONS", "regulatory_citations", "at least one citation is required")
            fail("citations_exist", "NO_CITATIONS", "regulatory_citations", "at least one citation is required")
            return False
        return True

    exist_flags = [_validate_single_citation(cs, corpus_map, registry, fail) for cs in citations]
    if not all(exist_flags):
        return False

    typology_id = str(ws.get("typology_id") or "scatter_gather")
    allowed_all = typology_registry.all_typology_categories(typology_id)
    allowed_claim = typology_registry.allowed_categories_for_claim(disposition, typology_id)
    known_cats = [c for c in (corpus_map.get(cs, "") for cs in citations) if c]
    det_rel = (not known_cats) or (
        all(c in allowed_all for c in known_cats) and any(c in allowed_claim for c in known_cats)
    )
    if not (det_rel or judge_relevant is True):
        fail(
            "citations_relevant",
            "IRRELEVANT_CITATION",
            "regulatory_citations",
            f"categories {known_cats} not relevant for disposition={disposition!r}",
        )
    return det_rel


def _referenced_ids(ws: Mapping[str, Any]) -> Iterable[tuple[str, str]]:
    for name, text in _narrative_fields(ws):
        for ref in REF_PATTERN.findall(text):
            yield name, ref.rstrip("-_.")
    for i, hyp in enumerate(ws.get("hypotheses", [])):
        if isinstance(hyp, Mapping):
            for ref in [*hyp.get("evidence_ids", []), *hyp.get("regulatory_citations", [])]:
                yield f"hypotheses[{i}]", str(ref)


def _check_evidence_registration(ws: Mapping[str, Any], registry: Mapping[str, Any], fail: _FailFn) -> None:
    for field, ref in _referenced_ids(ws):
        if ref not in registry:
            fail("evidence_ids_registered", "UNRESOLVED_EVIDENCE_ID", field, f"{ref!r} not in evidence_registry")
            fail("evidence_ids_resolved", "UNRESOLVED_EVIDENCE_ID", field, f"{ref!r} not in evidence_registry")

    non_clause_ids = [k for k in registry if not str(k).startswith(CLAUSE_ID_PREFIXES)]
    exempt_degraded = bool(ws.get("degraded_evidence")) and str(ws.get("recommended_disposition")) == "request_info"
    rationale = str(ws.get("recommendation_rationale", ""))
    if not exempt_degraded and not REF_PATTERN.search(rationale) and not ws.get("regulatory_citations"):
        fail("evidence_ids_registered", "UNCITED_MATERIAL_CLAIM", "recommendation_rationale", "rationale lacks IDs")
    if non_clause_ids and not exempt_degraded:
        for i, hyp in enumerate(ws.get("hypotheses", [])):
            if not isinstance(hyp, Mapping):
                continue
            expl = str(hyp.get("explanation", ""))
            has_id = bool(hyp.get("evidence_ids")) or bool(DATA_EVIDENCE_PATTERN.search(expl))
            if not has_id:
                fail(
                    "evidence_ids_registered",
                    "UNCITED_MATERIAL_CLAIM",
                    f"hypotheses[{i}]",
                    f"hypothesis {hyp.get('label')!r} carries 0 registered evidence IDs",
                )


def _check_hypotheses_and_missing(ws: Mapping[str, Any], fail: _FailFn) -> None:
    hyps = [h for h in ws.get("hypotheses", []) if isinstance(h, Mapping)]
    labels = {str(h.get("label", "")).lower() for h in hyps if str(h.get("explanation", "")).strip()}
    if not ({"suspicious", "benign"} <= labels):
        fail("both_hypotheses_present", "MISSING_COMPETING_HYPOTHESES", "hypotheses", "both hypotheses required")

    explicit_list = [str(m).strip() for m in (ws.get("missing_evidence") or []) if str(m).strip()]
    degraded_list = [str(d).strip() for d in (ws.get("degraded_evidence") or []) if str(d).strip()]
    rationale_low = str(ws.get("recommendation_rationale", "")).lower()
    notes_low = str(ws.get("analyst_notes") or "").lower()
    if not (explicit_list or degraded_list or any(c in rationale_low or c in notes_low for c in _MISSING_CUES)):
        fail("missing_evidence_stated", "MISSING_EVIDENCE_NOT_STATED", "missing_evidence", "missing evidence required")


def _check_confidence_and_disp(ws: Mapping[str, Any], fail: _FailFn) -> str:
    try:
        to_confidence(ws.get("confidence_score", 0))
    except NumericError:
        fail("confidence_in_range", "CONFIDENCE_OUT_OF_RANGE", "confidence_score", str(ws.get("confidence_score")))
    disp = str(ws.get("recommended_disposition", ""))
    if disp not in _VALID_DISPOSITIONS:
        fail("valid_disposition", "INVALID_DISPOSITION", "recommended_disposition", disp)
    return disp


def verify_worksheet(
    worksheet: Mapping[str, Any],
    evidence_registry: Mapping[str, Any] | None = None,
    corpus_ids: Collection[str] | Mapping[str, Any] | None = None,
    calc_log: Sequence[Mapping[str, Any]] | None = None,
    *,
    judge_citation_relevant: Optional[bool] = None,
) -> VerificationResult:
    """Run all 6 deterministic Verifier v2 checks and return structured `VerificationResult`."""
    issues: list[Discrepancy] = []
    checks: dict[str, bool] = {}

    def fail(check: str, code: str, field: str, detail: str) -> None:
        checks[check] = False
        issues.append(Discrepancy(code=code, field=field, detail=detail))

    registry: Mapping[str, Any] = evidence_registry if evidence_registry is not None else {}
    if evidence_registry is None:
        fail("evidence_registry_present", "EVIDENCE_REGISTRY_MISSING", "evidence_registry", "registry is required")
    checks.setdefault("evidence_registry_present", True)

    for name, text in _narrative_fields(worksheet):
        if hits := check_prohibited_claims(text):
            fail("no_guilt_claims", "PROHIBITED_CLAIM", name, f"guilt assertion matched: {hits}")
            checks["no_prohibited_claims"] = False

    disposition = _check_confidence_and_disp(worksheet, fail)
    judge_sig = judge_citation_relevant
    if judge_sig is None and isinstance(worksheet.get("judge_citation_relevant"), bool):
        judge_sig = bool(worksheet["judge_citation_relevant"])
    cmap = _resolve_corpus_map(corpus_ids, registry)
    det_rel = _check_citations_v2(worksheet, registry, cmap, disposition, judge_sig, fail)
    _check_evidence_registration(worksheet, registry, fail)
    _check_hypotheses_and_missing(worksheet, fail)

    for default_ok in (
        "no_guilt_claims",
        "no_prohibited_claims",
        "confidence_in_range",
        "valid_disposition",
        "has_citations",
        "citation_format_valid",
        "citations_resolved",
        "citations_exist",
        "citations_relevant",
        "evidence_ids_registered",
        "evidence_ids_resolved",
        "both_hypotheses_present",
        "missing_evidence_stated",
    ):
        checks.setdefault(default_ok, True)

    known_amounts, known_pcts = _collect_known_numbers(worksheet, registry, calc_log or ())
    paths_ok, path_errs, path_total = _check_paths_math(worksheet, registry, issues)
    prose_ok, prose_errs, prose_total = _check_prose_numbers(worksheet, known_amounts, known_pcts, issues)
    checks["inr_math_verified"] = paths_ok
    checks["narrative_amounts_grounded"] = prose_ok
    checks["numbers_match_calc"] = (path_errs + prose_errs) == 0 and paths_ok and prose_ok

    return VerificationResult(
        passed=all(checks.values()) and not issues,
        checks=checks,
        errors=[f"{d.code}: {d.field}: {d.detail}" for d in issues],
        discrepancies=issues,
        payload_hash=compute_canonical_hash(worksheet),
        inr_error_count=path_errs + prose_errs,
        inr_numbers_total=path_total + prose_total,
        deterministic_citation_relevant=det_rel,
        judge_citation_relevant=judge_sig,
    )
