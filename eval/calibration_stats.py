"""
Strict CSV validation, rank/linear verbosity correlations, and stratified-vs-population
agreement estimators for `eval/calibration.py`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import csv
import math
from pathlib import Path
from typing import Any

from eval.judge import ALL_CRITERIA, BINARY_CRITERIA, ORDINAL_CRITERIA, criterion_kappa

EXPECTED_CSV_COLUMNS: tuple[str, ...] = (
    "worksheet_id",
    "annotator",
    "G1",
    "G2",
    "G3",
    "G4",
    "G5",
    "G6",
    "G7",
    "comments",
)


class AnnotationValidationError(ValueError):
    """Raised when human worksheet annotation CSVs contain malformed, partial, or duplicate rows."""


def _validate_single_row(wid: str, row: Mapping[str, str], source: str) -> dict[str, Any] | None:
    raw_vals = {c: (row.get(c) or "").strip() for c in ALL_CRITERIA}
    filled = [c for c, v in raw_vals.items() if v != ""]
    if not filled:
        return None
    missing = [c for c, v in raw_vals.items() if v == ""]
    if missing:
        raise AnnotationValidationError(
            f"MISSING_CRITERIA in {source} for {wid}: missing {missing} (all G1..G7 required once started)"
        )
    parsed: dict[str, Any] = {
        "worksheet_id": wid,
        "annotator": (row.get("annotator") or "").strip(),
        "comments": (row.get("comments") or "").strip(),
    }
    for c in ORDINAL_CRITERIA:
        val_s = raw_vals[c]
        if not val_s.isdigit() or not (1 <= int(val_s) <= 5):
            raise AnnotationValidationError(
                f"INVALID_SCORE in {source} for {wid}.{c}: {val_s!r} (expected integer 1..5)"
            )
        parsed[c] = int(val_s)
    for c in BINARY_CRITERIA:
        val_b = raw_vals[c].lower()
        if val_b not in ("pass", "fail"):
            raise AnnotationValidationError(
                f"INVALID_SCORE in {source} for {wid}.{c}: {raw_vals[c]!r} (expected 'pass' or 'fail')"
            )
        parsed[c] = val_b
    return parsed


def read_and_validate_annotator_csv(path: Path) -> tuple[list[str], dict[str, dict[str, Any]]]:
    """Return `(ordered_template_ids, completed_scores_by_id)` after strict schema & value checks."""
    if not path.exists():
        return [], {}
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = tuple(reader.fieldnames or ())
        missing_cols = [col for col in EXPECTED_CSV_COLUMNS if col not in fieldnames]
        if missing_cols:
            raise AnnotationValidationError(f"MISSING_COLUMNS in {path.name}: missing {missing_cols}")
        ordered_ids: list[str] = []
        seen: set[str] = set()
        completed: dict[str, dict[str, Any]] = {}
        for idx, row in enumerate(reader, start=2):
            wid = (row.get("worksheet_id") or "").strip()
            if not wid:
                raise AnnotationValidationError(f"EMPTY_WORKSHEET_ID in {path.name} at line {idx}")
            if wid in seen:
                raise AnnotationValidationError(f"DUPLICATE_WORKSHEET_ID in {path.name}: {wid!r}")
            seen.add(wid)
            ordered_ids.append(wid)
            parsed = _validate_single_row(wid, row, path.name)
            if parsed is not None:
                completed[wid] = parsed
    return ordered_ids, completed


def pearson_r(xs: Sequence[float], ys: Sequence[float]) -> float | None:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True))
    den_x = math.sqrt(sum((x - mx) ** 2 for x in xs))
    den_y = math.sqrt(sum((y - my) ** 2 for y in ys))
    if den_x <= 1e-12 or den_y <= 1e-12:
        return 0.0
    return round(num / (den_x * den_y), 4)


def _ranks(vals: Sequence[float]) -> list[float]:
    indexed = sorted(enumerate(vals), key=lambda t: t[1])
    ranks = [0.0] * len(vals)
    i = 0
    while i < len(indexed):
        j = i
        while j + 1 < len(indexed) and indexed[j + 1][1] == indexed[i][1]:
            j += 1
        avg_rank = (i + j + 2) / 2.0
        for k in range(i, j + 1):
            ranks[indexed[k][0]] = avg_rank
        i = j + 1
    return ranks


def spearman_rho(xs: Sequence[float], ys: Sequence[float]) -> float | None:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    return pearson_r(_ranks(xs), _ranks(ys))


def compute_criterion_table(
    wids: Sequence[str],
    ann1: Mapping[str, Mapping[str, Any]],
    ann2: Mapping[str, Mapping[str, Any]],
    judge: Mapping[str, Mapping[str, Any]] | None,
    manifest_items: Mapping[str, Mapping[str, Any]],
    pop_family_weights: Mapping[str, float],
) -> dict[str, dict[str, Any]]:
    """Compute per-criterion human-human kappa, judge-human kappa, sample & population-weighted agreement."""
    out: dict[str, dict[str, Any]] = {}
    judge_paired = [w for w in wids if judge and w in judge]
    for crit in ALL_CRITERIA:
        v1 = [ann1[w][crit] for w in wids]
        v2 = [ann2[w][crit] for w in wids]
        hh_kappa = round(criterion_kappa(crit, v1, v2), 4)
        sample_agree = round(sum(1 for a, b in zip(v1, v2, strict=True) if a == b) / len(wids), 4)
        pop_agree = _population_weighted_agreement(wids, ann1, ann2, crit, manifest_items, pop_family_weights)

        jh_kappa: float | None = None
        jh_pop_agree: float | None = None
        if judge is not None and len(judge_paired) >= 2:
            jv = [judge[w][crit] for w in judge_paired]
            k1 = criterion_kappa(crit, jv, [ann1[w][crit] for w in judge_paired])
            k2 = criterion_kappa(crit, jv, [ann2[w][crit] for w in judge_paired])
            jh_kappa = round((k1 + k2) / 2.0, 4)
            pa1 = _population_weighted_agreement(judge_paired, judge, ann1, crit, manifest_items, pop_family_weights)
            pa2 = _population_weighted_agreement(judge_paired, judge, ann2, crit, manifest_items, pop_family_weights)
            jh_pop_agree = round((pa1 + pa2) / 2.0, 4)

        out[crit] = {
            "scale": "ordinal_1_5" if crit in ORDINAL_CRITERIA else "binary_pass_fail",
            "kappa_type": "linear_weighted" if crit in ORDINAL_CRITERIA else "plain_cohen",
            "n_paired": len(wids),
            "human_human_kappa": hh_kappa,
            "human_sample_agreement": sample_agree,
            "human_population_weighted_agreement": pop_agree,
            "judge_human_kappa": jh_kappa,
            "judge_population_weighted_agreement": jh_pop_agree,
            "meets_target_0_75": (jh_kappa >= 0.75) if jh_kappa is not None else None,
        }
    return out


def _population_weighted_agreement(
    wids: Sequence[str],
    rater_a: Mapping[str, Mapping[str, Any]],
    rater_b: Mapping[str, Mapping[str, Any]],
    crit: str,
    manifest_items: Mapping[str, Mapping[str, Any]],
    pop_weights: Mapping[str, float],
) -> float:
    by_fam: dict[str, list[float]] = {}
    for w in wids:
        fam = str((manifest_items.get(w) or {}).get("family_group", "unknown"))
        exact = 1.0 if rater_a[w][crit] == rater_b[w][crit] else 0.0
        by_fam.setdefault(fam, []).append(exact)
    total_w = 0.0
    acc = 0.0
    for fam, vals in by_fam.items():
        fw = float(pop_weights.get(fam, 0.0))
        if fw > 0 and vals:
            acc += fw * (sum(vals) / len(vals))
            total_w += fw
    if total_w <= 1e-12:
        all_v = [v for vals in by_fam.values() for v in vals]
        return round(sum(all_v) / max(1, len(all_v)), 4)
    return round(acc / total_w, 4)
