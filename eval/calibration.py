"""
Phase 4 — Judge Calibration, Inter-Annotator Kappa & Bias Analysis CLI (`eval/calibration.py`).

Usage:
  `python -m eval.calibration --labels eval/human_labels --out runs/cal/`

Enforces:
  * Honest status progression: `awaiting_human_annotations` -> `incomplete_annotations` ->
    `dev_calibration_ready` -> `final_held_out_complete` (never fabricates scores or treats empty as 0)
  * Held-out isolation: held-out annotations are strictly blocked from dev rubric/prompt tuning,
    and final held-out agreement requires `rubric_frozen=True`
  * Reports human-human & judge-human kappa (linear-weighted for 1..5, plain for pass/fail),
    sample vs population-weighted agreement, verbosity correlation, position-swap bias,
    cross-family model validation, and deterministic companions (`numbers_match_calc`, `citations_exist`).
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
from pathlib import Path
from typing import Any

from eval.calibration_stats import (
    AnnotationValidationError,
    compute_criterion_table,
    pearson_r,
    read_and_validate_annotator_csv,
    spearman_rho,
)
from eval.judge import ORDINAL_CRITERIA, validate_cross_family_judge
from eval.judge_prompts import PROMPT_VERSION, load_rubric_text_and_version

DEFAULT_LABELS_DIR = Path("eval/human_labels")
DEFAULT_MANIFEST_PATH = Path("eval/calibration_manifest/packet_manifest.json")
DEFAULT_OUT_DIR = Path("runs/cal")
KAPPA_TARGET = 0.75


def load_manifest(manifest_path: Path = DEFAULT_MANIFEST_PATH) -> dict[str, Any]:
    if not manifest_path.exists():
        return {"worksheets": {}, "sampling_design": {}, "rubric_frozen": False}
    return dict(json.loads(manifest_path.read_text(encoding="utf-8")))


def assert_dev_only_for_tuning(worksheet_id: str, manifest: Mapping[str, Any]) -> None:
    """Block any held-out or unknown worksheet from entering judge rubric/prompt tuning."""
    items = manifest.get("worksheets") or {}
    meta = items.get(worksheet_id)
    if not isinstance(meta, Mapping) or meta.get("split") != "dev":
        split_found = meta.get("split") if isinstance(meta, Mapping) else "unknown"
        raise PermissionError(
            f"Held-out isolation violation: worksheet {worksheet_id!r} (split={split_found!r}) "
            "cannot be accessed by development judge tuning workflows."
        )


def extract_dev_tuning_disagreements(
    ann1: Mapping[str, Mapping[str, Any]],
    ann2: Mapping[str, Mapping[str, Any]],
    judge_scores: Mapping[str, Mapping[str, Any]],
    manifest: Mapping[str, Any],
    *,
    requested_ids: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Return judge-vs-human disagreements STRICTLY from the 20-item `dev` split."""
    items = manifest.get("worksheets") or {}
    if requested_ids is not None:
        for wid in requested_ids:
            assert_dev_only_for_tuning(wid, manifest)
        candidate_ids = list(requested_ids)
    else:
        candidate_ids = [w for w, m in items.items() if isinstance(m, Mapping) and m.get("split") == "dev"]

    records: list[dict[str, Any]] = []
    for wid in sorted(candidate_ids):
        assert_dev_only_for_tuning(wid, manifest)
        if wid not in ann1 or wid not in ann2 or wid not in judge_scores:
            continue
        diffs = {
            c: {"annotator_1": ann1[wid][c], "annotator_2": ann2[wid][c], "judge": judge_scores[wid][c]}
            for c in ("G1", "G2", "G3", "G4", "G5", "G6", "G7")
            if judge_scores[wid][c] != ann1[wid][c] or judge_scores[wid][c] != ann2[wid][c]
        }
        if diffs:
            records.append({"worksheet_id": wid, "split": "dev", "disagreements": diffs})
    return records


def evaluate_held_out_calibration(
    held_out_ids: Sequence[str],
    ann1: Mapping[str, Mapping[str, Any]],
    ann2: Mapping[str, Mapping[str, Any]],
    judge_scores: Mapping[str, Mapping[str, Any]] | None,
    manifest: Mapping[str, Any],
    *,
    rubric_frozen: bool,
) -> dict[str, dict[str, Any]]:
    """Measure untouched held-out agreement ONLY after `rubric_frozen=True`."""
    if not rubric_frozen:
        raise PermissionError(
            "Held-out judge calibration refused: rubric and judge prompt must be frozen (`rubric_frozen=True`) "
            "on development data before evaluating held-out agreement."
        )
    items = manifest.get("worksheets") or {}
    pop_w = ((manifest.get("sampling_design") or {}).get("population_family_weights") or {}).get("held_out") or {}
    paired = [w for w in held_out_ids if w in ann1 and w in ann2]
    if not paired:
        return {}
    return compute_criterion_table(paired, ann1, ann2, judge_scores, items, pop_w)


def _load_blinded_packet(labels_dir: Path) -> dict[str, dict[str, Any]]:
    pkt_path = labels_dir / "worksheets_packet_blinded.jsonl"
    if not pkt_path.exists():
        return {}
    out: dict[str, dict[str, Any]] = {}
    for raw in pkt_path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            rec = json.loads(raw)
            out[str(rec["worksheet_id"])] = rec
    return out


def _compute_bias_and_companions(
    packet: Mapping[str, Mapping[str, Any]],
    judge_scores: Mapping[str, Mapping[str, Any]] | None,
    swap_records: Sequence[Mapping[str, Any]] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    family_info = validate_cross_family_judge()
    lengths: list[float] = []
    ord_means: list[float] = []
    if judge_scores:
        for wid, j_sc in judge_scores.items():
            pkt = packet.get(wid) or {}
            ws_body = pkt.get("worksheet") or {}
            text_blob = json.dumps(ws_body, sort_keys=True)
            lengths.append(float(len(text_blob.split())))
            ord_means.append(sum(float(j_sc[c]) for c in ORDINAL_CRITERIA) / len(ORDINAL_CRITERIA))

    swaps = list(swap_records or [])
    consistent = sum(1 for s in swaps if s.get("position_consistent"))
    bias = {
        "verbosity_word_count_pearson_r": pearson_r(lengths, ord_means) if len(lengths) >= 2 else None,
        "verbosity_word_count_spearman_rho": spearman_rho(lengths, ord_means) if len(lengths) >= 2 else None,
        "verbosity_n_worksheets": len(lengths),
        "position_swap_pairs_tested": len(swaps),
        "position_swap_consistent_rate": round(consistent / len(swaps), 4) if swaps else None,
        "position_swap_flip_rate": round(1.0 - (consistent / len(swaps)), 4) if swaps else None,
        "position_swap_mean_ordinal_drift": (
            round(sum(float(s.get("mean_abs_ordinal_drift", 0.0)) for s in swaps) / len(swaps), 4)
            if swaps
            else None
        ),
        "self_preference_check": family_info,
    }

    comps = [dict(p["deterministic_companions"]) for p in packet.values() if p.get("deterministic_companions")]
    n_c = len(comps)
    companions = {
        "n_worksheets": n_c,
        "numbers_match_calc_pass_rate": (
            round(sum(1 for c in comps if c.get("numbers_match_calc")) / n_c, 4) if n_c else None
        ),
        "citations_exist_pass_rate": (
            round(sum(1 for c in comps if c.get("citations_exist")) / n_c, 4) if n_c else None
        ),
        "no_guilt_claims_pass_rate": (
            round(sum(1 for c in comps if c.get("no_guilt_claims")) / n_c, 4) if n_c else None
        ),
    }
    return bias, companions


def _load_optional_json_map(path: Path | None) -> tuple[dict[str, dict[str, Any]] | None, list[dict[str, Any]]]:
    if path is None or not path.exists():
        return None, []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "scores" in raw:
        return dict(raw["scores"]), list(raw.get("position_swaps") or [])
    return dict(raw), []


def run_calibration(
    *,
    labels_dir: Path = DEFAULT_LABELS_DIR,
    out_dir: Path = DEFAULT_OUT_DIR,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    judge_scores_path: Path | None = None,
    rubric_frozen_override: bool | None = None,
) -> dict[str, Any]:
    """Validate human CSVs, compute Phase 4 agreement & bias tables, and write calibration artifacts."""
    ids_1, ann1 = read_and_validate_annotator_csv(labels_dir / "worksheets_to_score_annotator_1.csv")
    ids_2, ann2 = read_and_validate_annotator_csv(labels_dir / "worksheets_to_score_annotator_2.csv")
    if set(ids_1) != set(ids_2):
        raise AnnotationValidationError(
            f"TEMPLATE_COVERAGE_MISMATCH: annotator_1 has {len(ids_1)} IDs vs annotator_2 {len(ids_2)} IDs"
        )

    manifest = load_manifest(manifest_path)
    items = manifest.get("worksheets") or {}
    rubric_frozen = (
        rubric_frozen_override if rubric_frozen_override is not None else bool(manifest.get("rubric_frozen", False))
    )
    _, rubric_ver = load_rubric_text_and_version()
    judge_map, swap_records = _load_optional_json_map(judge_scores_path)
    packet = _load_blinded_packet(labels_dir)
    bias_table, companions_table = _compute_bias_and_companions(packet, judge_map, swap_records)

    dev_ids = [w for w in ids_1 if (items.get(w) or {}).get("split") == "dev"]
    ho_ids = [w for w in ids_1 if (items.get(w) or {}).get("split") == "held_out"]
    paired_all = sorted(set(ann1) & set(ann2))
    paired_dev = [w for w in dev_ids if w in ann1 and w in ann2]
    paired_ho = [w for w in ho_ids if w in ann1 and w in ann2]

    if not paired_all:
        summary = {
            "status": "awaiting_human_annotations",
            "calibration_complete": False,
            "rubric_version": rubric_ver,
            "prompt_version": PROMPT_VERSION,
            "rubric_frozen": rubric_frozen,
            "target_total_worksheets": len(ids_1),
            "target_dev_worksheets": len(dev_ids),
            "target_held_out_worksheets": len(ho_ids),
            "annotator_1_completed": len(ann1),
            "annotator_2_completed": len(ann2),
            "paired_completed": 0,
            "dev_criteria_kappa": None,
            "held_out_criteria_kappa": None,
            "excluded_from_headline": [],
            "sampling_design": manifest.get("sampling_design") or {},
            "bias_checks": bias_table,
            "deterministic_companions": companions_table,
        }
        _write_outputs(out_dir, summary)
        return summary

    pop_weights = (manifest.get("sampling_design") or {}).get("population_family_weights") or {}
    dev_table = (
        compute_criterion_table(paired_dev, ann1, ann2, judge_map, items, pop_weights.get("dev") or {})
        if len(paired_dev) >= 2
        else None
    )
    dev_complete = bool(dev_ids) and len(paired_dev) == len(dev_ids)
    ho_complete = bool(ho_ids) and len(paired_ho) == len(ho_ids)

    ho_table: dict[str, dict[str, Any]] | None = None
    if dev_complete and ho_complete and rubric_frozen:
        ho_table = evaluate_held_out_calibration(
            ho_ids, ann1, ann2, judge_map, manifest, rubric_frozen=True
        )
        status = "final_held_out_complete"
    elif dev_complete:
        status = "dev_calibration_ready"
    else:
        status = "incomplete_annotations"

    active_table = ho_table or dev_table or {}
    excluded = [
        c
        for c, row in active_table.items()
        if row.get("judge_human_kappa") is not None and float(row["judge_human_kappa"]) < KAPPA_TARGET
    ]
    summary = {
        "status": status,
        "calibration_complete": status == "final_held_out_complete",
        "rubric_version": rubric_ver,
        "prompt_version": PROMPT_VERSION,
        "rubric_frozen": rubric_frozen,
        "target_total_worksheets": len(ids_1),
        "target_dev_worksheets": len(dev_ids),
        "target_held_out_worksheets": len(ho_ids),
        "annotator_1_completed": len(ann1),
        "annotator_2_completed": len(ann2),
        "paired_completed": len(paired_all),
        "paired_dev_completed": len(paired_dev),
        "paired_held_out_completed": len(paired_ho),
        "dev_criteria_kappa": dev_table,
        "held_out_criteria_kappa": ho_table,
        "excluded_from_headline": excluded,
        "sampling_design": manifest.get("sampling_design") or {},
        "bias_checks": bias_table,
        "deterministic_companions": companions_table,
    }
    _write_outputs(out_dir, summary)
    return summary


def _format_markdown_report(summary: Mapping[str, Any]) -> str:
    lines = [
        "# AuditGuard Phase 4 — Judge Calibration & Bias Report",
        "",
        f"- **Status:** `{summary['status']}`",
        f"- **Rubric Version:** `{summary['rubric_version']}` (`frozen={summary['rubric_frozen']}`)",
        f"- **Prompt Version:** `{summary['prompt_version']}`",
        f"- **Completed Paired Annotations:** `{summary['paired_completed']} / {summary['target_total_worksheets']}` "
        f"(Annotator 1: `{summary['annotator_1_completed']}`, Annotator 2: `{summary['annotator_2_completed']}`)",
        "",
        "## 1. Per-Criterion Kappa Table (Target Weighted Kappa >= 0.75)",
        "",
    ]
    table_src = summary.get("held_out_criteria_kappa") or summary.get("dev_criteria_kappa")
    if not table_src:
        lines.append("_Awaiting completed independent human annotations (`status: awaiting_human_annotations`)._")
    else:
        lines.extend(
            [
                "| Criterion | Scale | Human-Human Kappa | Judge-Human Kappa "
                "| Sample Agree | Pop-Weighted Agree | >= 0.75 |",
                "|---|---|---:|---:|---:|---:|---|",
            ]
        )
        for crit, row in table_src.items():
            jh = f"{row['judge_human_kappa']:.4f}" if row["judge_human_kappa"] is not None else "N/A"
            mt = str(row["meets_target_0_75"]) if row["meets_target_0_75"] is not None else "N/A"
            lines.append(
                f"| `{crit}` | `{row['kappa_type']}` | {row['human_human_kappa']:.4f} | {jh} | "
                f"{row['human_sample_agreement']:.4f} | {row['human_population_weighted_agreement']:.4f} | `{mt}` |"
            )
    bias = summary["bias_checks"]
    comp = summary["deterministic_companions"]
    fam = bias["self_preference_check"]
    lines.extend(
        [
            "",
            "## 2. Bias & Self-Preference Table",
            "",
            "| Check | Value |",
            "|---|---|",
            (
                f"| Cross-Family Verified | `{fam['cross_family_verified']}` "
                f"(`{fam['judge_model']}` -> `{fam['judge_family']}`) |"
            ),
            (
                f"| Verbosity Pearson r | `{bias['verbosity_word_count_pearson_r']}` "
                f"(n={bias['verbosity_n_worksheets']}) |"
            ),
            f"| Verbosity Spearman rho | `{bias['verbosity_word_count_spearman_rho']}` |",
            (
                f"| Position-Swap Flip Rate | `{bias['position_swap_flip_rate']}` "
                f"(pairs={bias['position_swap_pairs_tested']}) |"
            ),
            f"| Position-Swap Mean Drift | `{bias['position_swap_mean_ordinal_drift']}` |",
            "",
            "## 3. Deterministic Companions (Verifier v2)",
            "",
            f"- `numbers_match_calc` pass rate: `{comp['numbers_match_calc_pass_rate']}` (n={comp['n_worksheets']})",
            f"- `citations_exist` pass rate: `{comp['citations_exist_pass_rate']}`",
            f"- `no_guilt_claims` pass rate: `{comp['no_guilt_claims_pass_rate']}`",
            "",
        ]
    )
    return "\n".join(lines)


def _write_outputs(out_dir: Path, summary: Mapping[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "calibration_summary.json").write_text(json.dumps(dict(summary), indent=2), encoding="utf-8")
    (out_dir / "calibration_report.md").write_text(_format_markdown_report(summary), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="AuditGuard Phase 4 Judge Calibration & Bias CLI")
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS_DIR, help="Directory with human label CSVs")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR, help="Output directory for calibration artifacts")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST_PATH, help="Coordinator manifest path")
    parser.add_argument("--judge-scores", type=Path, default=None, help="Optional judge scores JSON path")
    args = parser.parse_args()
    summary = run_calibration(
        labels_dir=args.labels,
        out_dir=args.out,
        manifest_path=args.manifest,
        judge_scores_path=args.judge_scores,
    )
    print(_format_markdown_report(summary))


if __name__ == "__main__":
    main()
