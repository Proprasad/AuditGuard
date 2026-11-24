"""
Reproducible Golden Dataset v2 Builder (`python -m data.generator_v2.build --seed 42`).

Generates:
  - Development split : `data/golden_v2/dev/`       (60 cases; no held-out-only `⚑` variants)
  - Held-out split    : `eval/golden_v2/held_out/`  (120 cases; includes `⚑` held-out-only variants)
  - Challenge split   : `eval/golden_v2/challenge/` (30 cases; all adversarial)
  - Human-label CSVs  : `eval/human_labels/`        (40 ambiguous/hard dev cases; empty annotation fields)

Verifies purity (<= 0.75 per single KYC field), structural fingerprint uniqueness across all 210 cases,
ID disjointness across splits, and stable SHA-256 directory digest.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import random
from typing import Any

from data.generator_v2.families import DEV_VARIANTS, HELD_OUT_ONLY_VARIANTS, VariantSpec, generate_v2_case
from data.generator_v2.labels import assert_kyc_purity_bounds, assert_unique_fingerprints

DEFAULT_SEED = 42
DEV_DIR = Path("data/golden_v2/dev")
HELD_OUT_DIR = Path("eval/golden_v2/held_out")
CHALLENGE_DIR = Path("eval/golden_v2/challenge")
HUMAN_LABELS_DIR = Path("eval/human_labels")
SUMMARY_PATH = Path("data/golden_v2/summary.json")


def _by_group(variants: tuple[VariantSpec, ...], group: str) -> list[VariantSpec]:
    return [v for v in variants if v.family_group == group]


def _schedule_dev_specs(rng: random.Random) -> list[VariantSpec]:
    """60 dev cases balanced across the 5 families (24 escalate, 20 benign, 16 request_info/ambiguous)."""
    plan: list[VariantSpec] = []
    groups = (
        ("layering", 14),
        ("layering_benign_cover", 8),
        ("benign_lookalike", 20),
        ("incomplete_data", 8),
        ("ambiguous", 10),
    )
    for grp, count in groups:
        pool = _by_group(DEV_VARIANTS, grp)
        for i in range(count):
            plan.append(pool[i % len(pool)])
    rng.shuffle(plan)
    return plan


def _schedule_held_out_specs(rng: random.Random) -> list[VariantSpec]:
    """120 held-out cases including all 7 `⚑` held-out-only variants + unseen seeds of base families."""
    all_pool = (*DEV_VARIANTS, *HELD_OUT_ONLY_VARIANTS)
    plan: list[VariantSpec] = []
    # Guarantee rich representation of every held-out-only `⚑` variant first (7 * 8 = 56 cases)
    for hv in HELD_OUT_ONLY_VARIANTS:
        plan.extend([hv] * 8)
    groups = (
        ("layering", 14),
        ("layering_benign_cover", 8),
        ("benign_lookalike", 22),
        ("incomplete_data", 8),
        ("ambiguous", 12),
    )
    for grp, count in groups:
        pool = _by_group(all_pool, grp)
        for i in range(count):
            plan.append(pool[i % len(pool)])
    assert len(plan) == 120
    rng.shuffle(plan)
    return plan


def _schedule_challenge_specs(rng: random.Random) -> list[VariantSpec]:
    """30 adversarial challenge cases (12 escalate, 10 benign hard/unregistered/decoy, 8 incomplete/ambiguous)."""
    all_pool = (*DEV_VARIANTS, *HELD_OUT_ONLY_VARIANTS)
    hard_escalate = [
        v for v in all_pool if v.gold_disposition == "escalate_str" and (v.adversarial_tags or v.held_out_only)
    ]
    hard_benign = [v for v in all_pool if v.gold_disposition == "close_benign"]
    hard_req = [v for v in all_pool if v.family_group in ("incomplete_data", "ambiguous")]
    plan: list[VariantSpec] = []
    for pool, count in ((hard_escalate, 12), (hard_benign, 10), (hard_req, 8)):
        for i in range(count):
            plan.append(pool[i % len(pool)])
    assert len(plan) == 30
    rng.shuffle(plan)
    return plan


def select_40_dev_annotation_cases(dev_cases: list[dict[str, Any]]) -> list[str]:
    """Select 40 ambiguous/hard (then medium) cases strictly from `dev` — never `held_out` or `challenge`."""
    for c in dev_cases:
        if c.get("split") != "dev" or c.get("is_held_out"):
            raise ValueError(f"Refusing non-dev case {c.get('case_id')} for human annotation template")
    priority = {"hard": 0, "medium": 1, "easy": 2}
    ranked = sorted(
        dev_cases,
        key=lambda c: (
            0 if c["family_group"] == "ambiguous" else 1,
            priority.get(str(c["difficulty"]), 2),
            0 if c.get("adversarial") else 1,
            str(c["case_id"]),
        ),
    )
    selected = [str(c["case_id"]) for c in ranked[:40]]
    return sorted(selected)


def _write_csv_if_unpopulated(
    path: Path, headers: list[str], rows: list[list[str]], *, overwrite_templates: bool
) -> None:
    if path.exists() and not overwrite_templates:
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = list(csv.reader(f))
        # Preserve file if any human annotation cell (column >= 1) has already been filled
        if any(any(cell.strip() for cell in row[1:]) for row in reader[1:] if len(row) > 1):
            return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(headers)
        writer.writerows(rows)


def write_human_annotation_templates(
    dev_cases: list[dict[str, Any]],
    labels_dir: Path = HUMAN_LABELS_DIR,
    *,
    overwrite_templates: bool = False,
) -> list[str]:
    """Write the 4 independent human-annotation CSV files with all annotation fields strictly empty."""
    case_ids = select_40_dev_annotation_cases(dev_cases)
    ann_headers = ["case_id", "annotator", "disposition", "confidence", "notes"]
    blank_rows = [[cid, "", "", "", ""] for cid in case_ids]

    _write_csv_if_unpopulated(
        labels_dir / "cases_to_annotate_annotator_1.csv",
        ann_headers,
        blank_rows,
        overwrite_templates=overwrite_templates,
    )
    _write_csv_if_unpopulated(
        labels_dir / "cases_to_annotate_annotator_2.csv",
        ann_headers,
        blank_rows,
        overwrite_templates=overwrite_templates,
    )
    _write_csv_if_unpopulated(labels_dir / "cases.csv", ann_headers, [], overwrite_templates=overwrite_templates)
    _write_csv_if_unpopulated(
        labels_dir / "adjudicated_cases.csv",
        ["case_id", "adjudicated_disposition", "acceptable_dispositions", "adjudicator", "resolution_notes"],
        [],
        overwrite_templates=overwrite_templates,
    )
    return case_ids


def _write_split_dir(target_dir: Path, cases: list[dict[str, Any]]) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    for old in target_dir.glob("CASE-V2-*.json"):
        old.unlink()
    for c in cases:
        out_file = target_dir / f"{c['case_id']}.json"
        out_file.write_text(json.dumps(c, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def compute_directory_sha256(*dirs: Path) -> str:
    h = hashlib.sha256()
    for d in dirs:
        for fp in sorted(d.glob("*.json")):
            h.update(fp.name.encode("utf-8"))
            h.update(b"\0")
            h.update(fp.read_bytes())
            h.update(b"\0")
    return h.hexdigest()


def build_dataset_v2(
    seed: int = DEFAULT_SEED,
    *,
    dev_dir: Path = DEV_DIR,
    held_out_dir: Path = HELD_OUT_DIR,
    challenge_dir: Path = CHALLENGE_DIR,
    labels_dir: Path = HUMAN_LABELS_DIR,
    summary_path: Path = SUMMARY_PATH,
) -> dict[str, Any]:
    """Deterministically build all 210 Golden v2 cases (`60` dev / `120` held-out / `30` challenge)."""
    # Guard: held-out and challenge must never be placed inside runtime `data/`!
    for eval_dir in (held_out_dir, challenge_dir):
        if "data" in eval_dir.resolve().parts and "eval" not in eval_dir.resolve().parts:
            raise ValueError(f"Refusing to write evaluation split inside runtime data/ directory: {eval_dir}")

    rng = random.Random(seed)
    dev_specs = _schedule_dev_specs(rng)
    held_specs = _schedule_held_out_specs(rng)
    chal_specs = _schedule_challenge_specs(rng)

    dev_cases = [
        generate_v2_case(rng, sp, idx, seed * 100_000 + idx, "dev", force_adversarial=False)
        for idx, sp in enumerate(dev_specs, start=1)
    ]
    held_cases = [
        generate_v2_case(rng, sp, idx, seed * 100_000 + idx, "held_out", force_adversarial=False)
        for idx, sp in enumerate(held_specs, start=101)
    ]
    chal_cases = [
        generate_v2_case(rng, sp, idx, seed * 100_000 + idx, "challenge", force_adversarial=True)
        for idx, sp in enumerate(chal_specs, start=301)
    ]

    all_cases = [*dev_cases, *held_cases, *chal_cases]
    assert_unique_fingerprints(all_cases)
    dev_purities = assert_kyc_purity_bounds(dev_cases)
    held_purities = assert_kyc_purity_bounds(held_cases)
    overall_purities = assert_kyc_purity_bounds(all_cases)

    _write_split_dir(dev_dir, dev_cases)
    _write_split_dir(held_out_dir, held_cases)
    _write_split_dir(challenge_dir, chal_cases)
    annotated_ids = write_human_annotation_templates(dev_cases, labels_dir=labels_dir)

    digest = compute_directory_sha256(dev_dir, held_out_dir, challenge_dir)
    summary = {
        "dataset_version": "golden_v2",
        "seed": seed,
        "counts": {
            "dev": len(dev_cases),
            "held_out": len(held_cases),
            "challenge": len(chal_cases),
            "total": len(all_cases),
        },
        "directories": {
            "dev": str(dev_dir.as_posix()),
            "held_out": str(held_out_dir.as_posix()),
            "challenge": str(challenge_dir.as_posix()),
        },
        "single_kyc_purities": {
            "dev": dev_purities,
            "held_out": held_purities,
            "overall": overall_purities,
        },
        "human_annotation_dev_cases": len(annotated_ids),
        "human_adjudication_status": "pending_human_annotations",
        "output_sha256": digest,
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Build AuditGuard Golden Dataset v2")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    summary = build_dataset_v2(seed=args.seed)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
