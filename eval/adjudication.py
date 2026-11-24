"""
Human Adjudication & Inter-Annotator Agreement Workflow (`docs/AGENT_GUIDE.md` §4 Phase 1.6).

Computes Cohen's kappa (`eval.judge.cohens_kappa`), agreement rate, and structured disagreement
records across two independent human annotators on the 40 dev cases in `eval/human_labels/`.
Never fabricates human annotations and never marks adjudication complete until all 40 pairs are
independently annotated and all disagreements have human-resolved rows in `adjudicated_cases.csv`.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from eval.judge import cohens_kappa

VALID_DISPOSITIONS = frozenset({"escalate_str", "close_benign", "request_info"})
DEFAULT_LABELS_DIR = Path("eval/human_labels")


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return [dict(r) for r in csv.DictReader(f)]


def _parse_annotator_sheet(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    parsed: dict[str, dict[str, str]] = {}
    for r in rows:
        cid = (r.get("case_id") or "").strip()
        disp = (r.get("disposition") or "").strip()
        ann = (r.get("annotator") or "").strip()
        if not cid or not disp:
            continue
        if disp not in VALID_DISPOSITIONS:
            raise ValueError(f"Invalid disposition {disp!r} for {cid}; expected one of {sorted(VALID_DISPOSITIONS)}")
        parsed[cid] = {
            "case_id": cid,
            "annotator": ann,
            "disposition": disp,
            "confidence": (r.get("confidence") or "").strip(),
            "notes": (r.get("notes") or "").strip(),
        }
    return parsed


def load_annotations(
    labels_dir: Path = DEFAULT_LABELS_DIR,
) -> tuple[list[str], dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """Load expected 40 dev case IDs and completed rows from annotator sheets or combined `cases.csv`."""
    sheet1_raw = _read_csv_rows(labels_dir / "cases_to_annotate_annotator_1.csv")
    sheet2_raw = _read_csv_rows(labels_dir / "cases_to_annotate_annotator_2.csv")
    expected_ids = [r["case_id"].strip() for r in sheet1_raw if (r.get("case_id") or "").strip()]

    ann1 = _parse_annotator_sheet(sheet1_raw)
    ann2 = _parse_annotator_sheet(sheet2_raw)

    combined = _read_csv_rows(labels_dir / "cases.csv")
    if combined and not (ann1 and ann2):
        by_case: dict[str, list[dict[str, str]]] = {}
        for r in combined:
            cid = (r.get("case_id") or "").strip()
            disp = (r.get("disposition") or "").strip()
            if cid and disp:
                if disp not in VALID_DISPOSITIONS:
                    raise ValueError(f"Invalid disposition {disp!r} in cases.csv for {cid}")
                by_case.setdefault(cid, []).append(r)
        for cid, items in by_case.items():
            if len(items) >= 1 and cid not in ann1:
                ann1[cid] = items[0]
            if len(items) >= 2 and cid not in ann2:
                ann2[cid] = items[1]

    return expected_ids, ann1, ann2


def evaluate_adjudication_status(labels_dir: Path = DEFAULT_LABELS_DIR) -> dict[str, Any]:
    """Compute Cohen's kappa, disagreements, and honest completion status for Phase 1.6."""
    expected_ids, ann1, ann2 = load_annotations(labels_dir)
    paired_ids = sorted(set(ann1) & set(ann2))
    adjudicated_rows = {
        r["case_id"].strip(): r
        for r in _read_csv_rows(labels_dir / "adjudicated_cases.csv")
        if (r.get("case_id") or "").strip() and (r.get("adjudicated_disposition") or "").strip()
    }

    if not paired_ids:
        return {
            "status": "awaiting_human_annotations",
            "adjudication_complete": False,
            "target_cases": len(expected_ids),
            "annotator_1_completed": len(ann1),
            "annotator_2_completed": len(ann2),
            "paired_cases": 0,
            "cohens_kappa": None,
            "raw_agreement": None,
            "disagreements": [],
            "unresolved_disagreements": [],
        }

    labels_a = [ann1[cid]["disposition"] for cid in paired_ids]
    labels_b = [ann2[cid]["disposition"] for cid in paired_ids]
    kappa = round(cohens_kappa(labels_a, labels_b), 4)
    agree = round(sum(1 for a, b in zip(labels_a, labels_b, strict=True) if a == b) / len(paired_ids), 4)

    disagreements = [
        {
            "case_id": cid,
            "annotator_1": ann1[cid].get("annotator", ""),
            "disposition_1": ann1[cid]["disposition"],
            "notes_1": ann1[cid].get("notes", ""),
            "annotator_2": ann2[cid].get("annotator", ""),
            "disposition_2": ann2[cid]["disposition"],
            "notes_2": ann2[cid].get("notes", ""),
            "adjudicated_disposition": (adjudicated_rows.get(cid) or {}).get("adjudicated_disposition"),
        }
        for cid in paired_ids
        if ann1[cid]["disposition"] != ann2[cid]["disposition"]
    ]
    unresolved = [d["case_id"] for d in disagreements if not d["adjudicated_disposition"]]
    all_expected_paired = bool(expected_ids) and set(expected_ids) <= set(paired_ids)
    complete = all_expected_paired and not unresolved

    return {
        "status": "complete" if complete else "in_progress",
        "adjudication_complete": complete,
        "target_cases": len(expected_ids),
        "annotator_1_completed": len(ann1),
        "annotator_2_completed": len(ann2),
        "paired_cases": len(paired_ids),
        "cohens_kappa": kappa,
        "raw_agreement": agree,
        "disagreements": disagreements,
        "unresolved_disagreements": unresolved,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect AuditGuard Phase 1.6 human annotation & kappa status")
    parser.add_argument("--labels-dir", type=Path, default=DEFAULT_LABELS_DIR)
    args = parser.parse_args()
    print(json.dumps(evaluate_adjudication_status(args.labels_dir), indent=2))


if __name__ == "__main__":
    main()
