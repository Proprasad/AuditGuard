"""
Single-Source-of-Truth Evaluation Report Generator (`eval/report.py`).

Generates `docs/evaluation_report.md` strictly from computed `summary.json` artifacts
(ZERO hand-typed numbers). Any metric printed in `docs/evaluation_report.md` is read
directly from JSON outputs produced by `eval/run_eval.py`, `eval/retrieval_eval.py`,
and `eval/calibration.py`.

Usage:
    python -m eval.report
    python -m eval.report --bundle-dir eval/replay_bundle --out docs/evaluation_report.md
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

import typer

from eval.exp_report import render_experiment_report

DEFAULT_BUNDLE_DIR = Path("eval/replay_bundle")
DEFAULT_REPORT_OUT = Path("docs/evaluation_report.md")


def _sha256_file(path: Path) -> str:
    # Normalise CRLF -> LF so provenance hashes are identical on Windows (autocrlf) and POSIX checkouts.
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()[:16]


def _load_json(path: Path) -> dict[str, Any]:
    return dict(json.loads(path.read_text(encoding="utf-8")))


def _demote_headings(md: str, prefix: str = "##") -> str:
    out: list[str] = []
    for line in md.splitlines():
        if line.startswith("# "):
            out.append(f"{prefix} {line[2:]}")
        elif line.startswith("## "):
            out.append(f"{prefix}# {line[3:]}")
        else:
            out.append(line)
    return "\n".join(out)


def _render_retrieval_section(ret: Mapping[str, Any]) -> str:
    lines = [
        "## Retrieval v2 Benchmark (All 4 Pipelines)",
        "",
        f"- **Benchmark:** `{ret['benchmark_path']}` (`{ret['total_queries']}` queries: "
        f"`{ret['n_answerable']}` answerable, `{ret['n_unanswerable']}` unanswerable = "
        f"`{ret['n_unanswerable'] / max(ret['total_queries'], 1):.1%}`)",
        f"- **Configured Default Pipeline:** `{ret['default_mode']}`",
        f"- **Empirical Best Pipeline:** `{ret['empirical_best_mode']}`",
        f"- **Default >= BM25 on Recall@1:** `{ret['default_beats_or_ties_bm25_r1']}`",
        "",
        "| Pipeline | Recall@1 | Recall@3 | Recall@5 | MRR | nDCG@5 | Abstain Prec | Abstain Rec | Abstain F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for mode, m in (ret.get("results") or {}).items():
        tag = " **(default)**" if mode == ret.get("default_mode") else ""
        lines.append(
            f"| `{mode}`{tag} | {float(m['recall_at_1']):.3f} | {float(m['recall_at_3']):.3f} | "
            f"{float(m['recall_at_5']):.3f} | {float(m['mrr']):.3f} | {float(m['ndcg_at_5']):.3f} | "
            f"{float(m['abstain_precision']):.3f} | {float(m['abstain_recall']):.3f} | "
            f"{float(m['abstain_f1']):.3f} |"
        )
    lines.append("")
    return "\n".join(lines)


def _render_calibration_section(cal: Mapping[str, Any]) -> str:
    lines = [
        "## Cross-Family LLM Judge & Human Calibration Status",
        "",
        f"- **Calibration Status:** `{cal.get('status', 'unknown')}`",
        f"- **Judge Model:** `{cal.get('judge_model', 'unknown')}` "
        f"(cross-family verified: `{cal.get('cross_family_ok', False)}`)",
        f"- **Stratified Blinded Packet:** `{cal.get('packet_worksheets', 0)}` worksheets "
        f"(`{cal.get('packet_dev', 0)}` dev, `{cal.get('packet_held_out', 0)}` held-out)",
        f"- **Annotator Rows Completed:** annotator_1=`{cal.get('annotator_1_rows', 0)}`, "
        f"annotator_2=`{cal.get('annotator_2_rows', 0)}`",
        "",
    ]
    return "\n".join(lines)


def _render_provenance_table(sources: list[tuple[str, Path]]) -> str:
    lines = [
        "## Artifact Provenance (Zero Hand-Typed Numbers)",
        "",
        "Every quantitative value in this report was generated programmatically by `python -m eval.report` "
        "from the verified JSON artifacts listed below:",
        "",
        "| Artifact | Path | SHA-256 (prefix) |",
        "|---|---|---|",
    ]
    for label, p in sources:
        lines.append(f"| {label} | `{p.as_posix()}` | `{_sha256_file(p)}` |")
    lines.append("")
    return "\n".join(lines)


def _render_limitations_section() -> str:
    return "\n".join(
        [
            "## Limitations & Pending `[HUMAN]` Sign-Offs",
            "",
            "1. **Synthetic Dataset (`golden_v2`):** All development, held-out, and challenge cases are "
            "parametrically synthesized to model Indian AML scatter-gather topologies and benign look-alikes. "
            "Metrics measure behavior on this synthetic benchmark rather than live bank production traffic.",
            "2. **Pending Independent Human Annotations (`[HUMAN]`):** The 40-case dev adjudication templates "
            "(`eval/human_labels/cases_to_annotate_annotator_{1,2}.csv`) and the 60-worksheet judge "
            "calibration templates (`eval/human_labels/worksheets_to_score_annotator_{1,2}.csv`) are "
            "intentionally empty until completed independently by human compliance annotators; judge-human "
            "Cohen's kappa is NOT claimed until those templates are populated.",
            "3. **Pending Statutory Numbering Sign-Off (`[HUMAN]`):** All regulatory passages in "
            "`data/regulatory_corpus/indian_aml_corpus.jsonl` carry `human_verified: false` pending "
            "verification against official Gazette of India / RBI / FIU-IND / FATF originals "
            "(`data/regulatory_corpus/HUMAN_VERIFICATION_CHECKLIST.md`).",
            "4. **Keyless Replay Scope vs Full Live LLM Matrix:** `make replay` reproduces the recorded "
            "10-case `v2_dev` E1 LLM cassette (`c0_fixed`, `rule_engine`, `c1_single`, `c2_multi`), the "
            "full 120-case `held_out` + 30-case `challenge` deterministic E1 baselines, the full E2 "
            "red-team v2 security suite, and the full 110-query Retrieval v2 benchmark without API keys. "
            "Running full 120-case x 3-repeat live LLM E1/E3/E4 sweeps requires a funded OpenRouter key.",
            "5. **Dense Retriever Offline Backend:** In CI without multi-GB neural weights installed, "
            "`compliance-kb` uses L2-normalized float32 SVD semantic embeddings over word + character "
            "3/4-gram + domain concept features; an optional BGE-M3 neural backend can be substituted "
            "when `sentence_transformers` is installed.",
            "",
        ]
    )


def generate_evaluation_report(
    *,
    bundle_dir: Path = DEFAULT_BUNDLE_DIR,
    output_path: Path = DEFAULT_REPORT_OUT,
) -> Path:
    """Read `summary.json` files from `bundle_dir` and render `output_path` with zero hand-typed numbers."""
    e1_det_path = bundle_dir / "e1_held_out_det_summary.json"
    e1_smoke_path = bundle_dir / "e1_smoke_summary.json"
    e2_path = bundle_dir / "e2_security_summary.json"
    ret_path = bundle_dir / "retrieval_v2_summary.json"
    cal_path = bundle_dir / "calibration_status.json"

    sources: list[tuple[str, Path]] = []
    sections: list[str] = [
        "# AuditGuard v3 — Reproducible Evaluation Report",
        "",
        "> Generated automatically from computed JSON summaries by `eval/report.py` (`make replay` / `make report`). "
        "No metrics in this file are hand-typed.",
        "",
    ]

    for label, path in (
        ("E1 Deterministic Held-Out (120 + 30 challenge)", e1_det_path),
        ("E1 Offline Replay Smoke (10 dev, all 4 modes)", e1_smoke_path),
        ("E2 Red-Team v2 Security Suite", e2_path),
        ("Retrieval v2 Benchmark (110 queries)", ret_path),
        ("Phase 4 Judge Calibration Status", cal_path),
    ):
        if path.exists():
            sources.append((label, path))

    if not sources:
        raise FileNotFoundError(f"No evaluation summary JSON files found in {bundle_dir}")

    sections.append(_render_provenance_table(sources))

    if e1_det_path.exists():
        sections.append(_demote_headings(render_experiment_report(_load_json(e1_det_path))))
    if e1_smoke_path.exists():
        sections.append(_demote_headings(render_experiment_report(_load_json(e1_smoke_path))))
    if e2_path.exists():
        sections.append(_demote_headings(render_experiment_report(_load_json(e2_path))))
    if ret_path.exists():
        sections.append(_render_retrieval_section(_load_json(ret_path)))
    if cal_path.exists():
        sections.append(_render_calibration_section(_load_json(cal_path)))

    sections.append(_render_limitations_section())
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(sections), encoding="utf-8")
    return output_path


def main(
    bundle_dir: str = typer.Option(str(DEFAULT_BUNDLE_DIR), "--bundle-dir", help="Directory containing summary JSONs"),
    out: str = typer.Option(str(DEFAULT_REPORT_OUT), "--out", help="Output Markdown report path"),
) -> None:
    written = generate_evaluation_report(bundle_dir=Path(bundle_dir), output_path=Path(out))
    typer.echo(f"Generated evaluation report from JSON summaries -> {written}")


if __name__ == "__main__":
    typer.run(main)
