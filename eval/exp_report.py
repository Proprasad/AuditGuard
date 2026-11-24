"""
Markdown Report Formatter for `eval/run_eval.py` (`eval/exp_report.py`).

Generates `runs/<run_id>/report.md` strictly from computed `summary` dictionaries
(zero hand-typed numbers), rendering Wilson & 10k cluster-bootstrap 95% CIs,
p50/p95 resource percentiles, paired cluster-bootstrap + McNemar comparisons,
per-family / challenge breakdowns, and anti-shortcut baselines.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Optional


def _fmt_ci(ci_obj: Mapping[str, Any] | None, *, pct: bool = False, money: bool = False) -> str:
    if not ci_obj:
        return "N/A"
    m, lo, hi = float(ci_obj["mean"]), float(ci_obj["ci_low"]), float(ci_obj["ci_high"])
    if pct:
        return f"{m * 100:.1f}% [{lo * 100:.1f}%, {hi * 100:.1f}%]"
    if money:
        return f"\\${m:.4f} [\\${lo:.4f}, \\${hi:.4f}]"
    return f"{m:.4f} [{lo:.4f}, {hi:.4f}]"


def render_e2_report(summary: Mapping[str, Any]) -> str:
    lines = [
        f"# AuditGuard Experiment `{summary.get('experiment_id', 'E2')}` — Security Defenses Report",
        "",
        f"- **Split:** `{summary.get('split')}`",
        f"- **Red-Team Suite:** `{summary.get('red_team_version', 'v2')}`",
        "",
        "## 1. Defenses OFF vs Defenses ON (Mean & Wilson 95% CI)",
        "",
        "| Variant | Red-Team ASR (95% CI) | Block Rate | Benign False-Block Rate (95% CI) "
        "| Unauth Writes | PII Leaks | End-to-End Agent ASR |",
        "|---|---|---|---|---:|---:|---|",
    ]
    for v_name, res in (summary.get("E2") or {}).items():
        asr_ci = _fmt_ci(res.get("attack_success_rate_ci"), pct=True)
        fbr_ci = _fmt_ci(res.get("false_block_rate_ci"), pct=True)
        e2e = res.get("end_to_end_asr")
        e2e_str = f"{float(e2e) * 100:.1f}%" if e2e is not None else "N/A"
        lines.append(
            f"| `{v_name}` | {asr_ci} | {float(res['attack_block_rate']) * 100:.1f}% "
            f"({res['blocked']}/{res['red_team_total']}) | {fbr_ci} "
            f"({res['false_blocks']}/{res['clean_cases_checked']}) | "
            f"{res['unauthorized_write_attempts']} | {res['pii_leakage_count']} | {e2e_str} |"
        )
    lines.append("")
    return "\n".join(lines)


def _render_headline_table(results: Mapping[str, Any]) -> list[str]:
    lines = [
        "## 1. Headline Metrics (Mean ± 95% CI)",
        "",
        "| Configuration | Type | Accuracy (95% CI) | Macro-F1 | Weighted Error Cost (95% CI) "
        "| False-Close Rate (95% CI) | Evidence Recall | Evidence Precision |",
        "|---|---|---|---:|---|---|---:|---:|",
    ]
    for label, entry in results.items():
        m = entry["metrics"]
        ci = m.get("ci_95") or {}
        lines.append(
            f"| `{label}` | `{m.get('execution_type', 'llm')}` | "
            f"{_fmt_ci(ci.get('disposition_accuracy'), pct=True)} | {float(m.get('macro_f1', 0.0)):.3f} | "
            f"{_fmt_ci(ci.get('weighted_error_cost'))} | {_fmt_ci(ci.get('false_close_rate'), pct=True)} | "
            f"{float(m['evidence_recall']) * 100:.1f}% | {float(m.get('evidence_precision', 0.0)) * 100:.1f}% |"
        )
    lines.extend(
        [
            "",
            "## 2. Replanning, Verification & Resource Percentiles (`p50` / `p95`)",
            "",
            "| Configuration | Replan Recovery | Needless Replan | INR Math Err | Citation Valid "
            "| Cost USD (p50 / p95) | Latency s (p50 / p95) | Tool Calls (p50 / p95) | Tool Err Rate |",
            "|---|---:|---:|---:|---:|---|---|---|---:|",
        ]
    )
    for label, entry in results.items():
        m = entry["metrics"]
        pcts = m.get("percentiles") or {}
        c_p = pcts.get("cost_usd") or {"p50": 0.0, "p95": 0.0}
        l_p = pcts.get("latency_s") or {"p50": 0.0, "p95": 0.0}
        t_p = pcts.get("tool_calls") or {"p50": 0.0, "p95": 0.0}
        lines.append(
            f"| `{label}` | {float(m['replan_recovery_rate']) * 100:.1f}% | "
            f"{float(m.get('needless_replan_rate', 0.0)) * 100:.1f}% | "
            f"{float(m['inr_arithmetic_error_rate']) * 100:.2f}% | "
            f"{float(m['citation_validity_rate']) * 100:.1f}% | "
            f"\\${c_p['p50']:.4f} / \\${c_p['p95']:.4f} | "
            f"{l_p['p50']:.2f}s / {l_p['p95']:.2f}s | "
            f"{t_p['p50']:.1f} / {t_p['p95']:.1f} | "
            f"{float(m.get('tool_error_rate', 0.0)) * 100:.2f}% |"
        )
    return lines


def _render_comparisons_and_shortcuts(summary: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    comparisons = summary.get("paired_comparisons") or []
    if comparisons:
        lines.extend(
            [
                "",
                "## 3. Paired Cluster-Bootstrap (10k) & Exact McNemar Comparisons",
                "",
                "*Pre-registered rule: no configuration claims `outperforms` unless the paired 95% CI excludes `0`.*",
                "",
                "| Pair (`A vs B`) | Acc Diff (95% CI) | Acc Verdict | McNemar p | Error-Cost Diff (95% CI) "
                "| Error-Cost Verdict | Cohen's d (Cost) |",
                "|---|---|---|---:|---|---|---:|",
            ]
        )
        for comp in comparisons:
            ad = comp["accuracy_bootstrap"]
            ed = comp["error_cost_bootstrap"]
            mc = comp["mcnemar"]
            lines.append(
                f"| `{comp['pair']}` | {ad['diff_a_minus_b']:+.4f} [{ad['ci_low']:+.4f}, {ad['ci_high']:+.4f}] | "
                f"`{ad['verdict']}` | {mc['p_value_exact']:.4f} | "
                f"{ed['diff_a_minus_b']:+.4f} [{ed['ci_low']:+.4f}, {ed['ci_high']:+.4f}] | "
                f"`{ed['verdict']}` | {ed['cohens_d']:+.3f} |"
            )

    shortcuts = summary.get("shortcut_baselines")
    if isinstance(shortcuts, Mapping) and shortcuts.get("target"):
        lines.extend(
            [
                "",
                "## 4. Anti-Shortcut Reference Baselines (`eval/shortcuts.py`)",
                "",
                "| Shortcut Baseline | Dev Accuracy | Target Split Accuracy |",
                "|---|---:|---:|",
            ]
        )
        dev_s = shortcuts.get("dev") or {}
        for b_name, b_vals in shortcuts["target"].items():
            d_acc = float((dev_s.get(b_name) or {}).get("accuracy", 0.0))
            t_acc = float(b_vals.get("accuracy", 0.0))
            lines.append(f"| `{b_name}` | {d_acc * 100:.1f}% | {t_acc * 100:.1f}% |")
    return lines


def _render_family_and_challenge(summary: Mapping[str, Any]) -> list[str]:
    lines = ["", "## 5. Per-Family Breakdown (`disposition_accuracy` / `weighted_error_cost`)", ""]
    results = summary.get("results") or {}
    families = sorted(
        {fam for entry in results.values() for fam in (entry["metrics"].get("per_family") or {}).keys()}
    )
    if families:
        hdr = "| Family | " + " | ".join(f"`{lbl}`" for lbl in results) + " |"
        sep = "|---|" + "|".join("---:" for _ in results) + "|"
        lines.extend([hdr, sep])
        for fam in families:
            cells = []
            for entry in results.values():
                pf = (entry["metrics"].get("per_family") or {}).get(fam)
                if pf:
                    cells.append(f"{pf['disposition_accuracy'] * 100:.1f}% / {pf['weighted_error_cost']:.2f}")
                else:
                    cells.append("N/A")
            lines.append(f"| `{fam}` | " + " | ".join(cells) + " |")

    chal = summary.get("challenge_slice")
    if isinstance(chal, Mapping) and chal:
        lines.extend(
            [
                "",
                "## 6. Adversarial Challenge Slice (`30` Cases)",
                "",
                "| Configuration | Accuracy (95% CI) | Weighted Error Cost (95% CI) | False-Close Rate |",
                "|---|---|---|---|",
            ]
        )
        for lbl, c_entry in chal.items():
            cm = c_entry["metrics"]
            ci = cm.get("ci_95") or {}
            lines.append(
                f"| `{lbl}` | {_fmt_ci(ci.get('disposition_accuracy'), pct=True)} | "
                f"{_fmt_ci(ci.get('weighted_error_cost'))} | {float(cm['false_close_rate']) * 100:.1f}% |"
            )
    lines.append("")
    return lines


def render_experiment_report(summary: Mapping[str, Any]) -> str:
    """Render complete Markdown report from `summary.json` dictionary."""
    if "E2" in summary:
        return render_e2_report(summary)
    lines = [
        f"# AuditGuard Experiment `{summary.get('experiment_id')}` Report",
        "",
        f"- **Split:** `{summary.get('split')}` (`n={summary.get('n_cases', 0)}` cases)",
        f"- **Configured LLM Repeats:** `{summary.get('repeats')}` (`llm_mode={summary.get('llm_mode')}`)",
        f"- **Run ID:** `{summary.get('run_id')}`",
        "",
    ]
    lines.extend(_render_headline_table(summary.get("results") or {}))
    lines.extend(_render_comparisons_and_shortcuts(summary))
    lines.extend(_render_family_and_challenge(summary))
    return "\n".join(lines)


def write_run_artifacts(run_dir: Path, summary: dict[str, Any], extra_output: Optional[str] = None) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (run_dir / "report.md").write_text(render_experiment_report(summary), encoding="utf-8")
    if extra_output:
        Path(extra_output).parent.mkdir(parents=True, exist_ok=True)
        Path(extra_output).write_text(json.dumps(summary, indent=2), encoding="utf-8")
