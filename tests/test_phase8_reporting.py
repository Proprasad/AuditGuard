"""
Phase 8 — Reporting, Reproducible Replay & Documentation Consistency Tests
(`tests/test_phase8_reporting.py`).

Verifies `docs/AGENT_GUIDE.md` §4 Phase 8 deliverables:
  1. `eval/report.py` generates `docs/evaluation_report.md` strictly from `summary.json` inputs
     with zero hand-typed numbers (verified via synthetic mutation test).
  2. Generated `docs/evaluation_report.md` matches the committed `eval/replay_bundle/` JSONs,
     includes mean ± 95% CI, anti-shortcut baselines, E2 security, Retrieval v2, calibration status,
     and an honest `Limitations` section.
  3. `Makefile` exposes `verify`, `replay`, and `report` targets.
  4. `README.md`, `docs/architecture.md`, and `docs/threat_model.md` match current AuditGuard v3
     code and include an honest Limitations / Residual Risks section without stale legacy claims.
"""

from __future__ import annotations

import json
from pathlib import Path

from eval.report import DEFAULT_BUNDLE_DIR, DEFAULT_REPORT_OUT, generate_evaluation_report


def test_report_generated_strictly_from_summary_json_no_hand_typed_numbers(tmp_path: Path) -> None:
    """Mutating a metric in `summary.json` must change the rendered report deterministically."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    toy_e1 = {
        "experiment_id": "E1_TOY",
        "split": "held_out",
        "n_cases": 12,
        "repeats": 1,
        "llm_mode": "replay",
        "run_id": "toy-run-1",
        "results": {
            "rule_engine": {
                "metrics": {
                    "execution_type": "deterministic",
                    "disposition_accuracy": 0.7777,
                    "macro_f1": 0.7654,
                    "weighted_error_cost": 0.4321,
                    "false_close_rate": 0.0123,
                    "evidence_recall": 0.5432,
                    "evidence_precision": 0.8765,
                    "replan_recovery_rate": 0.8123,
                    "needless_replan_rate": 0.1111,
                    "inr_arithmetic_error_rate": 0.0,
                    "citation_validity_rate": 1.0,
                    "tool_error_rate": 0.0,
                    "ci_95": {
                        "disposition_accuracy": {"mean": 0.7777, "ci_low": 0.6111, "ci_high": 0.9111},
                        "weighted_error_cost": {"mean": 0.4321, "ci_low": 0.2222, "ci_high": 0.6666},
                        "false_close_rate": {"mean": 0.0123, "ci_low": 0.0, "ci_high": 0.0555},
                    },
                    "percentiles": {
                        "cost_usd": {"p50": 0.0, "p95": 0.0},
                        "latency_s": {"p50": 0.12, "p95": 0.34},
                        "tool_calls": {"p50": 14.0, "p95": 15.0},
                    },
                    "per_family": {},
                }
            }
        },
        "paired_comparisons": [],
        "shortcut_baselines": {},
    }
    (bundle / "e1_held_out_det_summary.json").write_text(json.dumps(toy_e1), encoding="utf-8")
    out_md = tmp_path / "report.md"
    generate_evaluation_report(bundle_dir=bundle, output_path=out_md)
    text = out_md.read_text(encoding="utf-8")

    assert "77.8% [61.1%, 91.1%]" in text
    assert "0.4321 [0.2222, 0.6666]" in text
    assert "0.765" in text
    assert "Limitations" in text


def test_committed_evaluation_report_matches_replay_bundle_exactly(tmp_path: Path) -> None:
    """Committed `docs/evaluation_report.md` must match regenerating from `eval/replay_bundle/` bit-for-bit."""
    assert DEFAULT_BUNDLE_DIR.exists()
    assert DEFAULT_REPORT_OUT.exists()
    for fname in (
        "e1_held_out_det_summary.json",
        "e1_smoke_summary.json",
        "e2_security_summary.json",
        "retrieval_v2_summary.json",
        "calibration_status.json",
    ):
        assert (DEFAULT_BUNDLE_DIR / fname).exists(), f"Missing replay bundle artifact: {fname}"

    regen = tmp_path / "regen_eval_report.md"
    generate_evaluation_report(bundle_dir=DEFAULT_BUNDLE_DIR, output_path=regen)
    committed = DEFAULT_REPORT_OUT.read_text(encoding="utf-8")
    assert committed == regen.read_text(encoding="utf-8")

    for required_section in (
        "Artifact Provenance",
        "Headline Metrics (Mean ± 95% CI)",
        "Security Defenses Report",
        "Retrieval v2 Benchmark",
        "Cross-Family LLM Judge & Human Calibration Status",
        "Limitations & Pending `[HUMAN]` Sign-Offs",
    ):
        assert required_section in committed


def test_makefile_and_docs_aligned_with_v3_codebase() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    for target in ("verify:", "replay:", "report:"):
        assert target in makefile
    assert "eval.run_replay_suite" in makefile
    assert "eval.report" in makefile

    readme = Path("README.md").read_text(encoding="utf-8")
    assert "## Limitations" in readme
    assert "make verify" in readme and "make replay" in readme
    for stale in ("92-test", "35 dev + 28", "32-clause"):
        assert stale not in readme

    arch = Path("docs/architecture.md").read_text(encoding="utf-8")
    for component in ("OpenRouterClient", "CassetteStore", "corroboration.py", "Verifier v2", "165 Passages"):
        assert component in arch

    threat = Path("docs/threat_model.md").read_text(encoding="utf-8")
    assert "Residual Risks" in threat
    assert "INTERRUPT_NOT_ACTIVE" in threat
    assert "red_team_v2" in threat
