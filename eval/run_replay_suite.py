"""
Keyless Offline Replay Suite (`eval/run_replay_suite.py` — invoked by `make replay`).

Reproduces the entire AuditGuard v3 evaluation bundle without any live API keys:
  1. E1 offline cassette replay on the 10-case `v2_dev` smoke slice (`eval/cassettes/e1_smoke_10.jsonl`)
  2. E1 deterministic held-out (`120` held-out + `30` challenge) for `c0_fixed` and `rule_engine`
  3. E2 Security Red-Team v2 (`132` attacks + `320` benign memos + end-to-end agent poisoning)
  4. Retrieval v2 Benchmark (`110` queries across all 4 pipelines)
  5. Phase 4 Cross-Family Judge calibration status check (honest `awaiting_human_annotations` when empty)
  6. Regenerates `docs/evaluation_report.md` strictly from the produced JSON summaries via `eval/report.py`.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Any

import yaml

from eval.calibration import run_calibration
from eval.report import DEFAULT_BUNDLE_DIR, DEFAULT_REPORT_OUT, generate_evaluation_report
from eval.retrieval_eval import run_retrieval_benchmark
from eval.run_eval import run as run_eval_cmd
from eval.verify_gates import SMOKE_CASSETTE, verify_summary_has_yaml_metrics


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_replay_suite(
    *,
    bundle_dir: Path = DEFAULT_BUNDLE_DIR,
    report_out: Path = DEFAULT_REPORT_OUT,
) -> dict[str, Any]:
    """Execute the full offline keyless replay suite and regenerate `docs/evaluation_report.md`."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    e1_yaml = yaml.safe_load(Path("config/experiments/E1.yaml").read_text(encoding="utf-8"))
    e2_yaml = yaml.safe_load(Path("config/experiments/E2.yaml").read_text(encoding="utf-8"))

    # 1. E1 Offline Replay Smoke (10 dev cases, all 4 modes from recorded cassette)
    e1_smoke = run_eval_cmd(
        config="E1",
        split="v2_dev",
        repeats=1,
        limit=10,
        llm="replay",
        cassette=str(SMOKE_CASSETTE),
        run_id="replay_e1_smoke",
        concurrency=4,
        seed=42,
    )
    verify_summary_has_yaml_metrics(e1_smoke, e1_yaml["metrics"])
    _write_json(bundle_dir / "e1_smoke_summary.json", e1_smoke)

    # 2. E1 Deterministic Held-Out (120 held_out + 30 challenge cases, offline)
    det_cfg_path = bundle_dir / "_e1_det_held_out.yaml"
    det_cfg = {
        **e1_yaml,
        "experiment_id": "E1_HELD_OUT_DET",
        "include_challenge_slice": True,
        "repeats": 1,
        "modes": ["c0_fixed", "rule_engine"],
    }
    det_cfg_path.write_text(yaml.safe_dump(det_cfg), encoding="utf-8")
    e1_det = run_eval_cmd(
        config=str(det_cfg_path),
        split="held_out",
        repeats=1,
        llm="offline",
        run_id="replay_e1_held_out_det",
        concurrency=4,
    )
    verify_summary_has_yaml_metrics(e1_det, e1_yaml["metrics"])
    _write_json(bundle_dir / "e1_held_out_det_summary.json", e1_det)
    det_cfg_path.unlink(missing_ok=True)

    # 3. E2 Security Red-Team v2 (132 attacks + 320 benign memos + E2E poisoning)
    e2_res = run_eval_cmd(
        config="E2",
        split="held_out",
        repeats=1,
        llm="offline",
        run_id="replay_e2_security",
        concurrency=4,
    )
    verify_summary_has_yaml_metrics(e2_res, e2_yaml["metrics"])
    _write_json(bundle_dir / "e2_security_summary.json", e2_res)

    # 4. Retrieval v2 Benchmark (110 queries, all 4 pipelines)
    ret_res = run_retrieval_benchmark()
    _write_json(bundle_dir / "retrieval_v2_summary.json", ret_res)

    # 5. Phase 4 Judge Calibration Status (offline check against human annotation CSVs)
    with tempfile.TemporaryDirectory(prefix="auditguard_cal_") as cal_tmp:
        cal_raw = run_calibration(out_dir=Path(cal_tmp))
    fam = (cal_raw.get("bias_checks") or {}).get("self_preference_check") or {}
    cal_summary = {
        "status": str(cal_raw.get("status", "awaiting_human_annotations")),
        "judge_model": str(fam.get("judge_model", "google/gemini-3.1-flash-lite")),
        "cross_family_ok": bool(fam.get("cross_family_verified", False)),
        "packet_worksheets": int(cal_raw.get("target_total_worksheets", 0)),
        "packet_dev": int(cal_raw.get("target_dev_worksheets", 0)),
        "packet_held_out": int(cal_raw.get("target_held_out_worksheets", 0)),
        "annotator_1_rows": int(cal_raw.get("annotator_1_completed", 0)),
        "annotator_2_rows": int(cal_raw.get("annotator_2_completed", 0)),
    }
    _write_json(bundle_dir / "calibration_status.json", cal_summary)

    # 6. Generate docs/evaluation_report.md strictly from JSON summaries
    written = generate_evaluation_report(bundle_dir=bundle_dir, output_path=report_out)
    return {
        "bundle_dir": str(bundle_dir),
        "report_path": str(written),
        "e1_smoke_cases": e1_smoke["n_cases"],
        "e1_held_out_cases": e1_det["n_cases"],
        "e2_attacks": e2_res["E2"]["defenses_on"]["red_team_total"],
        "retrieval_queries": ret_res["total_queries"],
        "calibration_status": cal_summary["status"],
    }


if __name__ == "__main__":
    out = run_replay_suite()
    print(json.dumps(out, indent=2))
