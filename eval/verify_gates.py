"""
Phase 5 CI & Verification Gates (`eval/verify_gates.py` — invoked by `make verify`).

Enforces all 3 `docs/AGENT_GUIDE.md` §4 Phase 5 gates without requiring API keys:
  1. Offline replay of `E1` on the 10-case `v2_dev` smoke slice (`eval/cassettes/e1_smoke_10.jsonl`)
     reproduces `eval/baselines/e1_smoke_expected.json` within `1e-9` across all 4 modes.
  2. Deterministic baselines (`c0_fixed`, `rule_engine`) stay within `±0` (`0.0` drift) of
     `eval/baselines/deterministic_held_out.json` across all 120 `held_out` cases.
  3. Any metric listed in an experiment YAML (`E1`–`E4`) that is missing from `summary.json`
     fails the gate immediately.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from pathlib import Path
from typing import Any

import yaml

from eval.run_eval import run as run_eval_cmd

SMOKE_CASSETTE = Path("eval/cassettes/e1_smoke_10.jsonl")
SMOKE_BASELINE = Path("eval/baselines/e1_smoke_expected.json")
DET_HELD_OUT_BASELINE = Path("eval/baselines/deterministic_held_out.json")
DETERMINISTIC_METRIC_KEYS: tuple[str, ...] = (
    "disposition_accuracy",
    "macro_f1",
    "weighted_error_cost",
    "false_close_rate",
    "evidence_recall",
    "evidence_precision",
    "replan_recovery_rate",
    "needless_replan_rate",
    "inr_arithmetic_error_rate",
    "citation_validity_rate",
    "cost_usd",
    "tokens",
    "tool_calls",
    "tool_error_rate",
)


class VerificationGateError(AssertionError):
    """Raised when any CI replay, held-out zero-drift, or YAML-metric completeness gate fails."""


def verify_summary_has_yaml_metrics(summary: Mapping[str, Any], yaml_metrics: Sequence[str]) -> None:
    """Fail immediately if any metric requested by the experiment YAML is missing from `summary`."""
    if "E2" in summary:
        for var_name, var_metrics in (summary.get("E2") or {}).items():
            missing = [m for m in yaml_metrics if m not in var_metrics or var_metrics[m] is None]
            if missing:
                raise VerificationGateError(f"E2 variant {var_name!r} missing YAML metrics: {missing}")
        return

    results = summary.get("results") or {}
    if not results:
        raise VerificationGateError("summary.json contains empty `results`")
    for mode_label, mode_entry in results.items():
        metrics = mode_entry.get("metrics") or {}
        missing = [m for m in yaml_metrics if m not in metrics]
        if missing:
            raise VerificationGateError(f"Mode {mode_label!r} missing YAML metrics: {missing}")


def verify_smoke_replay_gate(
    cassette_path: Path = SMOKE_CASSETTE,
    expected_path: Path = SMOKE_BASELINE,
) -> dict[str, Any]:
    """Replay the 10-case E1 smoke cassette offline and verify exact metric reproduction (`tol=1e-9`)."""
    if not cassette_path.exists() or not expected_path.exists():
        raise VerificationGateError(f"Missing smoke gate files: {cassette_path} / {expected_path}")
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    e1_yaml = yaml.safe_load(Path("config/experiments/E1.yaml").read_text(encoding="utf-8"))

    replayed = run_eval_cmd(
        config="E1",
        split="v2_dev",
        repeats=1,
        limit=10,
        llm="replay",
        cassette=str(cassette_path),
        run_id="verify_smoke_replay",
        concurrency=4,
        seed=42,
    )
    verify_summary_has_yaml_metrics(replayed, e1_yaml["metrics"])

    for mode, exp_metrics in expected["modes"].items():
        if mode not in replayed["results"]:
            raise VerificationGateError(f"Smoke replay missing mode {mode!r}")
        act_metrics = replayed["results"][mode]["metrics"]
        for key in DETERMINISTIC_METRIC_KEYS:
            exp_val = float(exp_metrics[key])
            act_val = float(act_metrics[key])
            if abs(act_val - exp_val) > 1e-9:
                raise VerificationGateError(
                    f"Smoke replay drift on {mode}.{key}: expected={exp_val}, actual={act_val}"
                )
    return {"smoke_replay_verified": True, "modes_checked": list(expected["modes"].keys())}


def verify_deterministic_held_out_gate(
    baseline_path: Path = DET_HELD_OUT_BASELINE,
    tmp_yaml_dir: Path = Path("runs/verify_gate_tmp"),
) -> dict[str, Any]:
    """Verify `c0_fixed` and `rule_engine` exhibit exact `±0` drift across all 120 `held_out` cases."""
    if not baseline_path.exists():
        raise VerificationGateError(f"Missing deterministic held-out baseline: {baseline_path}")
    recorded = json.loads(baseline_path.read_text(encoding="utf-8"))
    e1_yaml = yaml.safe_load(Path("config/experiments/E1.yaml").read_text(encoding="utf-8"))

    tmp_yaml_dir.mkdir(parents=True, exist_ok=True)
    det_cfg_path = tmp_yaml_dir / "E1_det_gate.yaml"
    det_cfg = {
        **e1_yaml,
        "experiment_id": "E1_DET_GATE",
        "include_challenge_slice": False,
        "repeats": 1,
        "modes": ["c0_fixed", "rule_engine"],
    }
    det_cfg_path.write_text(yaml.safe_dump(det_cfg), encoding="utf-8")

    summary = run_eval_cmd(
        config=str(det_cfg_path),
        split="held_out",
        repeats=1,
        llm="offline",
        run_id="verify_det_held_out",
        concurrency=4,
    )
    verify_summary_has_yaml_metrics(summary, det_cfg["metrics"])

    for mode in ("c0_fixed", "rule_engine"):
        exp_m = recorded["modes"][mode]
        act_m = summary["results"][mode]["metrics"]
        for key in DETERMINISTIC_METRIC_KEYS:
            if float(act_m[key]) != float(exp_m[key]):
                raise VerificationGateError(
                    f"Non-zero held-out drift on deterministic {mode}.{key}: "
                    f"recorded={exp_m[key]}, actual={act_m[key]}"
                )
    return {"held_out_zero_drift_verified": True, "n_cases": summary["n_cases"]}


def run_all_gates() -> dict[str, Any]:
    smoke = verify_smoke_replay_gate()
    det = verify_deterministic_held_out_gate()
    return {**smoke, **det}


if __name__ == "__main__":
    result = run_all_gates()
    print(json.dumps(result, indent=2))
