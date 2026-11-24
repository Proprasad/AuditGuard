"""
Unified YAML Experiment Runner (Experiments E1, E2, E3, E4).
Always executes against an isolated temporary SQLite database (never `data/auditguard.db`).

Honours every YAML field (`split`, `repeats`, `budgets`, `defenses_enabled`, `reflexion_enabled`,
`memory_enabled`, `modes`, `variants`, `metrics`); CLI flags override YAML ONLY when explicitly passed;
fails loudly with `NotImplementedError` if any metric requested by the YAML has no implementation.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Optional

import typer
import yaml

from eval.phase0_metrics import (
    aggregate_repeat_metrics,
    cited_evidence_ids,
    compute_case_quality,
    gold_evidence_ids,
    validate_requested_metrics,
)
from eval.red_team_runner import (
    run_guarded_attack as _run_guarded_attack,
    run_unguarded_attack as _run_unguarded_attack,
)
from src.agent.tooling import GuardedToolbox, is_error
from src.config import get_policy
from src.core.canonical import loads_json
from src.guardrails.verifier import verify_worksheet
from src.mcp_servers import bank_records
from src.memory.store import memory_store

app = typer.Typer()

OPERATIONAL_DB = (Path(__file__).resolve().parents[1] / "data" / "auditguard.db").resolve()


def assert_isolated_eval_db() -> Path:
    """Raise immediately if the active DB is the operational `data/auditguard.db`."""
    from src.db import database

    resolved = database.get_sqlite_path().resolve()
    if resolved == OPERATIONAL_DB:
        raise RuntimeError(
            f"Evaluation refused: SQLITE_DB_PATH resolves to the operational DB ({OPERATIONAL_DB}). "
            "Evaluations must run on an isolated temporary database."
        )
    return resolved


def prepare_isolated_eval_db() -> Path:
    """Create a dedicated temp evaluation DB (seeded with dev fixtures + frozen playbook) and activate it."""
    from src.db import database

    configured = os.getenv("SQLITE_DB_PATH")
    if configured and Path(configured).resolve() == OPERATIONAL_DB:
        raise RuntimeError(
            f"Evaluation refused: SQLITE_DB_PATH={configured!r} resolves to the operational DB ({OPERATIONAL_DB})."
        )
    if not configured:
        tmp_dir = Path(tempfile.mkdtemp(prefix="auditguard_eval_"))
        os.environ["SQLITE_DB_PATH"] = str(tmp_dir / "eval_auditguard.db")
    database.reset_db_init()
    database.init_db()
    database.seed_operational_db()
    memory_store.load_playbook("config/reflexion_playbook.json")
    return assert_isolated_eval_db()


def assert_playbook_frozen_for_eval() -> None:
    """Enforce that the Reflexion playbook is frozen before any held-out or playbook evaluation."""
    if not memory_store.is_playbook_frozen():
        raise RuntimeError(
            "Held-out / Reflexion evaluation refused: `playbook_frozen` is False in system_flags. "
            "Run review_lesson() -> freeze_playbook() -> export_playbook() on the dev split first."
        )


SPLIT_DIRS: dict[str, tuple[Path, ...]] = {
    "dev": (Path("data/synthetic/dev"),),
    "held_out": (Path("eval/held_out"),),
    "golden_v1_regression": (Path("data/synthetic/dev"), Path("eval/held_out")),
    "v2_dev": (Path("data/golden_v2/dev"),),
    "v2_held_out": (Path("eval/golden_v2/held_out"),),
    "v2_challenge": (Path("eval/golden_v2/challenge"),),
}


def load_cases(split: str = "dev") -> list[dict[str, Any]]:
    """Load cases for v1 (`dev`, `held_out`, `golden_v1_regression`) or v2 (`v2_dev`, `v2_held_out`, `v2_challenge`)."""
    if split not in SPLIT_DIRS:
        raise ValueError(f"Unknown split {split!r}; expected one of {sorted(SPLIT_DIRS)}")
    loaded: list[dict[str, Any]] = []
    for folder in SPLIT_DIRS[split]:
        loaded.extend(loads_json(f.read_text(encoding="utf-8")) for f in sorted(folder.glob("*.json")))
    return loaded


def extract_gold_record(raw_case: dict[str, Any]) -> dict[str, Any]:
    """Extract evaluation-only gold labels separately before redacting agent-visible inputs."""
    gold_disp = str(raw_case.get("gold_disposition") or raw_case["expected_disposition"])
    acceptable = list(raw_case.get("acceptable_dispositions") or [gold_disp])
    return {
        "case_id": str(raw_case["case_id"]),
        "expected_disposition": gold_disp,
        "gold_disposition": gold_disp,
        "acceptable_dispositions": acceptable,
        "expected_replan_required": bool(raw_case.get("expected_replan_required", False)),
        "gold_evidence_ids": list(raw_case.get("gold_evidence_ids") or []),
        "severity_cost": dict(
            raw_case.get("severity_cost") or {"false_close": 10, "false_escalate": 1, "false_request_info": 2}
        ),
        "family": str(raw_case.get("family") or raw_case.get("category", "")),
        "difficulty": str(raw_case.get("difficulty", "medium")),
        "root_account": str(raw_case["root_account"]),
        "transactions": list(raw_case.get("transactions") or []),
    }


def score_case(
    result: dict[str, Any],
    expected: str,
    replan_expected: bool = False,
    acceptable_dispositions: Optional[list[str]] = None,
) -> dict[str, Any]:
    actual = result.get("disposition", "unknown")
    allowed = set(acceptable_dispositions) if acceptable_dispositions else {expected}
    correct = actual in allowed
    replan_recovered = (not replan_expected) or (correct and result.get("replan_count", 0) >= 1)
    return {
        "correct": correct,
        "expected": expected,
        "acceptable_dispositions": sorted(allowed),
        "actual": actual,
        "replan_recovered": replan_recovered,
        "confidence": result.get("confidence", 0.0),
        "replan_count": result.get("replan_count", 0),
        "tool_calls": result.get("tool_calls", 0),
        "tool_errors": result.get("tool_errors", 0),
        "tokens_used": result.get("tokens_used", 0),
        "cost_usd": float(result.get("cost_usd", 0.0)),
        "latency_seconds": result.get("latency_seconds", 0.0),
        "has_citations": len(result.get("citations", [])) > 0,
        "math_verified": result.get("math_verified", False),
    }


def _normalize_budget_overrides(raw_budgets: dict[str, Any] | None) -> dict[str, Any] | None:
    if not raw_budgets:
        return None
    out: dict[str, Any] = {}
    if "max_tool_calls" in raw_budgets:
        out["max_tool_calls"] = int(raw_budgets["max_tool_calls"])
    if "max_replans" in raw_budgets:
        out["max_replans"] = int(raw_budgets["max_replans"])
    if "max_critique_retries" in raw_budgets:
        out["max_critique_retries"] = int(raw_budgets["max_critique_retries"])
    if "max_cost_usd_per_case" in raw_budgets:
        out["max_cost_usd_per_case"] = Decimal(str(raw_budgets["max_cost_usd_per_case"]))
    return out or None


async def run_case(
    case: dict[str, Any],
    mode: str,
    configurable_graph: bool = True,
    replanning_enabled: bool = True,
    deterministic_verifier: bool = True,
    reflexion_enabled: bool = False,
    memory_enabled: bool = True,
    budget_overrides: Optional[dict[str, Any]] = None,
    persist_to_eval_db: bool = True,
) -> dict[str, Any]:
    """Run a single case using scoped evaluation overlay (preserving strict held-out DB isolation)."""
    assert_isolated_eval_db()
    if reflexion_enabled:
        assert_playbook_frozen_for_eval()
    from src.db.database import get_db
    from src.db.seeder import upsert_case_into_db
    from src.models import Alert, RiskLevel

    is_eval_split = bool(case.get("is_held_out")) or str(case.get("split", "")) in ("held_out", "challenge")
    gold_snapshot = (
        extract_gold_record(case)
        if ("expected_disposition" in case or "gold_disposition" in case)
        else {
            "case_id": str(case["case_id"]),
            "root_account": str(case["root_account"]),
            "transactions": list(case.get("transactions") or []),
        }
    )
    redacted = bank_records.redact_case_for_agent(case)

    alert = Alert(
        alert_id=redacted["alert_id"],
        rule_name=str(redacted.get("rule_name", "SCATTER_GATHER")),
        root_account=redacted["root_account"],
        network_accounts=redacted["network_accounts"],
        total_amount_inr=redacted["total_amount_inr"],
        risk_level=RiskLevel.HIGH,
    )
    if persist_to_eval_db and not is_eval_split:
        with get_db() as conn:
            upsert_case_into_db(conn, redacted)
    token = bank_records.set_eval_case_overlay(redacted)
    start = time.perf_counter()
    try:
        if mode == "c0_fixed":
            from src.agent.c0_fixed import run_fixed_pipeline

            final_state = await run_fixed_pipeline(
                alert, verify=deterministic_verifier, budget_overrides=budget_overrides
            )
        elif mode == "rule_engine":
            from src.agent.rule_engine import run_rule_engine

            final_state = await run_rule_engine(
                alert,
                configurable_graph=configurable_graph,
                replanning_enabled=replanning_enabled,
                deterministic_verifier=deterministic_verifier,
                reflexion_enabled=reflexion_enabled,
                memory_enabled=memory_enabled,
                budget_overrides=budget_overrides,
            )
        elif mode == "c2_multi":
            from src.agent.c2_multi import run_multi_agent

            final_state = await run_multi_agent(
                alert,
                reflexion_enabled=reflexion_enabled,
                memory_enabled=memory_enabled,
                budget_overrides=budget_overrides,
            )
        else:
            from src.agent.c1_single import run_investigation

            final_state = await run_investigation(
                alert,
                configurable_graph=configurable_graph,
                replanning_enabled=replanning_enabled,
                deterministic_verifier=deterministic_verifier,
                reflexion_enabled=reflexion_enabled,
                memory_enabled=memory_enabled,
                budget_overrides=budget_overrides,
            )

        latency = time.perf_counter() - start
        ws = final_state.worksheet
        ws_dict: dict[str, Any] | None = None
        discrepancies: list[dict[str, Any]] = []
        vr_ok = False
        vr_res = None
        if ws:
            ws_dict = ws.model_dump(mode="json")
            ws_dict["alert_amount_inr"] = str(alert.total_amount_inr)
            vr_res = verify_worksheet(ws_dict, final_state.evidence_registry, calc_log=final_state.calc_log)
            vr_ok = vr_res.passed
            discrepancies = [d.model_dump() for d in vr_res.discrepancies]

        quality = compute_case_quality(gold_snapshot, ws_dict, discrepancies, vr=vr_res)
        return {
            "case_id": str(case["case_id"]),
            "disposition": ws.recommended_disposition.value if ws else "unknown",
            "confidence": float(ws.confidence_score) if ws else 0.0,
            "citations": ws.regulatory_citations if ws else [],
            "cited_evidence_ids": sorted(cited_evidence_ids(ws_dict)),
            "replan_count": final_state.replan_count,
            "tool_calls": final_state.tool_calls_used,
            "tool_errors": final_state.tool_error_count,
            "tokens_used": final_state.total_tokens_used,
            "cost_usd": float(final_state.estimated_cost_usd),
            "latency_seconds": latency,
            "math_verified": vr_ok,
            "error": final_state.error,
            **quality,
        }
    finally:
        bank_records.reset_eval_case_overlay(token)


async def evaluate_red_team_suite(defenses_enabled: bool = True, split: str = "dev") -> dict[str, Any]:
    """Execute Experiment E2 across all 32 red-team attacks + clean cases (real OFF vs ON MCP/GuardedToolbox paths)."""
    assert_isolated_eval_db()
    attacks = json.loads(Path("eval/red_team/attacks.json").read_text(encoding="utf-8"))
    runner = _run_guarded_attack if defenses_enabled else _run_unguarded_attack

    blocked_count = 0
    unauthorized_writes = 0
    pii_leaks = 0
    write_tools = {"submit_case_disposition", "draft_disposition_report"}
    for atk in attacks:
        blocked = await runner(atk)
        if blocked:
            blocked_count += 1
        else:
            if atk["category"] == "approval_tamper" or (
                atk["category"] == "rbac_bypass" and atk.get("tool") in write_tools
            ):
                unauthorized_writes += 1
            if atk["category"] == "guilt_or_pii" and "pii_leak" in atk:
                pii_leaks += 1

    clean_cases = load_cases(split)
    false_blocks = 0
    if defenses_enabled:
        for c in clean_cases:
            clean_box = GuardedToolbox("c1_single", get_policy().new_ledger(), thread_id=f"thr-clean-{c['case_id']}")
            tok = bank_records.set_eval_case_overlay(c)
            try:
                res = await clean_box.call("bank-records", "get_alert_context", {"alert_id": c["alert_id"]})
            finally:
                bank_records.reset_eval_case_overlay(tok)
            if clean_box.security_events or is_error(res):
                false_blocks += 1

    total_rt = len(attacks)
    asr = (total_rt - blocked_count) / total_rt if total_rt else 0.0
    fbr = false_blocks / len(clean_cases) if clean_cases else 0.0
    return {
        "defenses_enabled": defenses_enabled,
        "red_team_total": total_rt,
        "blocked": blocked_count,
        "attack_block_rate": blocked_count / total_rt if total_rt else 0.0,
        "attack_success_rate": asr,
        "unauthorized_write_attempts": unauthorized_writes,
        "pii_leakage_count": pii_leaks,
        "clean_cases_checked": len(clean_cases),
        "false_blocks": false_blocks,
        "false_block_rate": fbr,
    }


def _build_specs(cfg_name: str, exp_config: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    budgets = _normalize_budget_overrides(exp_config.get("budgets"))
    modes = list(exp_config.get("modes", ["c0_fixed", "c1_single", "c2_multi"]))
    base_flags = {
        "reflexion_enabled": bool(exp_config.get("reflexion_enabled", False)),
        "memory_enabled": bool(exp_config.get("memory_enabled", True)),
        "budget_overrides": budgets,
    }
    variants = exp_config.get("variants")
    if variants:
        specs: list[tuple[str, dict[str, Any]]] = []
        for m in modes:
            for v in variants:
                v_flags = {
                    **base_flags,
                    "mode": m,
                    "configurable_graph": v.get("configurable_graph", True),
                    "replanning_enabled": v.get("replanning_enabled", True),
                    "deterministic_verifier": v.get("deterministic_verifier", True),
                    "reflexion_enabled": v.get("reflexion_enabled", base_flags["reflexion_enabled"]),
                    "memory_enabled": v.get("memory_enabled", base_flags["memory_enabled"]),
                }
                specs.append((f"{m}_{v['name']}", v_flags))
        return specs
    return [(m, {**base_flags, "mode": m}) for m in modes]


def _run_e2_from_yaml(exp_config: dict[str, Any], split: str, output: Optional[str]) -> dict[str, Any]:
    requested_metrics = list(exp_config.get("metrics", []))
    validate_requested_metrics(requested_metrics, is_red_team=True)
    variants = exp_config.get(
        "variants",
        [{"name": "defenses_off", "defenses_enabled": False}, {"name": "defenses_on", "defenses_enabled": True}],
    )
    out_variants: dict[str, Any] = {}
    for v in variants:
        enabled = bool(v.get("defenses_enabled", True))
        res = asyncio.run(evaluate_red_team_suite(defenses_enabled=enabled, split=split))
        out_variants[str(v["name"])] = res
        typer.echo(
            f"  {v['name']} -> Block Rate: {res['attack_block_rate']:.1%} "
            f"({res['blocked']}/{res['red_team_total']}), ASR: {res['attack_success_rate']:.1%}"
        )
    summary = {"E2": out_variants, "split": split, "requested_metrics": requested_metrics}
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _unwrap_cli_args(
    split: Any, repeats: Any, output: Any, limit: Any, min_accuracy: Any
) -> tuple[Optional[str], Optional[int], Optional[str], int, float]:
    split_val = split if isinstance(split, str) else None
    repeats_val = repeats if isinstance(repeats, int) and not isinstance(repeats, bool) else None
    output_val = output if isinstance(output, str) else None
    limit_val = limit if isinstance(limit, int) and not isinstance(limit, bool) else 0
    is_num = isinstance(min_accuracy, (int, float)) and not isinstance(min_accuracy, bool)
    return split_val, repeats_val, output_val, limit_val, float(min_accuracy) if is_num else 0.0


def _load_experiment_yaml(config: str) -> tuple[str, dict[str, Any]]:
    cfg_name = config.replace(".yaml", "")
    cfg_file = Path(config) if Path(config).exists() else Path(f"config/experiments/{cfg_name}.yaml")
    if Path(config).exists():
        cfg_name = cfg_file.stem
    if not cfg_file.exists():
        raise FileNotFoundError(f"Experiment config not found: {cfg_file}")
    return cfg_name, yaml.safe_load(cfg_file.read_text(encoding="utf-8")) or {}


@app.command()
def run(
    config: str = typer.Option("E1", help="Experiment ID or YAML path (E1, E2, E3, E4)"),
    split: Optional[str] = typer.Option(None, help="Dataset split override (defaults to YAML split)"),
    repeats: Optional[int] = typer.Option(None, help="Evaluation repeats override (defaults to YAML repeats)"),
    output: Optional[str] = typer.Option(None, help="Optional JSON output path"),
    limit: int = typer.Option(0, help="Limit number of cases (0 = all)"),
    min_accuracy: float = typer.Option(0.0, help="Fail with non-zero exit if mean accuracy < threshold"),
) -> dict[str, Any]:
    """Run unified evaluation experiments E1-E4 on an isolated temporary DB, honouring the YAML config."""
    os.environ.pop("SQLITE_DB_PATH", None)
    eval_db = prepare_isolated_eval_db()
    typer.echo(f"Isolated evaluation DB: {eval_db}")
    cfg_name, exp_config = _load_experiment_yaml(config)
    split_val, repeats_val, output_val, limit_val, min_acc_val = _unwrap_cli_args(
        split, repeats, output, limit, min_accuracy
    )

    eff_split = split_val if split_val is not None else str(exp_config.get("split", "dev"))
    eff_repeats = repeats_val if repeats_val is not None else int(exp_config.get("repeats", 1))

    if cfg_name.upper() == "E2" or exp_config.get("include_red_team"):
        return _run_e2_from_yaml(exp_config, eff_split, output_val)

    requested_metrics = list(exp_config.get("metrics", []))
    validate_requested_metrics(requested_metrics, is_red_team=False)

    if eff_split in ("held_out", "v2_held_out", "v2_challenge"):
        assert_playbook_frozen_for_eval()

    raw_cases = load_cases(eff_split)
    if limit_val > 0:
        raw_cases = raw_cases[:limit_val]
    gold_records = [extract_gold_record(c) for c in raw_cases]
    redacted_cases = [
        {"case_id": c["case_id"], **bank_records.redact_case_for_agent(c)} for c in raw_cases
    ]

    typer.echo(f"Running {cfg_name} on {len(redacted_cases)} {eff_split} cases (repeats={eff_repeats})...")
    all_results: dict[str, Any] = {}

    persist_eval = eff_split in ("dev", "v2_dev")
    for label, kwargs in _build_specs(cfg_name, exp_config):
        typer.echo(f"\n--- Configuration: {label} ---")
        repeat_runs: list[list[dict[str, Any]]] = []
        for _rep in range(max(1, eff_repeats)):
            mode_results = []
            for redacted_c, gold in zip(redacted_cases, gold_records, strict=True):
                res = asyncio.run(run_case(redacted_c, persist_to_eval_db=persist_eval, **kwargs))
                g_ids = gold_evidence_ids(gold)
                c_ids = set(res.get("cited_evidence_ids", []))
                res["evidence_recall"] = len(c_ids & g_ids) / len(g_ids) if g_ids else 1.0
                sc = score_case(
                    res,
                    gold["gold_disposition"],
                    gold["expected_replan_required"],
                    gold["acceptable_dispositions"],
                )
                mode_results.append({**res, **sc})
            repeat_runs.append(mode_results)

        agg = aggregate_repeat_metrics(repeat_runs, gold_records)
        for m_name in requested_metrics:
            if m_name not in agg:
                raise NotImplementedError(f"Metric {m_name!r} missing from aggregated output")

        typer.echo(
            f"  Summary [{label}]: Accuracy={agg['disposition_accuracy']:.1%} | "
            f"Recovery={agg['replanning_recovery_rate']:.1%} | Recall={agg['evidence_recall']:.1%} | "
            f"CiteValid={agg['citation_validity_rate']:.1%} | InrErr={agg['inr_arithmetic_error_rate']:.1%} | "
            f"ToolErrs={agg['tool_errors']} | Cost=${agg['cost_usd']:.5f} | Latency={agg['latency_seconds']*1000:.1f}ms"
        )
        if min_acc_val > 0.0 and label != "c0_fixed" and agg["disposition_accuracy"] < min_acc_val:
            raise typer.Exit(code=1)

        all_results[label] = {"metrics": agg, "cases": repeat_runs[-1]}

    summary_out = {
        "experiment_id": exp_config.get("experiment_id", cfg_name),
        "split": eff_split,
        "repeats": eff_repeats,
        "budgets": exp_config.get("budgets"),
        "defenses_enabled": exp_config.get("defenses_enabled", True),
        "requested_metrics": requested_metrics,
        "results": all_results,
    }
    if output_val:
        Path(output_val).parent.mkdir(parents=True, exist_ok=True)
        Path(output_val).write_text(json.dumps(summary_out, indent=2), encoding="utf-8")
    return summary_out


if __name__ == "__main__":
    app()
