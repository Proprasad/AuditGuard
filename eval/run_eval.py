"""Phase 5 Unified YAML Experiment Runner (`eval/run_eval.py` — Experiments E1, E2, E3, E4)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Optional
from uuid import uuid4

import typer
import yaml

from eval.exp_report import write_run_artifacts
from eval.metrics import (
    aggregate_mode_metrics,
    cited_evidence_ids,
    compute_case_quality,
    gold_evidence_ids,
    validate_requested_metrics,
)
from eval.red_team_runner import evaluate_red_team_suite_impl, run_e2_from_config
from eval.shortcuts import evaluate_shortcuts
from eval.stats import compute_paired_mode_table
from src.agent.llm_client import is_live_llm_active
from src.core.canonical import loads_json
from src.guardrails.verifier import verify_worksheet
from src.llm.client import LLMClient, LLMClientProtocol
from src.mcp_servers import bank_records
from src.memory.store import memory_store

app = typer.Typer()
OPERATIONAL_DB = (Path(__file__).resolve().parents[1] / "data" / "auditguard.db").resolve()
DETERMINISTIC_MODES: frozenset[str] = frozenset({"c0_fixed", "rule_engine"})
SPLIT_DIRS: dict[str, tuple[Path, ...]] = {
    "dev": (Path("data/golden_v2/dev"),),
    "held_out": (Path("eval/golden_v2/held_out"),),
    "challenge": (Path("eval/golden_v2/challenge"),),
    "v2_dev": (Path("data/golden_v2/dev"),),
    "v2_held_out": (Path("eval/golden_v2/held_out"),),
    "v2_challenge": (Path("eval/golden_v2/challenge"),),
    "v1_dev": (Path("data/synthetic/dev"),),
    "v1_held_out": (Path("eval/held_out"),),
    "golden_v1_regression": (Path("data/synthetic/dev"), Path("eval/held_out")),
}


def assert_isolated_eval_db() -> Path:
    from src.db import database

    resolved = database.get_sqlite_path().resolve()
    if resolved == OPERATIONAL_DB:
        raise RuntimeError(f"Evaluation refused: SQLITE_DB_PATH resolves to operational DB ({OPERATIONAL_DB}).")
    return resolved


def prepare_isolated_eval_db() -> Path:
    from src.db import database

    configured = os.getenv("SQLITE_DB_PATH")
    if configured and Path(configured).resolve() == OPERATIONAL_DB:
        raise RuntimeError(f"Evaluation refused: SQLITE_DB_PATH={configured!r} resolves to operational DB.")
    if not configured:
        os.environ["SQLITE_DB_PATH"] = str(Path(tempfile.mkdtemp(prefix="auditguard_eval_")) / "eval_auditguard.db")
    database.reset_db_init()
    database.init_db()
    database.seed_operational_db()
    memory_store.load_playbook("config/reflexion_playbook.json")
    return assert_isolated_eval_db()


def assert_playbook_frozen_for_eval() -> None:
    if not memory_store.is_playbook_frozen():
        raise RuntimeError("Held-out / Reflexion evaluation refused: `playbook_frozen` is False in system_flags.")


def load_cases(split: str = "dev") -> list[dict[str, Any]]:
    if split not in SPLIT_DIRS:
        raise ValueError(f"Unknown split {split!r}; expected one of {sorted(SPLIT_DIRS)}")
    return [
        loads_json(f.read_text(encoding="utf-8"))
        for folder in SPLIT_DIRS[split]
        for f in sorted(folder.glob("*.json"))
    ]


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
        "gold_calc": dict(raw_case.get("gold_calc") or {}),
        "severity_cost": dict(
            raw_case.get("severity_cost") or {"false_close": 10, "false_escalate": 1, "false_request_info": 2}
        ),
        "family": str(raw_case.get("family") or raw_case.get("category", "")),
        "family_group": str(raw_case.get("family_group") or str(raw_case.get("family", "")).split(".")[0]),
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
    for k in ("max_tool_calls", "max_replans", "max_critique_retries"):
        if k in raw_budgets:
            out[k] = int(raw_budgets[k])
    if "max_cost_usd_per_case" in raw_budgets:
        out["max_cost_usd_per_case"] = Decimal(str(raw_budgets["max_cost_usd_per_case"]))
    return out or None


async def run_case(
    case: dict[str, Any],
    mode: str,
    configurable_graph: bool = True,
    replanning_enabled: bool = True,
    deterministic_verifier: bool = True,
    allow_calc: bool = True,
    allow_registry: bool = True,
    allow_rag: bool = True,
    defenses_enabled: bool = True,
    reflexion_enabled: bool = False,
    memory_enabled: bool = True,
    budget_overrides: Optional[dict[str, Any]] = None,
    llm_client: Optional[LLMClientProtocol] = None,
    llm_mode: Optional[str] = None,
    seed: Optional[int] = None,
    run_id: Optional[str] = None,
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
                replanning_enabled=replanning_enabled,
                deterministic_verifier=deterministic_verifier,
                defenses_enabled=defenses_enabled,
                reflexion_enabled=reflexion_enabled,
                memory_enabled=memory_enabled,
                budget_overrides=budget_overrides,
                llm_client=llm_client,
                llm_mode=llm_mode,
                run_id=run_id,
                seed=seed,
            )
        else:
            from src.agent.c1_single import run_investigation

            final_state = await run_investigation(
                alert,
                configurable_graph=configurable_graph,
                replanning_enabled=replanning_enabled,
                deterministic_verifier=deterministic_verifier,
                allow_calc=allow_calc,
                allow_registry=allow_registry,
                allow_rag=allow_rag,
                defenses_enabled=defenses_enabled,
                reflexion_enabled=reflexion_enabled,
                memory_enabled=memory_enabled,
                budget_overrides=budget_overrides,
                llm_client=llm_client,
                llm_mode=llm_mode,
                run_id=run_id,
                seed=seed,
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
            "mode": mode,
            "seed": seed,
            "disposition": ws.recommended_disposition.value if ws else "unknown",
            "confidence": float(ws.confidence_score) if ws else 0.0,
            "citations": ws.regulatory_citations if ws else [],
            "cited_evidence_ids": sorted(cited_evidence_ids(ws_dict, gold_evidence_ids(gold_snapshot))),
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


async def evaluate_red_team_suite(
    defenses_enabled: bool = True,
    split: str = "v1_dev",
    *,
    suite: str = "v1",
    run_e2e_agent: bool = False,
    llm_client: Optional[LLMClientProtocol] = None,
) -> dict[str, Any]:
    """Execute Experiment E2 across v1 (32) or v2 (132) red-team attacks + benign false-block checks."""
    assert_isolated_eval_db()
    clean = None if suite == "v2" else load_cases(split)
    return await evaluate_red_team_suite_impl(
        defenses_enabled=defenses_enabled,
        clean_cases=clean,
        suite=suite,
        run_e2e_agent=run_e2e_agent,
        llm_client=llm_client,
    )


def _build_specs(exp_config: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    budgets = _normalize_budget_overrides(exp_config.get("budgets"))
    modes = list(exp_config.get("modes", ["c0_fixed", "rule_engine", "c1_single", "c2_multi"]))
    base_flags = {
        "defenses_enabled": bool(exp_config.get("defenses_enabled", True)),
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
                    "configurable_graph": bool(v.get("configurable_graph", True)),
                    "replanning_enabled": bool(v.get("replanning_enabled", True)),
                    "deterministic_verifier": bool(v.get("deterministic_verifier", True)),
                    "allow_calc": bool(v.get("allow_calc", True)),
                    "allow_registry": bool(v.get("allow_registry", True)),
                    "allow_rag": bool(v.get("allow_rag", True)),
                    "defenses_enabled": bool(v.get("defenses_enabled", base_flags["defenses_enabled"])),
                    "reflexion_enabled": bool(v.get("reflexion_enabled", base_flags["reflexion_enabled"])),
                    "memory_enabled": bool(v.get("memory_enabled", base_flags["memory_enabled"])),
                }
                specs.append((f"{m}_{v['name']}", v_flags))
        return specs
    return [(m, {**base_flags, "mode": m}) for m in modes]


def _resolve_eval_llm(
    llm_flag: Optional[str], cassette: Optional[str], run_id: str
) -> tuple[str, Optional[LLMClient]]:
    eff = (llm_flag or "").strip().lower()
    if not eff:
        eff = "live" if is_live_llm_active() else "offline"
    if eff == "offline":
        return "offline", None
    if eff in ("record", "replay"):
        if not cassette:
            raise ValueError(f"`--cassette` path is required when `--llm {eff}` is specified")
        return eff, LLMClient(mode=eff, cassette_path=Path(cassette), run_id=run_id, timeout_s=90.0)  # type: ignore[arg-type]
    return "live", LLMClient(mode="live", run_id=run_id, timeout_s=90.0)


async def _execute_matrix_spec(
    *,
    label: str,
    spec_kwargs: dict[str, Any],
    redacted_cases: list[dict[str, Any]],
    gold_records: list[dict[str, Any]],
    eff_repeats: int,
    base_seed: int,
    concurrency: int,
    persist_eval: bool,
    llm_mode_str: str,
    shared_llm: Optional[LLMClient],
    run_id: str,
    cases_out_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    mode_name = str(spec_kwargs["mode"])
    is_det = mode_name in DETERMINISTIC_MODES
    n_reps = 1 if is_det else max(1, eff_repeats)
    exec_label = "deterministic" if is_det else llm_mode_str
    sem = asyncio.Semaphore(max(1, concurrency))
    repeat_runs: list[list[dict[str, Any]]] = []

    for rep_idx in range(n_reps):
        rep_seed = None if is_det else (base_seed + rep_idx)

        async def _one(
            rc: dict[str, Any],
            g: dict[str, Any],
            s_val: Optional[int] = rep_seed,
            r_i: int = rep_idx,
        ) -> dict[str, Any]:
            async with sem:
                res = await run_case(
                    rc,
                    llm_client=None if is_det else shared_llm,
                    llm_mode="offline" if is_det else llm_mode_str,
                    seed=s_val,
                    run_id=run_id,
                    persist_to_eval_db=persist_eval,
                    **spec_kwargs,
                )
            sc = score_case(
                res, g["gold_disposition"], g["expected_replan_required"], g["acceptable_dispositions"]
            )
            merged = {**res, **sc}
            out_f = cases_out_dir / f"{label}__rep{r_i}__case_{rc['case_id']}.json"
            await asyncio.to_thread(out_f.write_text, json.dumps(merged, indent=2), "utf-8")
            return merged

        mode_results = list(
            await asyncio.gather(*(_one(rc, g) for rc, g in zip(redacted_cases, gold_records, strict=True)))
        )
        repeat_runs.append(mode_results)

    agg = aggregate_mode_metrics(repeat_runs, gold_records, seed=base_seed, execution_label=exec_label)
    return agg, repeat_runs[-1]


def _load_experiment_yaml(config: str) -> tuple[str, dict[str, Any]]:
    cfg_name = config.replace(".yaml", "")
    cfg_file = Path(config) if Path(config).exists() else Path(f"config/experiments/{cfg_name}.yaml")
    if Path(config).exists():
        cfg_name = cfg_file.stem
    if not cfg_file.exists():
        raise FileNotFoundError(f"Experiment config not found: {cfg_file}")
    return cfg_name, yaml.safe_load(cfg_file.read_text(encoding="utf-8")) or {}


def _unwrap_opt(val: Any, expected_type: type[Any], default: Any = None) -> Any:
    if isinstance(val, bool) and expected_type is int:
        return default
    return val if isinstance(val, expected_type) else default


def _maybe_run_challenge_slice(
    exp_config: dict[str, Any],
    eff_split: str,
    lim_v: int,
    specs: list[tuple[str, dict[str, Any]]],
    seed_v: int,
    conc_v: int,
    llm_mode_str: str,
    shared_llm: Optional[LLMClient],
    rid_v: str,
    cases_dir: Path,
) -> dict[str, Any]:
    want_chal = bool(exp_config.get("include_challenge_slice")) and lim_v == 0
    if not (want_chal and eff_split in ("held_out", "v2_held_out")):
        return {}
    chal_raw = load_cases("challenge")
    chal_gold = [extract_gold_record(c) for c in chal_raw]
    chal_red = [{"case_id": c["case_id"], **bank_records.redact_case_for_agent(c)} for c in chal_raw]
    challenge_out: dict[str, Any] = {}
    for label, s_kwargs in specs:
        c_agg, _ = asyncio.run(
            _execute_matrix_spec(
                label=f"{label}_challenge",
                spec_kwargs=s_kwargs,
                redacted_cases=chal_red,
                gold_records=chal_gold,
                eff_repeats=1,
                base_seed=seed_v,
                concurrency=conc_v,
                persist_eval=False,
                llm_mode_str=llm_mode_str,
                shared_llm=shared_llm,
                run_id=rid_v,
                cases_out_dir=cases_dir,
            )
        )
        c_agg.pop("_case_series", None)
        challenge_out[label] = {"metrics": c_agg}
    return challenge_out


@app.command()
def run(
    config: str = typer.Option("E1", help="Experiment ID or YAML path (E1, E2, E3, E4)"),
    split: Optional[str] = typer.Option(None, help="Dataset split override (defaults to YAML split)"),
    repeats: Optional[int] = typer.Option(None, help="Evaluation repeats override (defaults to YAML repeats)"),
    llm: Optional[str] = typer.Option(None, help="LLM execution mode: live, record, replay, offline"),
    cassette: Optional[str] = typer.Option(None, help="Cassette JSONL path for record/replay"),
    run_id: Optional[str] = typer.Option(None, help="Run directory identifier under runs/<run_id>/"),
    concurrency: int = typer.Option(4, help="Max concurrent case evaluations"),
    seed: int = typer.Option(42, help="Base deterministic seed"),
    output: Optional[str] = typer.Option(None, help="Optional extra JSON summary output path"),
    limit: int = typer.Option(0, help="Limit number of cases (0 = all)"),
    min_accuracy: float = typer.Option(0.0, help="Fail with non-zero exit if mean accuracy < threshold"),
) -> dict[str, Any]:
    """Run unified evaluation experiments E1-E4 on an isolated temporary DB, honouring the YAML config."""
    os.environ.pop("SQLITE_DB_PATH", None)
    eval_db = prepare_isolated_eval_db()
    cfg_name, exp_config = _load_experiment_yaml(config)

    split_v = _unwrap_opt(split, str, None)
    rep_v = _unwrap_opt(repeats, int, None)
    llm_v = _unwrap_opt(llm, str, None)
    cas_v = _unwrap_opt(cassette, str, None)
    ts_tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rid_v = _unwrap_opt(run_id, str, None) or f"{cfg_name.lower()}_{ts_tag}_{uuid4().hex[:6]}"
    conc_v = int(_unwrap_opt(concurrency, int, 4))
    seed_v = int(_unwrap_opt(seed, int, 42))
    out_v = _unwrap_opt(output, str, None)
    lim_v = int(_unwrap_opt(limit, int, 0))
    is_num = isinstance(min_accuracy, (int, float)) and not isinstance(min_accuracy, bool)
    min_acc_v = float(min_accuracy) if is_num else 0.0

    eff_split = split_v if split_v is not None else str(exp_config.get("split", "dev"))
    eff_repeats = rep_v if rep_v is not None else int(exp_config.get("repeats", 1))
    run_dir = Path("runs") / rid_v
    cases_dir = run_dir / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    llm_mode_str, shared_llm = _resolve_eval_llm(llm_v, cas_v, rid_v)
    typer.echo(f"Isolated evaluation DB: {eval_db} | run_id={rid_v} | llm={llm_mode_str}")

    if cfg_name.upper() == "E2" or exp_config.get("include_red_team"):
        return run_e2_from_config(cfg_name, exp_config, eff_split, rid_v, run_dir, out_v, shared_llm, load_cases)

    requested_metrics = list(exp_config.get("metrics", []))
    validate_requested_metrics(requested_metrics, is_red_team=False)
    if eff_split in ("held_out", "v2_held_out", "challenge", "v2_challenge", "v1_held_out"):
        assert_playbook_frozen_for_eval()

    raw_cases = load_cases(eff_split)
    if lim_v > 0:
        raw_cases = raw_cases[:lim_v]
    gold_records = [extract_gold_record(c) for c in raw_cases]
    redacted_cases = [{"case_id": c["case_id"], **bank_records.redact_case_for_agent(c)} for c in raw_cases]
    persist_eval = eff_split in ("dev", "v2_dev", "v1_dev")

    typer.echo(f"Running {cfg_name} on {len(redacted_cases)} {eff_split} cases (repeats={eff_repeats})...")
    specs = _build_specs(exp_config)
    all_results: dict[str, dict[str, Any]] = {}
    for label, s_kwargs in specs:
        agg, last_cases = asyncio.run(
            _execute_matrix_spec(
                label=label,
                spec_kwargs=s_kwargs,
                redacted_cases=redacted_cases,
                gold_records=gold_records,
                eff_repeats=eff_repeats,
                base_seed=seed_v,
                concurrency=conc_v,
                persist_eval=persist_eval,
                llm_mode_str=llm_mode_str,
                shared_llm=shared_llm,
                run_id=rid_v,
                cases_out_dir=cases_dir,
            )
        )
        for m_name in requested_metrics:
            if m_name not in agg:
                raise NotImplementedError(f"Metric {m_name!r} missing from aggregated output")
        typer.echo(
            f"  [{label}] ({agg['execution_type']}, reps={agg['repeats_executed']}): "
            f"Acc={agg['disposition_accuracy']:.1%} | ErrCost={agg['weighted_error_cost']:.2f} | "
            f"FCR={agg['false_close_rate']:.1%} | Cost=${agg['cost_usd']:.4f}"
        )
        if min_acc_v > 0.0 and label != "c0_fixed" and agg["disposition_accuracy"] < min_acc_v:
            raise typer.Exit(code=1)
        all_results[label] = {"metrics": agg, "cases": last_cases}

    paired = compute_paired_mode_table(all_results, gold_records, seed_v)
    for entry in all_results.values():
        entry["metrics"].pop("_case_series", None)

    challenge_out = _maybe_run_challenge_slice(
        exp_config, eff_split, lim_v, specs, seed_v, conc_v, llm_mode_str, shared_llm, rid_v, cases_dir
    )
    v2_dev = load_cases("v2_dev")
    shortcut_out = (
        {"dev": evaluate_shortcuts(v2_dev, v2_dev), "target": evaluate_shortcuts(v2_dev, raw_cases)}
        if raw_cases
        else {}
    )
    summary_out: dict[str, Any] = {
        "experiment_id": exp_config.get("experiment_id", cfg_name),
        "run_id": rid_v,
        "split": eff_split,
        "n_cases": len(raw_cases),
        "repeats": eff_repeats,
        "llm_mode": llm_mode_str,
        "budgets": exp_config.get("budgets"),
        "defenses_enabled": exp_config.get("defenses_enabled", True),
        "requested_metrics": requested_metrics,
        "results": all_results,
        "paired_comparisons": paired,
        "shortcut_baselines": shortcut_out,
        "challenge_slice": challenge_out,
    }
    write_run_artifacts(run_dir, summary_out, out_v)
    return summary_out


if __name__ == "__main__":
    app()
