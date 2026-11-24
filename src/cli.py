"""
AuditGuard CLI Entrypoint (`python -m src.cli` or `auditguard`)
Commands:
  generate-data    Generate 60-case golden dataset & seed SQLite operational DB
  investigate      Run a single investigation (c0_fixed | rule_engine | c1_single | c2_multi)
  retrieval-bench  Evaluate Recall@5 & MRR on the regulatory benchmarks
  serve            Initialize DB & launch FastAPI + Analyst Workbench locally
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, cast

import typer
from typer.models import OptionInfo

if TYPE_CHECKING:
    from src.llm.client import LLMClient
    from src.llm.replay import LLMMode
    from src.models import InvestigationState

app = typer.Typer(name="auditguard", help="AuditGuard AML Investigation CLI")


def _opt_str(val: Any) -> Optional[str]:
    if isinstance(val, OptionInfo) or val is None:
        return None
    s = str(val).strip()
    return s or None


@app.command("generate-data")
def generate_data() -> None:
    """Generate the 60-case synthetic dataset (20 dev / 40 isolated held-out) and seed DB."""
    from data.synthetic_generator import generate_all_cases

    generate_all_cases()


async def _dispatch_cli_mode(
    alert: Any,
    mode: str,
    client: Optional["LLMClient"],
    llm_mode: Optional[str],
    cassette_path: Optional[str],
    chosen_run_id: Optional[str],
) -> "InvestigationState":
    if mode == "c0_fixed":
        from src.agent.c0_fixed import run_fixed_pipeline

        return await run_fixed_pipeline(alert)
    if mode == "rule_engine":
        from src.agent.rule_engine import run_rule_engine

        return await run_rule_engine(alert)
    if mode == "c2_multi":
        from src.agent.c2_multi import run_multi_agent

        return await run_multi_agent(
            alert, llm_client=client, llm_mode=llm_mode, cassette_path=cassette_path, run_id=chosen_run_id
        )
    from src.agent.c1_single import run_investigation

    return await run_investigation(
        alert, llm_client=client, llm_mode=llm_mode, cassette_path=cassette_path, run_id=chosen_run_id
    )


@app.command("investigate")
def investigate(
    alert_id: str = typer.Argument(..., help="Alert ID from the operational DB"),
    mode: str = typer.Option("c1_single", help="Agent mode: c0_fixed | rule_engine | c1_single | c2_multi"),
    llm: Optional[str] = typer.Option(None, "--llm", help="LLM execution mode: live | record | replay | offline"),
    cassette: Optional[str] = typer.Option(None, "--cassette", help="Cassette JSONL path for --llm record|replay"),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Run ID directory under runs/<run_id>/"),
) -> None:
    """Run an end-to-end investigation locally and output the verified DispositionWorksheet JSON."""
    from src.llm.client import LLMClient
    from src.mcp_servers.bank_records import get_alert_record
    from src.models import Alert, RiskLevel

    llm_mode, cassette_path, chosen_run_id = _opt_str(llm), _opt_str(cassette), _opt_str(run_id)
    if llm_mode is not None and llm_mode not in ("live", "record", "replay", "offline"):
        typer.echo(f"INVALID_LLM_MODE: {llm_mode!r}; expected live | record | replay | offline")
        raise typer.Exit(code=1)

    rec = get_alert_record(alert_id)
    if rec is None:
        typer.echo(f"INVALID_ALERT_ID: {alert_id!r} not found in the operational database")
        raise typer.Exit(code=1)
    alert = Alert(
        alert_id=rec["alert_id"],
        rule_name=rec["rule_name"],
        root_account=rec["root_account"],
        network_accounts=rec["network_accounts"],
        total_amount_inr=rec["total_amount_inr"],
        risk_level=RiskLevel.HIGH,
    )
    client = (
        LLMClient(mode=cast("LLMMode", llm_mode), cassette_path=cassette_path, run_id=chosen_run_id)
        if llm_mode in ("live", "record", "replay") and mode in ("c1_single", "c2_multi")
        else None
    )
    state = asyncio.run(_dispatch_cli_mode(alert, mode, client, llm_mode, cassette_path, chosen_run_id))
    if not state.worksheet:
        typer.echo("Investigation completed without worksheet.")
        return
    out = {
        **state.worksheet.model_dump(mode="json"),
        "tokens_used": state.total_tokens_used,
        "cost_usd": str(state.estimated_cost_usd),
        "tool_calls_used": state.tool_calls_used,
        "tool_errors": state.tool_error_count,
        "replan_count": state.replan_count,
        "transcript_path": str(client.transcript_path) if client is not None else None,
    }
    typer.echo(json.dumps(out, indent=2))


@app.command("retrieval-bench")
def retrieval_bench(
    report: bool = typer.Option(False, "--report", help="Print full Markdown report across all 4 pipelines"),
    bench: str = typer.Option("eval/retrieval_bench_v2.jsonl", "--bench", help="Path to retrieval benchmark JSONL"),
    out: Optional[str] = typer.Option(None, "--out", help="Optional output path to save Markdown report"),
) -> None:
    """Evaluate BM25, dense, hybrid-RRF, and hybrid+reranker on Retrieval Benchmark v2."""
    from eval.retrieval_eval import ALL_PIPELINES, format_retrieval_report, run_retrieval_benchmark

    bench_path = Path(bench)
    if not bench_path.exists():
        typer.echo(f"BENCHMARK_NOT_FOUND: {bench_path}")
        raise typer.Exit(code=1)

    summary = run_retrieval_benchmark(bench_path)
    md = format_retrieval_report(summary)
    out_path = _opt_str(out)
    if out_path:
        Path(out_path).write_text(md, encoding="utf-8")

    if report:
        typer.echo(md)
        return

    typer.echo(
        f"\n=== Retrieval Benchmark ({summary['total_queries']} queries: "
        f"{summary['n_answerable']} answerable, {summary['n_unanswerable']} unanswerable) ==="
    )
    for mode in ALL_PIPELINES:
        m = summary["results"][mode]
        tag = " [default]" if mode == summary["default_mode"] else ""
        typer.echo(
            f"  {mode:18s}{tag:10s} -> R@1: {m['recall_at_1']:.3f}, R@3: {m['recall_at_3']:.3f}, "
            f"R@5: {m['recall_at_5']:.3f}, MRR: {m['mrr']:.3f}, nDCG@5: {m['ndcg_at_5']:.3f}, "
            f"AbstainP: {m['abstain_precision']:.3f}"
        )
    typer.echo(
        f"  Best mode: {summary['empirical_best_mode']} | "
        f"Default >= BM25 R@1: {summary['default_beats_or_ties_bm25_r1']}"
    )


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
) -> None:
    """Validate configuration, initialize operational DB, and launch FastAPI + Analyst Workbench."""
    import uvicorn

    from src.config import validate_startup
    from src.db.database import init_db

    validate_startup()
    init_db()
    uvicorn.run("src.api.main:app", host=host, port=port)


if __name__ == "__main__":
    app()
