"""
AuditGuard CLI Entrypoint (`python -m src.cli` or `auditguard`)
Commands:
  generate-data    Generate 60-case golden dataset & seed SQLite operational DB
  investigate      Run a single investigation (c0_fixed | c1_single | c2_multi)
  retrieval-bench  Evaluate Recall@5 & MRR on the 35-query regulatory benchmark
  serve            Initialize DB & launch FastAPI + Analyst Workbench locally
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer

app = typer.Typer(name="auditguard", help="AuditGuard AML Investigation CLI")


@app.command("generate-data")
def generate_data() -> None:
    """Generate the 60-case synthetic dataset (20 dev / 40 isolated held-out) and seed DB."""
    from data.synthetic_generator import generate_all_cases

    generate_all_cases()


@app.command("investigate")
def investigate(
    alert_id: str = typer.Argument(..., help="Alert ID from the operational DB"),
    mode: str = typer.Option("c1_single", help="Agent mode: c0_fixed | c1_single | c2_multi"),
) -> None:
    """Run an end-to-end investigation locally and output the verified DispositionWorksheet."""
    from src.mcp_servers.bank_records import get_alert_record
    from src.models import Alert, RiskLevel

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

    async def _run():
        if mode == "c0_fixed":
            from src.agent.c0_fixed import run_fixed_pipeline

            return await run_fixed_pipeline(alert)
        if mode == "c2_multi":
            from src.agent.c2_multi import run_multi_agent

            return await run_multi_agent(alert)
        from src.agent.c1_single import run_investigation

        return await run_investigation(alert)

    state = asyncio.run(_run())
    if state.worksheet:
        typer.echo(json.dumps(state.worksheet.model_dump(mode="json"), indent=2))
    else:
        typer.echo("Investigation completed without worksheet.")


@app.command("retrieval-bench")
def retrieval_bench() -> None:
    """Run the 35-query regulatory benchmark comparing BM25-only vs Hybrid RRF+Rerank."""
    from src.mcp_servers.client import call_mcp_tool

    bench_path = Path("eval/retrieval_bench.jsonl")
    queries = [json.loads(line) for line in bench_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    async def _eval_mode(mode: str) -> tuple[float, float]:
        hits = 0
        rr_sum = 0.0
        for q in queries:
            res = await call_mcp_tool(
                "compliance-kb", "search_regulations", {"query": q["query"], "top_k": 5, "mode": mode}
            )
            returned = [c["clause_id"] for c in res.get("clauses", [])]
            expected = set(q["expected_ids"])
            if expected & set(returned):
                hits += 1
                for rank, cid in enumerate(returned, start=1):
                    if cid in expected:
                        rr_sum += 1.0 / rank
                        break
        n = max(len(queries), 1)
        return hits / n, rr_sum / n

    bm25_r5, bm25_mrr = asyncio.run(_eval_mode("bm25_only"))
    hyb_r5, hyb_mrr = asyncio.run(_eval_mode("hybrid_rrf_rerank"))

    typer.echo(f"Evaluated {len(queries)} regulatory queries:")
    typer.echo(f"  BM25-Only          -> Recall@5: {bm25_r5:.1%} | MRR: {bm25_mrr:.3f}")
    typer.echo(f"  Hybrid RRF+Rerank  -> Recall@5: {hyb_r5:.1%} | MRR: {hyb_mrr:.3f}")


@app.command("serve")
def serve(host: str = "127.0.0.1", port: int = 8000, reload: bool = False) -> None:
    """Initialize SQLite DB, seed synthetic data if empty, and start FastAPI + Analyst Workbench."""
    import uvicorn
    from src.db.database import seed_operational_db

    seed_operational_db()
    typer.echo(f"AuditGuard Analyst Workbench starting at http://{host}:{port}/")
    uvicorn.run("src.api.main:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
