# AuditGuard v3: Evidence-Grounded AI Investigation System for Ambiguous Fund-Flow Networks

> **Primary Architectural Principle:** *The detector proposes. The agent investigates. The evidence supports. The human decides.*

AuditGuard v3 is an agentic Anti-Money Laundering (AML) investigation and decision-support system for ambiguous Indian scatter-gather fund-flow networks. It pairs **real tool-calling LLM agent loops (`C1` ReAct & `C2` Supervisor + 4 RBAC Specialists)** and **fair deterministic baselines (`C0` Fixed & `rule_engine`)** inside compiled **LangGraph `StateGraph` workflows with native `interrupt()` human gating**, **`nx.MultiDiGraph` + exact `decimal.Decimal` fund-flow & deduplicated aggregate-root conservation math**, **4 least-privilege FastMCP servers (`fastmcp.Client`)**, **Retrieval v2 (165 verifiable passages, BM25 + Dense SVD + RRF + Reranker with calibrated abstention)**, **Verifier v2 (6 fail-closed deterministic checks)**, and **single-use HMAC-SHA256 disposition commits**.

---

## Quick Local Setup & Startup

```powershell
# 1. Copy template and generate strong random local secrets + seeded user passwords
Copy-Item .env.example .env
python scripts/init_env.py

# 2. Launch FastAPI + Analyst Workbench (sign in with ANALYST_PASSWORD / REVIEWER_PASSWORD / ADMIN_PASSWORD from .env)
.\scripts\start_local.ps1
```

- **Compliance Analyst Web Workbench:** `http://127.0.0.1:8000/`
- **Swagger OpenAPI Docs:** `http://127.0.0.1:8000/api/docs`
- **Health & Prometheus Metrics:** `http://127.0.0.1:8000/health` | `http://127.0.0.1:8000/metrics`
- **Optional Chainlit chat UI:** `chainlit run src/ui/app.py --port 8001`. Each person signs in with their own account (`analyst` / `reviewer` / `admin`); it needs `CHAINLIT_AUTH_SECRET`, which `python scripts/init_env.py` adds to an existing `.env`.
- **Four-eyes approval:** the user who started an investigation, and whoever last edited its worksheet, can never approve it (`403 SELF_APPROVAL_FORBIDDEN`). Start as `analyst`, approve as `reviewer` or `admin`.

---

## Execution Modes & Evaluation Infrastructure

| Mode | Type | Description |
|---|---|---|
| `c0_fixed` | Deterministic | Fixed 14d / 4-hop scan, root + 3 counterparty KYC/registry, `compute_flow_conservation`, 3-way decision rule, 0 replans, 0 LLM calls. |
| `rule_engine` | Deterministic | Bounded replanning + proactive 365d counterparty history corroboration (`src/core/corroboration.py`) + explicit missing-data detection + evidence-weighted rubric (`allow_llm=False`). |
| `c1_single` | Live / Replay LLM | Versioned 6-slot prompt (`config/prompts/c1_investigator.yaml` v2.1.0), async OpenRouter tool-calling loop (`calc`, `replan_graph`, `finish`, MCP tools), Verifier v2 repair retries, transcript logging (`runs/<run_id>/transcripts.jsonl`). |
| `c2_multi` | Live / Replay LLM | Supervisor planning/replan + 4 RBAC-scoped specialists (`flow_tracer`, `benign_investigator`, `regulatory_analyst`, `reporter_critic`) with per-handoff sub-budgets. |

- **Benchmark Datasets:** Parametric `golden_v2` (`60` dev under `data/golden_v2/dev/`, `120` held-out under `eval/golden_v2/held_out/`, `30` adversarial challenge under `eval/golden_v2/challenge/`, disjoint IDs, shortcut baselines `<= 0.80`), `red_team_v2` (`132` attacks + `320` benign memos), and Retrieval Benchmark v2 (`110` queries with `20%` unanswerable).
- **LLM Execution Modes:** `--llm live | record | replay | offline` via `src/llm/client.py` and `src/llm/replay.py`.
- **Cross-Family Quality Judge:** `eval/judge.py` (`google/gemini-3.1-flash-lite`, `temperature=0`, blinded worksheets, G1–G7 rubric, position-swap bias test, calibration CLI in `eval/calibration.py`).

---

## Verification, Keyless Replay & Evaluation Commands

```powershell
# Full CI verification gate (ruff, mypy --strict, full pytest suite, offline smoke replay & held-out zero-drift gates)
make verify

# Keyless offline reproduction of E1 smoke replay, E1 120+30 deterministic held-out, E2 red-team v2,
# Retrieval v2 benchmark, and automatic regeneration of docs/evaluation_report.md from JSON summaries
make replay

# Regenerate docs/evaluation_report.md from JSON summaries + print 4-pipeline retrieval benchmark report
make report
python -m src.cli retrieval-bench --report

# Run pre-registered experiments (YAML honours split, repeats, modes, budgets, and metrics)
python -m eval.run_eval --config E1
python -m eval.run_eval --config E2
python -m eval.run_eval --config E3
python -m eval.run_eval --config E4

# Single-alert CLI investigation (supports --llm live|record|replay|offline and --cassette)
python -m src.cli investigate ALT-2026-0412 --mode c1_single --llm replay --cassette eval/cassettes/e1_smoke_10.jsonl

# Check operational DB has 0 held-out leakage
python scripts/purge_operational_db.py --check
```

---

## Key Documentation

- **[Reproducible Evaluation Report (auto-generated from `summary.json`)](docs/evaluation_report.md)**
- **[Pre-Registered Experimental Protocol (E1–E4)](docs/preregistration.md)**
- **[System, Component, Data-Flow & Database Architecture](docs/architecture.md)**
- **[STRIDE Threat Model & Residual Risks](docs/threat_model.md)**
- **[Memory Retention & Deletion Policy](docs/memory_policy.md)**
- **[Regulatory Corpus v2 `[HUMAN]` Verification Checklist](data/regulatory_corpus/HUMAN_VERIFICATION_CHECKLIST.md)**
- **[In-Depth Setup & Execution Guide](docs/IMPLEMENTATION_GUIDE.md)**

---

## Limitations

1. **Synthetic Evaluation Data:** All `golden_v2` cases (`60` dev, `120` held-out, `30` challenge) and `red_team_v2` payloads are parametrically generated rather than real bank customer transactions. Performance on live institutional payment rails has not been measured.
2. **Pending `[HUMAN]` Labeling & Statutory Verification:**
   - Independent human adjudication templates for 40 ambiguous dev cases (`eval/human_labels/cases_to_annotate_annotator_{1,2}.csv`) and 60 blinded worksheets (`eval/human_labels/worksheets_to_score_annotator_{1,2}.csv`) remain empty awaiting human compliance annotators; judge–human Cohen's kappa is reported as `awaiting_human_annotations` until populated.
   - Regulatory passages in `data/regulatory_corpus/indian_aml_corpus.jsonl` carry `human_verified: false` until verified against official Gazette of India / RBI / FIU-IND / FATF originals ([HUMAN_VERIFICATION_CHECKLIST.md](data/regulatory_corpus/HUMAN_VERIFICATION_CHECKLIST.md)).
3. **Keyless Replay Scope:** `make replay` reproduces recorded LLM cassettes (`eval/cassettes/e1_smoke_10.jsonl`, `eval/cassettes/judge_smoke.jsonl`) plus the full deterministic held-out, E2 red-team v2, and Retrieval v2 suites without API keys. Running a full 120-case x 3-repeat live LLM sweep across `c1_single` and `c2_multi` requires a funded OpenRouter API key.
4. **Offline Dense Retrieval Backend:** Default CI dense retrieval uses deterministic L2-normalized float32 SVD embeddings over word, character 3/4-gram, and AML concept features so CI requires zero multi-GB model downloads. Neural embeddings (e.g. `BAAI/bge-m3`) are not bundled in CI.
5. **Decision-Support Only:** AuditGuard never files STRs autonomously, never freezes accounts, and prohibits criminal guilt assertions; every committed disposition requires an authenticated human reviewer signature and matching canonical SHA-256 payload hash.
