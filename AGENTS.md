# AGENTS.md — AuditGuard Autonomous Development Manual

This document is the authoritative engineering and autonomous execution guide for AI coding agents working in the **AuditGuard** repository. Every technology, path, command, and limitation below is derived directly from the repository source code and configuration files.

---

## 1. Project Overview

### Purpose
**AuditGuard v3** (`auditguard` v0.3.0) is an evidence-grounded AI investigation and decision-support system for ambiguous Indian Anti-Money Laundering (AML) scatter-gather fund-flow networks.

**Core architectural principle:** *The detector proposes. The agent investigates. The evidence supports. The human decides.*
AuditGuard never autonomously files STRs or freezes accounts; every committed case disposition requires an authenticated `senior_reviewer` (or `admin`), a canonical SHA-256 worksheet hash match, and a single-use HMAC-SHA256 approval token.

### Detected Technology Stack
- **Language & Runtime:** Python `>=3.10` (`pyproject.toml` targets `py310`; CI and `Dockerfile` run Python `3.11`).
- **Backend API & CLI:** FastAPI (`>=0.115.0`), Uvicorn (`>=0.30.0`), Pydantic v2 (`>=2.8.0`), Pydantic Settings (`>=2.4.0`), Typer (`>=0.12.0`).
- **Agent Orchestration:** LangGraph (`>=0.2.60`) compiled `StateGraph` with native `interrupt()` human gating, `langgraph-checkpoint-sqlite`, `langgraph-checkpoint-postgres`, `langchain-core` (`>=0.3.0`).
- **LLM Client & Replay:** Async `httpx` (`>=0.27.0`) OpenRouter / OpenAI-compatible client (`src/llm/client.py`) with SHA-256 keyed JSONL cassette record/replay (`src/llm/replay.py`) and exact `Decimal` token cost accounting (`src/llm/cost.py`).
- **Graph & Quantitative Core:** NetworkX (`>=3.3`, `nx.MultiDiGraph`) and Python `decimal.Decimal` (`src/core/graph_math.py`, `src/core/canonical.py`).
- **Tool Protocol (MCP):** FastMCP (`>=2.0.0`) exposing 4 least-privilege servers (`compliance-kb`, `graph-engine`, `bank-records`, `case-actions`) over `inprocess` (local dev/tests) or authenticated `http` transport (Docker fleet / live E2E).
- **Frontend / Web UI:**
  - **Primary Analyst Web Workbench:** Static vanilla HTML5, CSS3, and ES Modules served by FastAPI at `/` and `/static` (`src/ui/static/`). There is **no Node.js, npm, TypeScript, or frontend build pipeline**.
  - **Optional Chat UI:** Chainlit (`>=2.0.0`, `src/ui/app.py`, port `8001`, optional `[ui]` extra).
- **Persistence:** SQLite (`data/auditguard.db` + `data/auditguard.langgraph.sqlite` via `aiosqlite`) by default; PostgreSQL 16 (`psycopg[binary,pool]>=3.2.0`) when `USE_POSTGRES=true` (`docker-compose.yml`).
- **Retrieval (RAG):** In-process Retrieval v2 (`src/mcp_servers/compliance_kb.py`) over `data/regulatory_corpus/indian_aml_corpus.jsonl` (165 passages) combining BM25, deterministic float32 SVD dense embeddings, Reciprocal Rank Fusion (RRF), and reranking with calibrated abstention. Optional `[rag]` extras (`qdrant-client`, `rank-bm25`, `sentence-transformers`) are not required for default local or CI execution.
- **Observability:** Prometheus metrics at `/metrics` (`prometheus-client`), non-blocking Grafana Loki log shipping (`src/observability/loki_shipper.py`) with PII/secret redaction (`src/observability/redaction.py`), and Grafana dashboards (`monitoring/`).

### High-Level Architecture
1. **Alert Intake & Auth:** Authenticated FastAPI routes (`/api/v1/*`, HS256 JWT with `analyst`, `senior_reviewer`, and `admin` roles) or Typer CLI (`src/cli.py`).
2. **Execution Modes (all compiled into LangGraph `StateGraph` via `src/agent/graph.py`):**
   - `c0_fixed`: Deterministic 14-day / 4-hop fixed baseline (`0` LLM calls, `0` replans).
   - `rule_engine`: Deterministic bounded-replan baseline with corroboration (`allow_llm=False`).
   - `c1_single`: Single-agent LLM ReAct tool-calling loop (`src/agent/loop.py`, 6-slot versioned prompt `config/prompts/c1_investigator.yaml`).
   - `c2_multi`: Supervisor LLM + 4 RBAC-scoped specialist LLMs (`flow_tracer`, `benign_investigator`, `regulatory_analyst`, `reporter_critic`) in `src/agent/c2_loop.py` with parallel fan-out (`asyncio.gather`) and shared `BudgetLedger`.
3. **Guarded MCP Tool Layer:** All tool invocations route through `GuardedToolbox` (`src/agent/tooling.py`) and `src/guardrails/hooks.py`, enforcing RBAC allow-lists, policy bounds (`config/models.yaml`), call/cost budgets, prompt-injection sanitization, `<untrusted_data>` wrapping, and PII masking.
4. **Deterministic Verifier & Human Gate:** `verify_worksheet` (`src/core/verifier.py`) validates INR arithmetic against `calc_log`/evidence, citation existence against the corpus, evidence IDs, and prohibited guilt language (fail-closed). The graph pauses at `human_gate` (`interrupt()`) until `POST /api/v1/investigations/{thread_id}/decision/prepare` + `POST /api/v1/investigations/{thread_id}/decision` supply a valid `approved_hash` and single-use HMAC `approval_token` to run `commit_disposition`.

---

## 2. Repository Structure

### Root Layout
- `pyproject.toml`: Package metadata, dependencies, optional extras (`llm`, `rag`, `ui`, `observability`, `dev`, `full`), Ruff, Mypy, and Pytest configuration.
- `Makefile`: Standard CI and evaluation targets (`verify`, `replay`, `report`, `data`, `eval-e1`..`eval-e4`).
- `.github/workflows/ci.yml`: GitHub Actions workflow running Python 3.11, dataset generation, and `make verify`.
- `Dockerfile` & `docker-compose.yml`: Multi-service container stack (PostgreSQL 16, 4 HTTP FastMCP servers, FastAPI API, Chainlit UI, Loki, Prometheus, Grafana).
- `.env.example`: Environment template (use `python scripts/init_env.py` to generate strong local secrets in `.env`).
- `config/`:
  - `config/models.yaml`: Single source of truth for `allowed_models`, role defaults, pricing, budgets, timeouts, graph parameter bounds, scoring weights, and retrieval settings.
  - `config/prompts/c1_investigator.yaml`: Versioned 6-slot system prompt for `c1_single`.
  - `config/experiments/E1.yaml`..`E4.yaml`: Pre-registered experiment specifications.
  - `config/reflexion_playbook.json`: Frozen Reflexion lessons.

### Application Modules (`src/`)
- `src/cli.py`: Typer CLI entrypoint (`auditguard` / `python -m src.cli` — commands: `generate-data`, `investigate`, `retrieval-bench`, `serve`).
- `src/config.py`: `Settings` (`BaseSettings`), `get_policy()` (`PolicyConfig` loader), fail-fast `validate_startup()`.
- `src/models.py`: Strict Pydantic v2 domain models (`StrictModel`, `Alert`, `FundFlowPath`, `DispositionWorksheet`, `InvestigationState`, API request/response schemas).
- `src/agent/`:
  - `graph.py`: Compiled LangGraph `StateGraph` definitions, `AsyncSqliteSaver`/`AsyncPostgresSaver`, `human_gate`, `commit_disposition`, `run_graph`, `resume_gate`, `resume_and_commit_gate`.
  - `loop.py` & `c2_loop.py`: Real LLM tool-calling loops for `c1_single` and `c2_multi`.
  - `c1_single.py`, `c2_multi.py`, `c0_fixed.py`, `rule_engine.py`: Top-level entry functions per agent mode.
  - `planning.py`, `nodes.py`, `gathering.py`, `reasoning.py`, `drafting.py`, `specialists.py`, `telemetry.py`: Shared `RunContext`, `resolve_model_for_role`, deterministic graph nodes, and telemetry helpers.
  - `tools.py`, `tool_schemas.py`, `tooling.py`, `prompts.py`, `llm_client.py`: OpenAI tool schemas, pure `Decimal` `calc` tool, `GuardedToolbox`, prompt rendering, and runtime `system_flags` LLM configuration.
- `src/llm/`: `client.py` (async OpenRouter client), `replay.py` (cassette store & SHA-256 envelope hashing), `cost.py`, `schemas.py`.
- `src/core/`: Pure deterministic safety & math core — `canonical.py` (Decimal types & SHA-256 hashing), `policy.py` (`PolicyConfig`, `BudgetLedger`), `graph_math.py` (`nx.MultiDiGraph` & aggregate-root flow conservation), `corroboration.py`, `adapters.py`, `scoring.py`, `verifier.py`, `verifier_patterns.py`.
- `src/guardrails/`: `hooks.py` (RBAC tool allow-lists & pre/post MCP hooks), `guardrails.py` (prompt-injection & PII defenses), `verifier.py`.
- `src/mcp_servers/`: 4 FastMCP servers (`bank_records.py`, `graph_engine.py`, `compliance_kb.py`, `case_actions.py`), `client.py` (inprocess/HTTP dispatcher), `http_auth.py`.
- `src/api/`: Thin HTTP layer — `main.py` (FastAPI app, lifespan, middleware, static mount), `auth.py` (JWT & revocation), `users.py`, `ratelimit.py`, `metrics.py`, `deps.py`, `routes/{ui,data,investigations}.py`, `services/{runner,approval,threads,erasure}.py`.
- `src/db/`: `database.py` (SQLite/PostgreSQL schema, checkpoints, events, audit logs), `case_repo.py`, `read_repo.py`, `seeder.py`, `postgres_backend.py`.
- `src/memory/store.py` & `src/reflexion/loop.py`: Episode/lesson storage and Reflexion loop.
- `src/observability/`: `loki_shipper.py` and `redaction.py`.
- `src/ui/`:
  - `src/ui/static/`: Primary Analyst Workbench (`index.html`, `css/{tokens,workbench}.css`, `js/{app,api,charts,graph-view}.js`).
  - `src/ui/app.py`: Optional Chainlit chat client.

### Data, Evaluation, Scripts, Tests & Docs
- `data/`: Synthetic data generators (`synthetic_generator.py`, `generator_v2/`), dev dataset (`data/golden_v2/dev/`), regulatory corpus (`data/regulatory_corpus/`), and local SQLite operational DB (`data/auditguard.db`, gitignored/runtime).
- `eval/`: Offline evaluation harness (`run_eval.py`, `verify_gates.py`, `run_replay_suite.py`, `report.py`, `retrieval_eval.py`, `red_team_runner.py`, `judge.py`, `calibration.py`), cassettes (`eval/cassettes/`), baselines (`eval/baselines/`), replay bundle (`eval/replay_bundle/`), and physically isolated held-out/challenge splits (`eval/golden_v2/{held_out,challenge}/`, `eval/held_out/`).
- `scripts/`: `init_env.py`, `start_local.ps1`, `verify_live_e2e.py`, `purge_operational_db.py`, `build_frozen_playbook.py`, `init_db.sql`.
- `tests/`: Pytest unit, API/SSE integration, MCP transport, security, verifier, detector, retrieval, reporting, and frontend DOM-contract tests (`conftest.py` enforces isolated temporary SQLite DB per test).
- `docs/`: Architecture, threat model, memory policy, preregistration, auto-generated `evaluation_report.md`, implementation guide.

### Application Entry Points
- **FastAPI + Analyst Workbench (primary):** `python -m src.cli serve --host 127.0.0.1 --port 8000` or `python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000`
- **CLI:** `python -m src.cli --help` (or installed console script `auditguard`)
- **Chainlit UI (optional):** `chainlit run src/ui/app.py --host 127.0.0.1 --port 8001`
- **Standalone FastMCP HTTP servers (optional fleet):** `python -m src.mcp_servers.{compliance_kb,graph_engine,bank_records,case_actions}`

---

## 3. Development Environment

> **Package Manager & Lockfile:** Uses `pip` with `pyproject.toml` (`setuptools`). No lockfile (`requirements.txt`, `poetry.lock`, or `uv.lock`) is present in the repository.
> **Windows Note:** GNU `make` may not be installed on Windows; every `make` target maps directly to the `python -m ...` commands listed below.

### Dependency Installation
```bash
python -m pip install --upgrade pip
python -m pip install -e ".[ui,dev]"
```
(CI additionally ensures `fastmcp prometheus-client uvicorn pytest-asyncio`; all core runtime packages are in `pyproject.toml` `dependencies`.)

### Local Environment & Dataset Initialization
```bash
# 1. Create .env with strong random local secrets (never commit .env)
cp .env.example .env
python scripts/init_env.py

# 2. Generate deterministic datasets (v1 + golden_v2 + regulatory corpus v2 + benchmarks)
python -m data.synthetic_generator
python -m data.generator_v2.build --seed 42
python -m data.regulatory_corpus.build_corpus_v2
python -m eval.build_retrieval_bench_v2
python -m eval.build_red_team_v2
```

### Running the Application
```bash
# Primary FastAPI API + Analyst Web Workbench (http://127.0.0.1:8000/)
python -m src.cli serve --host 127.0.0.1 --port 8000

# Or with hot reload (Windows PowerShell convenience script: .\scripts\start_local.ps1)
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload

# Optional Chainlit chat UI (requires API running on port 8000)
chainlit run src/ui/app.py --host 127.0.0.1 --port 8001

# Single-alert CLI investigation (offline cassette replay example)
python -m src.cli investigate ALT-2026-0412 --mode c1_single --llm replay --cassette eval/cassettes/e1_smoke_10.jsonl
```

### Available Verification Commands

| Check | Status | Exact Repository Command |
|---|---|---|
| **Build / Editable Package** | Available (Python only; no JS bundler) | `python -m pip install --no-deps -e .` (or `docker compose build` if Docker is available) |
| **Lint (Python)** | Available (`ruff`) | `python -m ruff check src/ eval/ data/generator_v2/ data/regulatory_corpus/ tests/ scripts/ --select E,F,B,S,DTZ,BLE,T20,C901` |
| **Type-check (Python)** | Available (`mypy --strict`) | `python -m mypy src/ --strict` |
| **Unit & Integration Tests** | Available (`pytest`) | `python -m pytest tests/ -q` |
| **Frontend DOM & SSE Contract Tests** | Available (`pytest`) | `python -m pytest tests/test_frontend_integrity.py -q` |
| **CI Offline Replay & Held-Out Zero-Drift Gates** | Available (`eval.verify_gates`) | `python -m eval.verify_gates` |
| **Full Keyless Replay Suite** | Available (`make replay`) | `python -m eval.run_replay_suite` |
| **Combined CI Gate (`make verify`)** | Available (requires `make` or run 4 commands above) | `make verify` |
| **Live Multi-Process E2E Script** | Conditional (requires `.env` credentials + live OpenRouter key) | `python scripts/verify_live_e2e.py` |
| **Held-Out Leakage Check** | Available | `python scripts/purge_operational_db.py --check` |

### Unavailable Verification Capabilities (Do Not Fabricate)
- **JavaScript / CSS Bundler or Build:** Not applicable — `src/ui/static/` uses native browser ES Modules and plain CSS with zero build step.
- **JavaScript / CSS Linter or TypeScript Checker:** Not available (no ESLint, Stylelint, Prettier, or `tsc` in the repo).
- **Automated Browser E2E Framework (Playwright / Cypress / Selenium):** Not installed in the repository. Interactive UI verification relies on starting the local server and driving a real browser via the agent's browser automation tool/subagent when available; if browser tooling is unavailable in the environment, report `BLOCKED`.

---

## 4. Coding Standards

### Python Style, Types & Complexity
- Start modules with `from __future__ import annotations`.
- **Strict typing in `src/`:** Every function and method in `src/` must have complete type annotations passing `python -m mypy src/ --strict` (`disallow_untyped_defs = true`, `no_implicit_optional = true`, `warn_unused_ignores = true`).
- **Ruff rules:** Must pass `--select E,F,B,S,DTZ,BLE,T20,C901` with `line-length = 120` and `max-complexity = 12`.
  - Use timezone-aware UTC datetimes (`DTZ`; prefer `utc_now()` / `utc_now_iso()` from `src/core/canonical.py` or `src/db/database.py`).
  - No `print()` in `src/` (`T20` — use `logging` or `typer.echo` in CLI).
  - Never use bare `except Exception:` (`BLE`) without narrow exception types or explicit documented justification.
- **Modularity:** Keep `src/` files concise (`<= 600` lines) and functions small (`<= 80` lines) by extracting cohesive helper modules.

### Domain & Architectural Invariants
- **Exact Decimal Arithmetic:** All INR amounts, USD costs, ratios, and confidences must use `Decimal` (`Money`, `Ratio`, `Confidence`, `Usd` in `src/core/canonical.py`), serialized as canonical strings. Never perform floating-point arithmetic on currency or cost totals.
- **Strict Schemas:** Inherit Pydantic models from `StrictModel` (`ConfigDict(extra="forbid")`).
- **Configuration as Truth:** Model slugs, budgets, timeouts, and graph bounds belong in `config/models.yaml` (`PolicyConfig`). Runtime UI/Admin model updates persist to SQLite `system_flags` (`resolve_model_for_role` in `src/agent/planning.py`), validated against `allowed_models`, and are bypassed during `llm_mode="replay"` to preserve deterministic cassette hashes.
- **Deterministic Safety Core:** Never bypass `GuardedToolbox`, RBAC tool allow-lists (`src/guardrails/hooks.py`), `verify_worksheet` (`src/core/verifier.py`), or single-use HMAC human approval commits (`src/api/services/approval.py`).
- **Held-Out Isolation:** Code in `src/` and `data/` must **never** read `eval/golden_v2/held_out/`, `eval/golden_v2/challenge/`, or `eval/held_out/`.

### Error Handling & Logging
- MCP tool failures must return structured `{status: "error", error_code, message}` dicts via `call_mcp_tool` and be surfaced as first-class `tool_errors` in `InvestigationState` — never silently swallowed.
- FastAPI unhandled exceptions return masked `500` responses with a 12-character `correlation_id` (`src/api/main.py`).
- Use `logging.getLogger("auditguard.<area>")` and `emit_loki_log(...)`. Never log raw API keys, passwords, JWTs, approval tokens, or unredacted PII — all external log payloads pass through `src/observability/redaction.py`.

### Frontend Conventions (`src/ui/static/`)
- Pure vanilla HTML/CSS/ES Modules; escape untrusted text via `esc()` before DOM insertion.
- Keep static DOM IDs referenced by `document.getElementById(...)` in `app.js` synchronized with `index.html` (enforced by `tests/test_frontend_integrity.py`).

### Testing Standards
- Write tests in `tests/` using `pytest` and `pytest-asyncio` (`asyncio_mode = "auto"`).
- Rely on `tests/conftest.py`'s `isolated_operational_db`, `client`, and `auth` fixtures — **never** modify `data/auditguard.db` during tests (a session-level guard fails the run if its mtime changes).
- Use `tests/fakes.py` (`FakeLLM`, `make_tool_turn`, `make_text_turn`) or `LLMClient(mode="replay", ...)` for deterministic offline agent tests without live API keys.
- Never hard-code evaluation metrics or weaken verifier/security assertions to force a pass.

### Documentation Standards
- `docs/evaluation_report.md` is auto-generated from `eval/replay_bundle/*.json` via `python -m eval.report` — never hand-edit numbers in it.
- Keep docstrings accurate to source code; update relevant docs when changing architecture, endpoints, or configuration schemas.

---

## 5. Mandatory Autonomous Execution Rules

All future development agents MUST follow these rules:

1. **End-to-End Ownership:** Implement every requested feature or bugfix completely. Do not stop after analysis, planning, or partial implementation.

2. **No Intermediate Confirmation:** Do not ask for approval between implementation steps. Make reasonable engineering decisions consistent with the existing architecture and complete the task autonomously.

3. **Self-Healing:** After implementation, run the applicable build, lint, type-check, and automated test commands. Analyze failures, fix the underlying issues, and rerun the checks iteratively until they pass.

4. **Regression Prevention:** Do not introduce unnecessary changes to existing functionality. Add or update tests where appropriate.

5. **Workspace Isolation:** Never modify, create, or delete files outside the authorized project workspace. Do not modify unrelated repositories or global system configurations.

6. **Git Safety:** Never execute `git commit`, `git push`, or publish changes remotely. Leave all modifications available for my review.

7. **Truthful Reporting:** Never claim a build, test, lint check, or browser verification passed unless it was actually executed successfully.

8. **No Destructive Shortcuts:** Do not disable tests, suppress errors, weaken lint rules, or remove existing functionality merely to achieve a passing result.
