# AuditGuard: Evidence-Grounded AI Investigation System for Ambiguous Fund-Flow Networks

> **Primary Architectural Principle:** *The detector proposes. The agent investigates. The evidence supports. The human decides.*

AuditGuard is an agentic Anti-Money Laundering (AML) investigation and decision-support system for ambiguous scatter-gather fund-flow networks. It combines **compiled LangGraph `StateGraph` workflows (`C0` / `C1` / `C2`) with native `interrupt()` human gating**, **`nx.MultiDiGraph` + exact `decimal.Decimal` fund-flow math**, **4 least-privilege FastMCP servers invoked via `fastmcp.Client`**, **Hybrid RAG (Okapi BM25 + Subword/Concept Vectors + RRF + Reranking)**, **fail-closed deterministic verification**, and **single-use HMAC-SHA256 disposition commits**.

---

## Quick Local Setup & Startup

```powershell
# 1. Copy template and generate strong random local secrets + seeded user passwords
Copy-Item .env.example .env
python scripts/init_env.py

# 2. Launch the API & Analyst Workbench (sign in with ANALYST_PASSWORD / ADMIN_PASSWORD from .env)
.\scripts\start_local.ps1
```
- **Compliance Analyst Web Workbench:** `http://127.0.0.1:8000/`
- **Swagger OpenAPI Docs:** `http://127.0.0.1:8000/api/docs`
- **Health & Prometheus Metrics:** `http://127.0.0.1:8000/health` | `http://127.0.0.1:8000/metrics`

---

## Key Documentation

- **[In-Depth Setup, Configuration & Execution Guide](docs/IMPLEMENTATION_GUIDE.md)**
- **[System, Component, Data-Flow & Database Architecture](docs/architecture.md)**
- **[Testing, Validation & Empirical Evaluation Report](docs/evaluation_report.md)**
- **[Viva & Architecture Defense Q&A](docs/viva_questions_and_answers.md)**
- **[STRIDE Threat Model](docs/threat_model.md)**
- **[Memory Retention & Deletion Policy](docs/memory_policy.md)**

---

## Verification & Evaluation Commands

```powershell
# Static quality gates (zero errors across src/, eval/, tests/)
ruff check src/ eval/ tests/ --select E,F,B,S,DTZ,BLE,T20,C901
mypy src/

# Full 92-test unit, integration, HTTP-MCP, respx-LLM & 18-scenario adversarial suite
python -m pytest tests/ -v --cov=src

# Build & freeze dev-split Reflexion playbook and verify 0 held-out DB leakage
python scripts/build_frozen_playbook.py
python scripts/purge_operational_db.py --check

# Dual regulatory retrieval benchmarks (35 dev + 28 independent NL held-out queries) & E1–E4 evaluations
python -m src.cli retrieval-bench
python -m eval.run_eval --config E1 --split dev --repeats 1
python -m eval.run_eval --config E1 --split held_out --repeats 1
python -m eval.run_eval --config E2
python -m eval.run_eval --config E3 --split held_out --repeats 1
python -m eval.run_eval --config E4 --split held_out --repeats 1

# Live end-to-end verification (4 FastMCP HTTP servers + Uvicorn + Live OpenRouter across C0/C1/C2)
python scripts/verify_live_e2e.py
```
