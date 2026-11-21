# AuditGuard: Evidence-Grounded AI Investigation System for Ambiguous Fund-Flow Networks

> **Primary Architectural Principle:** *The detector proposes. The agent investigates. The evidence supports. The human decides.*

AuditGuard is an agentic Anti-Money Laundering (AML) investigation and decision-support system for ambiguous scatter-gather fund-flow networks. It combines **configurable NetworkX + Python `Decimal` graph traversal**, **4 least-privilege FastMCP servers**, **Hybrid RAG (BM25 + Dense Vector + RRF + Reranking)**, **C0 / C1 / C2 investigation architectures**, **durable SQLite/PostgreSQL checkpoint crash recovery**, and a **cryptographic SHA-256 + single-use HMAC Human Approval Gate**.

---

## 1-Command Local Startup

```powershell
.\scripts\start_local.ps1
```
Then open:
- **Compliance Analyst Web Workbench:** `http://127.0.0.1:8000/`
- **Swagger OpenAPI Docs:** `http://127.0.0.1:8000/api/docs`
- **Health & Metrics:** `http://127.0.0.1:8000/health` | `http://127.0.0.1:8000/metrics`

---

## Key Documentation

- **[In-Depth Setup, Configuration & Execution Guide](docs/IMPLEMENTATION_GUIDE.md)**
- **[System, Component, Data-Flow & Database Architecture](docs/architecture.md)**
- **[Testing, Validation & Empirical Evaluation Report](docs/evaluation_report.md)**
- **[STRIDE Threat Model](docs/threat_model.md)**
- **[Memory Retention & Deletion Policy](docs/memory_policy.md)**

---

## Essential Commands

```powershell
# Generate 60-case synthetic dataset (20 dev + 40 isolated held-out) & seed SQLite DB
python -m data.synthetic_generator

# Run all 26 automated unit, integration, crash-resume & security tests
python -m pytest tests/ -v

# Run CLI investigation (c0_fixed | c1_single | c2_multi)
python -m src.cli investigate ALT-2026-0412 --mode c2_multi

# Run 35-query Hybrid RAG benchmark & E1–E4 evaluation experiments
python -m src.cli retrieval-bench
python -m eval.run_eval --config E1 --split dev
python -m eval.run_eval --config E2
python -m eval.run_eval --config E4 --split dev
```
