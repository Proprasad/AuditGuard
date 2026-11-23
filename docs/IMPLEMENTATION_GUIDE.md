# AuditGuard — In-Depth Local Setup, Configuration & Execution Guide

This guide provides the exact prerequisites, architecture summary, environment variables, database setup, single-command local startup, API examples, and troubleshooting instructions for the **AuditGuard** capstone implementation.

---

## 1. Prerequisites & Local Runtime Environment

- **Operating System:** Windows 10/11, macOS, or Linux (CPU-only; no GPU required)
- **Python:** Python `>= 3.10` (verified on Python `3.10.8`)
- **Database (Local Default):** Built-in Python `sqlite3` (`data/auditguard.db`) — **zero external database server required to run locally**
- **Optional Full-Stack Containers:** Docker Desktop `>= 4.30` with Docker Compose v2 (for PostgreSQL 16, 4 HTTP FastMCP containers, Chainlit, Loki, Prometheus, and Grafana)

---

## 2. Installation Steps (Local Machine)

Open PowerShell in the project directory:

```powershell
cd "c:\Users\User\Desktop\Generative AI\capstone-project"

# (Optional) Create & activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install core runtime + LangGraph + FastMCP + test/lint suite
pip install --upgrade pip
pip install -e ".[dev]"
```

Optional extras (Chainlit UI, extra RAG/LLM/observability packages):
```powershell
pip install -e ".[llm,rag,ui,observability]"
```

---

## 3. Single-Command Local Startup

Run the PowerShell launcher script:

```powershell
.\scripts\start_local.ps1
```

Or via the Python CLI directly:

```powershell
python -m data.synthetic_generator
python -m src.cli serve --host 127.0.0.1 --port 8000
```

Once started, open:
- **Interactive Compliance Analyst Workbench:** `http://127.0.0.1:8000/`
  - **9 Sidebar Views:** `Investigation`, `Alerts Queue`, `Cases`, `Customers` (with Forget API), `Graph Explorer`, `Regulatory KB` (Hybrid RAG search), `Audit Trail`, `Analytics`, `Settings`.
  - **Interactive Transaction Network Graph:** Hierarchical, Force-Directed & Circular layouts; pan, wheel-zoom, node drag, account search filter, candidate-path focus, and click-to-inspect node/edge evidence.
  - **Decimal Financial Charts:** Donut flow conservation summary & cumulative multi-day timeline.
  - **Cryptographic Human Gate:** Approve & Commit, Edit Worksheet (re-verifies & invalidates old SHA-256), and Reject.
- **Swagger OpenAPI Docs:** `http://127.0.0.1:8000/api/docs`
- **Health Check:** `http://127.0.0.1:8000/health`
- **Prometheus Metrics:** `http://127.0.0.1:8000/metrics`

---

## 4. Configuration Reference (`.env` & `config/models.yaml`)

Copy `.env.example` to `.env`:

```powershell
Copy-Item .env.example .env
```

| Environment Variable | Default | Purpose |
|----------------------|---------|---------|
| `ENVIRONMENT` | `development` | Runtime profile (`development`, `staging`, `production`) |
| `SQLITE_DB_PATH` | `data/auditguard.db` | Local relational SQLite database file |
| `USE_POSTGRES` | `false` | Set `true` in Docker/production to use PostgreSQL |
| `MCP_TRANSPORT` | `inprocess` | `inprocess` (single-process local execution) or `http` (4 separate FastMCP HTTP servers on `:8010–8013`) |
| `OPENAI_API_KEY` | `sk-placeholder` | OpenRouter/OpenAI API key (deterministic evidence-grounded reasoning runs locally when unset) |
| `OPENAI_MODEL` | `openai/gpt-4.1-mini` | Pinned model for C1 investigator & C2 specialists |
| `OPENAI_STRONG_MODEL` | `openai/gpt-4.1` | Pinned model for C2 supervisor |
| `API_SECRET_KEY` | `auditguard-dev-jwt...` | HS256 JWT signing secret |
| `AUTH_REQUIRED` | `false` | When `true`, every `/api/v1/*` request requires a valid `Authorization: Bearer <jwt>` header |
| `HMAC_SECRET` | `auditguard-dev-hmac...` | Server-side secret signing single-use SHA-256 human approval tokens |
| `MAX_TOOL_BUDGET_USD` | `0.15` | Hard per-case spend cap |
| `GRAPH_TIME_WINDOW_DAYS` | `7` | Initial lookback window (bounded to `[1, 30]`) |
| `GRAPH_MAX_HOPS` | `3` | Initial max traversal hops (bounded to `[2, 5]`) |
| `GRAPH_AMOUNT_TOLERANCE` | `0.10` | Initial conservation tolerance (bounded to `[0.01, 0.25]`) |

---

## 5. Complete Primary Workflow & API Examples

### 5.1 Issue a Bearer JWT Token (Optional when `AUTH_REQUIRED=false`)
```powershell
curl -X POST http://127.0.0.1:8000/api/v1/auth/token `
  -H "Content-Type: application/json" `
  -d "{\"username\": \"analyst_04\", \"role\": \"tier2_analyst\"}"
```

### 5.2 Run Walkthrough 1 (`ALT-2026-0412`: Staggered Day-11 Fee-Skimming Scatter-Gather)
```powershell
curl -X POST http://127.0.0.1:8000/api/v1/investigations/run `
  -H "Content-Type: application/json" `
  -d "{\"alert_id\": \"ALT-2026-0412\", \"mode\": \"c2_multi\"}"
```
- Initial 7-day / 3-hop scan finds 3 outbound legs (INR `9,00,000.00`) and `0` consolidation hops.
- Supervisor triggers **bounded replanning** (`replan_count=1` -> `30d / 5 hops / 0.20 tolerance`), uncovering Day-11 consolidation into `ACC-IND-9001` (`INR 8,28,000.00`, exact `8.00%` fee retained).
- Returns `status: "interrupt_required"`, `recommended_disposition: "escalate_str"`, and canonical `payload_hash` (`H1`).

### 5.3 Edit Worksheet (Demonstrates Cryptographic SHA-256 Hash Invalidation)
```powershell
curl -X POST http://127.0.0.1:8000/api/v1/investigations/<thread_id>/decision `
  -H "Content-Type: application/json" `
  -d "{\"action\": \"edit\", \"edited_fields\": {\"recommendation_rationale\": \"Analyst verified Day-11 consolidation.\"}, \"reviewer_id\": \"analyst_04\"}"
```
- Re-verifies math & prohibited claims, invalidates `H1`, and emits fresh `payload_hash` (`H2`). Attempting to approve with stale `H1` returns `HTTP 403 APPROVAL_HASH_MISMATCH`.

### 5.4 Approve & Commit Disposition (Exact Hash + Single-Use Idempotency)
```powershell
curl -X POST http://127.0.0.1:8000/api/v1/investigations/<thread_id>/decision `
  -H "Content-Type: application/json" `
  -d "{\"action\": \"approve\", \"decision\": \"escalate_str\", \"approved_hash\": \"<H2>\", \"reviewer_id\": \"analyst_04\", \"notes\": \"Approved for STR review.\"}"
```
- Atomically commits to `cases` and `audit_logs` in `data/auditguard.db` and archives the episode in `case_episodes`. Re-submitting returns `HTTP 409 ALREADY_COMMITTED`.

### 5.5 Run Walkthrough 2 (`ALT-2026-0508`: Benign GST Marketplace Payout)
```powershell
python -m src.cli investigate ALT-2026-0508 --mode c2_multi
```
- Corroborates active `MARKETPLACE` commercial registration (`CraftBazaar India Marketplace Pvt Ltd`) and low KYC risk -> recommends `close_benign`.

---

## 6. Executing Automated Tests & Evaluation Experiments

```powershell
# 1. Full automated test suite (26 tests: API, Auth, Crash/Resume, Graph Decimal, MCP, Memory, Red-Team)
python -m pytest tests/ -v

# 2. 35-Query Hybrid RAG Retrieval Benchmark (BM25 vs. Hybrid RRF + Rerank)
python -m src.cli retrieval-bench

# 3. Experiment E1: C0 Fixed vs. C1 Single-Agent vs. C2 Multi-Agent
python -m eval.run_eval --config E1 --split dev

# 4. Experiment E2: 32-Case Red-Team Security Suite + False-Block Check
python -m eval.run_eval --config E2

# 5. Experiment E3 & E4: Reflexion Playbook & Signature Replanning Ablations
python -m eval.run_eval --config E3 --split dev
python -m eval.run_eval --config E4 --split dev
```

---

## 7. Full Docker Compose Deployment (Optional)

```powershell
Copy-Item .env.example .env
# Edit .env: set MCP_TRANSPORT=http and OPENAI_API_KEY=<your_key>
docker compose up --build -d
```

---

## 8. Troubleshooting Common Issues

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `Port 8000 already in use` | Existing `uvicorn` process bound to `:8000` | Run `python -m src.cli serve --port 8005` or stop the existing Python process |
| `HTTP 403 APPROVAL_HASH_MISMATCH` | Worksheet was edited after `payload_hash` was read | Copy the new `payload_hash` returned by the edit response or reload `/state` |
| `HTTP 409 ALREADY_COMMITTED` | Duplicate click / replay of an already-committed case | Expected single-use idempotency guard; start a new investigation thread |
| `HTTP 422 GUARDRAIL_BLOCKED` | Input text matched prompt-injection filter (e.g. `Ignore previous instructions`) | Remove override/meta-prompt phrasing from notes or rule fields |
| `Alert not found` on custom ID | SQLite DB not seeded yet | Run `python -m data.synthetic_generator` |
