# AuditGuard v3 — System, Component, Data-Flow & Database Architecture

> **Core Principle:** *The detector proposes. The agent investigates. The evidence supports. The human decides.*

---

## 1. High-Level System Architecture

```mermaid
flowchart TB
    Analyst["AML Compliance Analyst / Reviewer"] --> UI["Analyst Web Workbench (GET /) / Chainlit UI (:8001)"]
    UI --> API["FastAPI Gateway (:8000)<br/>PBKDF2 Login · HS256 JWT RBAC · Sliding-Window Rate Limit · Read-Only SSE"]
    API --> IG["Input Guardrails<br/>(Unicode/Hinglish Injection Block · Extended PII Scrubbing)"]
    IG --> LG["Compiled LangGraph StateGraph (c0_fixed | rule_engine | c1_single | c2_multi)<br/>AsyncSqliteSaver / AsyncPostgresSaver · recursion_limit · interrupt()"]

    subgraph LLM["Async LLM & Replay Layer (src/llm/)"]
        OR["OpenRouterClient (httpx.AsyncClient)<br/>OpenAI Tool Calling · Transcript JSONL Logging"]
        CS["CassetteStore (--llm live | record | replay | offline)<br/>Deterministic SHA-256 Request Keying"]
    end

    LG <--> OR
    OR <--> CS

    subgraph Core["Pure Domain Core (src/core/)"]
        PC["PolicyConfig & BudgetLedger<br/>(config/models.yaml: 15 calls · USD 0.15 · 3 replans · 2 retries)"]
        GM["MultiDiGraph + Python Decimal Math<br/>(Per-Path + Deduplicated Aggregate-Root Conservation)"]
        CR["Corroboration & Explicit Missing-Data Detector<br/>(Registry Age · 365d Counterparty Cadence · Stale/Missing KYC/External Legs)"]
        VF["Verifier v2 (6 Fail-Closed Checks)<br/>(INR Math <= 0.01 · Citations Exist/Relevant · Registered IDs · Guilt Families)"]
    end

    LG --> PC & CR & VF

    subgraph Persistence["Relational & Memory Store (SQLite WAL | PostgreSQL)"]
        CP["Checkpoints & Durable Events<br/>(thread_checkpoints · investigation_events · .langgraph.sqlite)"]
        OP["Read-Only Operational Tables (?mode=ro)<br/>(banks · customers · commercial_registry · accounts · transactions · alerts)"]
        CM["Write-Scoped Case Repo (SQL Authorizer)<br/>(worksheets · approval_tokens · cases · audit_logs)"]
        LTM["Long-Term Memory & Trace-Only Reflexion<br/>(entity_profiles · case_episodes · reflexion_playbook · users)"]
    end

    LG <--> CP
    LG <--> LTM

    LG --> Hooks["Pre-Tool Hooks (Per-Agent RBAC · Policy Bounds · BudgetLedger)<br/>Post-Tool Hooks (Extended PII Masking · XML-Escaped untrusted_data · Injection Withholding)"]

    subgraph MCP["4 Typed FastMCP Servers via fastmcp.Client (In-Memory | Streamable HTTP /mcp)"]
        S1["compliance-kb (READ — Retrieval v2)<br/>165 Passages (145 Reg + 20 Internal SOP) · BM25 + Dense SVD + RRF + Reranker + Abstention"]
        S2["graph-engine (COMPUTE)<br/>nx.MultiDiGraph + Aggregate-Root Decimal Conservation & Run Diff"]
        S3["bank-records (READ-ONLY)<br/>?mode=ro + query_only + 5s Deadline (<=200 rows) + Counterparty History"]
        S4["case-actions (WRITE - GATED)<br/>Idempotent Draft + Server Verifier + Single-Use HMAC Commit"]
    end

    Hooks --> S1 & S2 & S3 & S4
    S2 --> GM
    S3 --> OP
    S4 --> CM
    LG --> Gate{"LangGraph human_gate<br/>interrupt() + Single-Use HMAC Token"}
    Gate -->|"Approve (Exact SHA-256 + Single-Use Token + Active Interrupt)"| S4
    Gate -->|"Edit (Restricted Fields -> Re-Verify -> New SHA-256 & Token)"| VF
    Gate -->|"Reject"| CM
```

---

## 2. Component Responsibilities & Separation of Concerns

| Layer | Module(s) | Responsibility | Enforced Invariant |
|---|---|---|---|
| **Pure Core** | [canonical.py](../src/core/canonical.py), [policy.py](../src/core/policy.py), [graph_math.py](../src/core/graph_math.py), [corroboration.py](../src/core/corroboration.py), [scoring.py](../src/core/scoring.py), [verifier.py](../src/core/verifier.py), [adapters.py](../src/core/adapters.py) | Framework-free `Decimal` types, canonical SHA-256 hashing, `PolicyConfig` & thread-safe `BudgetLedger`, `nx.MultiDiGraph` per-path & deduplicated aggregate-root flow math, registration corroboration & explicit missing-data detection, and Verifier v2 (6 named checks). | Zero `fastapi`, `fastmcp`, or LLM SDK imports; zero `float` currency math; INR grounding within ₹0.01. |
| **Async LLM & Replay** | [client.py](../src/llm/client.py), [replay.py](../src/llm/replay.py), [schemas.py](../src/llm/schemas.py) | Async OpenRouter tool-calling client with PII-redacted transcript logging (`runs/<run_id>/transcripts.jsonl`) and deterministic SHA-256 `CassetteStore` for keyless CI replay. | Every LLM call logs model, tokens, USD cost, and latency; `--llm replay` fails closed on cassette miss. |
| **Agent Orchestration** | [graph.py](../src/agent/graph.py), [loop.py](../src/agent/loop.py), [c2_loop.py](../src/agent/c2_loop.py), [tools.py](../src/agent/tools.py), [nodes.py](../src/agent/nodes.py), [gathering.py](../src/agent/gathering.py), [c0_fixed.py](../src/agent/c0_fixed.py), [rule_engine.py](../src/agent/rule_engine.py) | Compiled LangGraph `StateGraph` across `c0_fixed`, `rule_engine`, `c1_single`, and `c2_multi`; local `calc`, `replan_graph`, and `finish` tools; case-specific regulatory query formulation; native `interrupt()` before commit. | `recursion_limit` bound to `max_replans`; fail-closed verifier repair retries (`<= 2`) before `human_gate`; forged-registry never auto-closes below corroboration threshold. |
| **Guardrails & FastMCP Fleet** | [guardrails.py](../src/guardrails/guardrails.py), [hooks.py](../src/guardrails/hooks.py), [client.py](../src/mcp_servers/client.py), [compliance_kb.py](../src/mcp_servers/compliance_kb.py), [graph_engine.py](../src/mcp_servers/graph_engine.py), [bank_records.py](../src/mcp_servers/bank_records.py), [case_actions.py](../src/mcp_servers/case_actions.py) | Unicode/homoglyph/multilingual injection detection, extended Indian PII masking, per-agent RBAC allow-lists, Retrieval v2 (165 passages, 4 pipelines, abstention, `source_type` filter), and 4 typed FastMCP servers. | Read-only SQLite URI on `bank-records`; SQL write-scope authorizer on `case-actions`; XML-escaped `<untrusted_data>` tags; `eval/golden_v2/held_out/` inaccessible to runtime code. |
| **Presentation & API** | [main.py](../src/api/main.py), [auth.py](../src/api/auth.py), [users.py](../src/api/users.py), [ratelimit.py](../src/api/ratelimit.py), `src/api/routes/*`, `src/api/services/*` | Modular FastAPI routers, PBKDF2 login, HS256 JWT RBAC (`analyst`, `senior_reviewer`, `admin`) with `jti` logout revocation, read-only SSE replay, restricted edits, atomic single-winner approval (`409 INTERRUPT_NOT_ACTIVE` fail-closed), and transactional Right-to-Erasure. | `AUTH_REQUIRED=true` by default; `reviewer_id` derived strictly from `jwt.sub`; `/metrics` bearer-token protected. |
| **Evaluation, Judge & Reporting** | [run_eval.py](../eval/run_eval.py), [red_team_runner.py](../eval/red_team_runner.py), [retrieval_eval.py](../eval/retrieval_eval.py), [judge.py](../eval/judge.py), [calibration.py](../eval/calibration.py), [stats.py](../eval/stats.py), [verify_gates.py](../eval/verify_gates.py), [report.py](../eval/report.py) | YAML-honoured concurrent E1–E4 harness, Wilson & 10k cluster-bootstrap 95% CIs, exact McNemar, anti-shortcut baselines, cross-family Gemini judge (`G1`–`G7`), CI zero-drift & smoke-replay gates, and programmatic `docs/evaluation_report.md` generation from `summary.json` only. | Held-out gold labels stripped before passing cases to agents; missing YAML metrics raise `NotImplementedError` / `VerificationGateError`. |

---

## 3. End-to-End Investigation & Cryptographic Approval Lifecycle

```mermaid
sequenceDiagram
    participant Analyst
    participant API as FastAPI Router + Services
    participant Graph as Compiled LangGraph (c0/rule/c1/c2)
    participant LLM as OpenRouterClient / CassetteStore
    participant MCP as FastMCP Fleet (fastmcp.Client)
    participant Ver as Verifier v2 (Fail-Closed)
    participant DB as SQLite WAL / PostgreSQL

    Analyst->>API: POST /api/v1/auth/token (username, password)
    API-->>Analyst: HS256 Bearer JWT (sub, role, jti)
    Analyst->>API: POST /api/v1/investigations (alert_id, mode)
    API->>DB: Register Checkpoint + "started" Event
    Analyst->>API: GET /api/v1/investigations/{thread_id}/stream (Bearer JWT)
    Graph->>MCP: bank-records.get_alert_context + graph-engine.find_candidate_fund_flows
    Graph->>MCP: KYC + Commercial Registry + get_counterparty_history(365d) + compliance-kb.search_regulations
    opt C1 / C2 LLM Tool Loop (or Bounded Replan)
        Graph->>LLM: Chat + Tool Schemas (RBAC-scoped)
        LLM-->>Graph: Tool Calls (replan_graph / compute_flow_conservation / calc / finish)
        Graph->>MCP: Execute Bounded Tools via GuardedToolbox
    end
    Graph->>Ver: verify_worksheet(candidate, evidence_registry, corpus_ids, calc_log)
    Ver-->>Graph: Passed (or up to 2 Repair Retries -> Fail-Closed request_info)
    Graph->>MCP: case-actions.draft_disposition_report (Idempotent + Server-Side Re-Verify)
    Graph->>DB: Suspend at human_gate interrupt() + Issue Single-Use Token T1 (Hash H1)
    API-->>Analyst: Live SSE Events -> interrupt_required (H1, T1)
    opt Reviewer Edits Rationale / Disposition
        Analyst->>API: POST /decision (action="edit", edit={...})
        API->>Ver: Re-Verify against Stored evidence_registry
        API->>DB: Bump Revision -> Supersede T1 -> Issue Fresh Token T2 (Hash H2)
        API-->>Analyst: interrupt_required (H2, T2)
    end
    Analyst->>API: POST /decision (action="approve", approved_hash=H2, approval_token=T2)
    API->>MCP: case-actions.submit_case_disposition(worksheet_id, T2, reviewer=jwt.sub)
    MCP->>DB: Verify Active Interrupt + Atomic Consume T2 + INSERT cases + audit_logs
    API->>Graph: Command(resume={"action": "approve"}) -> END
    API-->>Analyst: HTTP 200 committed (CASE-DISP-*, AUD-*)
```
