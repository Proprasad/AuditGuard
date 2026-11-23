# AuditGuard — System, Component, Data-Flow & Database Architecture

> **Core Principle:** *The detector proposes. The agent investigates. The evidence supports. The human decides.*

---

## 1. High-Level System Architecture

```mermaid
flowchart TB
    Analyst["AML Compliance Analyst"] --> UI["Analyst Web Workbench (GET /) / Chainlit UI (:8001)"]
    UI --> API["FastAPI Gateway (:8000)<br/>PBKDF2 Login · HS256 JWT RBAC · Sliding-Window Rate Limit · Read-Only SSE"]
    API --> IG["Input Guardrails<br/>(Normalized Injection Block · PII Scrubbing)"]
    IG --> LG["Compiled LangGraph StateGraph (C0 | C1 | C2)<br/>AsyncSqliteSaver / AsyncPostgresSaver · recursion_limit · interrupt()"]

    subgraph Core["Pure Domain Core (src/core/)"]
        PC["PolicyConfig & BudgetLedger<br/>(config/models.yaml: 15 calls · USD 0.15 · 3 replans · 2 retries)"]
        GM["MultiDiGraph + Python Decimal Math<br/>(Deterministic SHA-256 PATH-* / CALC-* IDs)"]
        VF["Fail-Closed Verifier<br/>(Decimal Math · Evidence Registry Resolution · Guilt Regex Families)"]
    end

    LG --> PC & VF

    subgraph Persistence["Relational & Memory Store (SQLite WAL | PostgreSQL)"]
        CP["Checkpoints & Durable Events<br/>(checkpoints · investigation_events · .langgraph.sqlite)"]
        OP["Read-Only Operational Tables (?mode=ro)<br/>(banks · customers · commercial_registry · accounts · transactions · alerts)"]
        CM["Write-Scoped Case Repo (SQL Authorizer)<br/>(worksheets · approval_tokens · cases · audit_logs)"]
        LTM["Long-Term Memory & Governance<br/>(entity_profiles · case_episodes · reflexion_playbook · system_flags · users)"]
    end

    LG <--> CP
    LG <--> LTM

    LG --> Hooks["Pre-Tool Hooks (Per-Agent RBAC · Bounds · BudgetLedger)<br/>Post-Tool Hooks (PII Masking · XML-Escaped <untrusted_data> · Injection Withholding)"]

    subgraph MCP["4 Typed FastMCP Servers via fastmcp.Client (In-Memory | Streamable HTTP /mcp)"]
        S1["compliance-kb (READ)<br/>BM25 + Subword/Concept TF-IDF + RRF + Reranker"]
        S2["graph-engine (COMPUTE)<br/>nx.MultiDiGraph + Decimal Conservation & Run Diff"]
        S3["bank-records (READ-ONLY)<br/>?mode=ro + query_only + 5s Deadline (<=200 rows)"]
        S4["case-actions (WRITE - GATED)<br/>Idempotent Draft + Single-Use HMAC Commit"]
    end

    Hooks --> S1 & S2 & S3 & S4
    S2 --> GM
    S3 --> OP
    S4 --> CM
    LG --> Gate{"LangGraph human_gate<br/>interrupt() + Single-Use HMAC Token"}
    Gate -->|"Approve (Exact SHA-256 + Single-Use Token)"| S4
    Gate -->|"Edit (Restricted Fields -> Re-Verify -> New SHA-256 & Token)"| VF
    Gate -->|"Reject"| CM
```

---

## 2. Component Responsibilities & Separation of Concerns

| Layer | Module(s) | Responsibility | Enforced Invariant |
|---|---|---|---|
| **Pure Core** | [canonical.py](../src/core/canonical.py), [policy.py](../src/core/policy.py), [graph_math.py](../src/core/graph_math.py), [scoring.py](../src/core/scoring.py), [verifier.py](../src/core/verifier.py), [adapters.py](../src/core/adapters.py) | Framework-free `Decimal` types, canonical SHA-256 JSON hashing, `PolicyConfig` & thread-safe `BudgetLedger`, `nx.MultiDiGraph` path math, evidence-weighted rubric, and fail-closed worksheet verifier. | Zero `fastapi`, `fastmcp`, or LLM SDK imports; zero `float` currency math. |
| **Presentation & API** | [main.py](../src/api/main.py), [auth.py](../src/api/auth.py), [users.py](../src/api/users.py), [ratelimit.py](../src/api/ratelimit.py), `src/api/routes/*`, `src/api/services/*` | Thin modular routers (`ui`, `data`, `investigations`), PBKDF2 user auth, JWT role gates (`analyst`, `senior_reviewer`, `admin`), read-only SSE event subscriber, restricted edits, atomic approval, and transactional Right-to-Erasure. | `AUTH_REQUIRED=true` by default; `reviewer_id` derived strictly from `jwt.sub`; `500` errors masked with correlation IDs. |
| **LangGraph Orchestration** | [graph.py](../src/agent/graph.py), [nodes.py](../src/agent/nodes.py), [reasoning.py](../src/agent/reasoning.py), [drafting.py](../src/agent/drafting.py), [c0_fixed.py](../src/agent/c0_fixed.py), [c1_single.py](../src/agent/c1_single.py), [c2_multi.py](../src/agent/c2_multi.py) | Compiled `StateGraph` across `C0`, `C1`, and `C2` with deduplicating state reducers, `AsyncSqliteSaver`/`AsyncPostgresSaver`, structured LLM planning/hypotheses/critique, and native `interrupt()` before commit. | `recursion_limit` bound to `max_replans`; fail-closed critique retry loop (`<= 2`) before `human_gate`. |
| **Guardrails & FastMCP Fleet** | [guardrails.py](../src/guardrails/guardrails.py), [hooks.py](../src/guardrails/hooks.py), [client.py](../src/mcp_servers/client.py), `src/mcp_servers/*` | Pre/post tool enforcement and real `fastmcp.Client` transport (in-memory or `/mcp` streamable HTTP) across all 4 servers. | Read-only SQLite URI on `bank-records`; SQL authorizer write-scoping on `case-actions`; XML-escaped `<untrusted_data>` tags. |

---

## 3. End-to-End Investigation & Cryptographic Approval Lifecycle

```mermaid
sequenceDiagram
    participant Analyst
    participant API as FastAPI Router + Services
    participant Graph as Compiled LangGraph (C0/C1/C2)
    participant MCP as FastMCP Fleet (fastmcp.Client)
    participant Ver as Fail-Closed Verifier
    participant DB as SQLite WAL / PostgreSQL

    Analyst->>API: POST /api/v1/auth/token (username, password)
    API-->>Analyst: HS256 Bearer JWT (sub, role)
    Analyst->>API: POST /api/v1/investigations (alert_id, mode)
    API->>DB: Register Checkpoint + "started" Event
    Analyst->>API: GET /api/v1/investigations/{thread_id}/stream (Bearer JWT)
    Graph->>MCP: bank-records.get_alert_context + graph-engine.find_candidate_fund_flows
    Graph->>MCP: KYC + Commercial Registry + compliance-kb.search_regulations
    opt Evidence Contradiction & Replan Budget Available
        Graph->>Graph: critique_node -> replan_node (Widen Bounds)
        Graph->>MCP: graph-engine.find_candidate_fund_flows + compute_flow_conservation + compare_graph_runs
    end
    Graph->>Ver: verify_worksheet(candidate, evidence_registry)
    Ver-->>Graph: Passed (or up to 2 Critique Self-Correction Retries)
    Graph->>MCP: case-actions.draft_disposition_report (Idempotent per thread_id, revision)
    Graph->>DB: Suspend at human_gate interrupt() + Issue Single-Use Approval Token T1 (Hash H1)
    API-->>Analyst: Live SSE Events -> interrupt_required (H1, T1)
    opt Analyst Edits Rationale / Disposition
        Analyst->>API: POST /decision (action="edit", edit={...})
        API->>Ver: Re-Verify against Stored evidence_registry
        API->>DB: Bump Revision -> Supersede T1 -> Issue Fresh Token T2 (Hash H2)
        API-->>Analyst: interrupt_required (H2, T2)
    end
    Analyst->>API: POST /decision (action="approve", approved_hash=H2, approval_token=T2)
    API->>MCP: case-actions.submit_case_disposition(worksheet_id, T2, reviewer=jwt.sub)
    MCP->>DB: Atomic Consume T2 + INSERT cases (UNIQUE alert_id) + audit_logs
    API->>Graph: Command(resume={"action": "approve"}) -> END
    API-->>Analyst: HTTP 200 committed (CASE-DISP-*, AUD-*)
```
