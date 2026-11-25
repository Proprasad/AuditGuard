# Live Validation Environment Manifest (`live_20261124_213206`)

- **Run ID:** `live_20261124_213206`
- **Timestamp (UTC):** `2026-11-24T21:32:06Z` – `2026-11-24T21:44:52Z`
- **Git HEAD:** `6401571` (branch `dev`)
- **Working Tree State:** Preserved unmodified (`16` pre-existing enhanced architecture/test/doc files untouched; zero modifications to `src/`, `tests/`, `config/`, or `eval/` during validation)
- **Python Runtime:** Python `3.10.8` on Windows (`win32`)

## LLM Provider & Runtime Configuration (Secrets Redacted)
- **Provider:** OpenRouter (`https://openrouter.ai/api/v1`)
- **API Key Status:** Configured (`sk-or-v1-2...87f9`, masked preview only)
- **Execution Mode:** `LLMClient(mode="live")` (`LLM_MODE=live`, isolated temp DB `llm_enabled=true`)
- **Active Models:**
  - `c1_investigator` / `c2_specialists`: `anthropic/claude-haiku-5.5`
  - `c2_supervisor`: `anthropic/claude-haiku-5.5`
- **Pre-Flight Connectivity Ping:** `{'ok': True, 'model': 'anthropic/claude-haiku-5.5', 'reply': 'READY', 'tokens': 22}`
- **Token/Cost/Retry Policy (`config/models.yaml`):**
  - `max_tool_calls`: `15`
  - `max_replans`: `3`
  - `max_critique_retries`: `2`
  - `max_cost_usd_per_case`: `$0.150000`
  - `c1_investigator.max_tokens`: `2048`, `c2_supervisor.max_tokens`: `2048` (replan check hardcoded `512` in `src/agent/c2_loop.py`), `c2_specialists.max_tokens`: `1536`

## Persistence, Checkpointing & Isolation
- **Operational DB (`data/auditguard.db`):** **UNTOUCHED** (never opened by validation harness)
- **Validation SQLite DB:** Isolated temporary file (`auditguard_live_20261124_213206_*/live_val_auditguard.db` + `.langgraph.sqlite` via `AsyncSqliteSaver`)
- **MCP Transport:** `inprocess` (`fastmcp.Client` in-memory transport across all 4 servers)
- **Retrieval Backend:** In-process Retrieval v2 (`compliance-kb`, 165 passages: 145 regulatory + 20 SOPs, BM25 + float32 SVD dense + RRF + reranker)

## MCP Server & Role-Scoped Tool Inventory
| MCP Server | Access Scope | Registered Tools |
|---|---|---|
| `bank-records` | READ-ONLY (`?mode=ro`, `LIMIT<=200`) | `get_alert_context`, `get_account_transactions`, `get_kyc_profile`, `get_counterparty_history`, `check_commercial_registry` |
| `graph-engine` | COMPUTE (`nx.MultiDiGraph` + `Decimal`) | `find_candidate_fund_flows`, `compute_flow_conservation`, `compare_graph_runs` |
| `compliance-kb` | READ-ONLY (Retrieval v2) | `search_regulations`, `get_clause_by_id` |
| `case-actions` | WRITE-GATED (Verifier + HMAC token) | `draft_disposition_report`, `submit_case_disposition` |
| Local Runtime | Guarded local helpers | `calc` (`Decimal`), `replan_graph`, `finish` |

## Approved Synthetic Test Dataset (`data/golden_v2/dev/` — Zero Real Customer / Held-Out Data)
- `S1`: `CASE-V2-0020` (`ALT-V2-D0020`, `layering.classic`)
- `S2`: `CASE-V2-0024` (`ALT-V2-D0024`, `benign_lookalike.marketplace`)
- `S3`: `CASE-V2-0013` (`ALT-V2-D0013`, `benign_lookalike.payroll`)
- `S4`: `CASE-V2-0002` (`ALT-V2-D0002`, `benign_lookalike.ngo`)
- `S5`: `CASE-V2-0012` (`ALT-V2-D0012`, `benign_lookalike.wedding`)
- `S6`: `CASE-V2-0011` (`ALT-V2-D0011`, `layering.staggered`)
- `S7`: `CASE-V2-0022` (`ALT-V2-D0022`, `layering.fee_skim`)
- `S8`: `CASE-V2-0005` (`ALT-V2-D0005`, `layering_benign_cover.shell_valid_gst`)
- `S9`: `CASE-V2-0014` (`ALT-V2-D0014`, `incomplete_data.missing_kyc`)
- `S10`: `CASE-V2-0028` (`ALT-V2-D0028`, `incomplete_data.missing_hop`)
- `S11`: `CASE-V2-0003` (`ALT-V2-D0003`, `ambiguous.benign_structure_high_risk_root`)
