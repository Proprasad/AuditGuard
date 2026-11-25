# AuditGuard — Live LLM End-to-End Validation Executive Summary

- **Run ID:** `live_20261124_213206`
- **Timestamp (UTC):** `2026-11-24T21:32:06Z` – `2026-11-24T21:44:52Z`
- **Live Provider & Model:** OpenRouter (`https://openrouter.ai/api/v1`) — `anthropic/claude-haiku-5.5`
- **Execution Mode:** `LLMClient(mode="live")` (zero mocks, zero `FakeLLM`, zero cassette replay; isolated temp SQLite DB; operational `data/auditguard.db` untouched)
- **Overall Verdict:** **LIVE VALIDATION PARTIALLY PASSED**

---

## 1. What Was Tested
1. **Suite A — Live C1 Single-Agent ReAct:** 6 approved synthetic dev scenarios (`S1, S2, S6, S8, S9, S10`) via `run_investigation(..., llm_mode="live")`.
2. **Suite B — Live C2 Multi-Stage Supervisor + 4 Specialists:** All 11 pre-registered synthetic dev scenarios (`S1–S11`) via `run_multi_agent(..., llm_mode="live")` across the 7-stage LangGraph topology.
3. **Suite C — Dynamic MCP Tool Selection & Role Isolation:** Independent live LLM calls for all 4 specialist roles plus 8 live runtime security/RBAC/bounds/JSON/error probes.
4. **Suite D & E — Competing Hypotheses & Evidence Grounding:** Evaluated `hypothesis_assessment`, `evidence_claims`, `critic_assessment`, and deterministic `verify_worksheet` across all 17 live runs plus 5 negative grounding probes against a live-generated worksheet.
5. **Suite F — Evidence-Driven Replanning:** Evaluated replan triggering, before/after comparison, and `initial_fund_flow_paths` preservation across all 17 live runs.
6. **Suite G — Checkpointing, Crash Recovery & Human Approval Gate:** Controlled mid-run `SimulatedCrashInterrupt` recovery across 7 graph boundaries (`6` C2 stages + `1` C1 stage) plus 6 end-to-end Human Approval Gate enforcement checks (token minting, hash mismatch, restricted edit invalidation, stale-token rejection, valid HMAC commit, replay rejection).

---

## 2. High-Level Outcome Summary

| Dimension | Classification | Headline Live Finding |
|---|---|---|
| **OpenRouter Live Provider Execution** | **PASS** | `199` live LLM calls completed with `0` HTTP/provider errors (avg latency `4,932.2ms`, p95 `8,056.5ms`). |
| **C1 Single-Agent ReAct** | **PARTIAL** | Genuine multi-turn observation-driven tool calls and 1 live replan (`S2`, `0->5` paths, `improved=True`), **but 6/6 runs ended in fail-closed forced `request_info`** due to `max_tokens=2048` truncation on `finish`/`find_candidate_fund_flows` and `$0.15` cost budget exhaustion. |
| **C2 Multi-Stage Orchestration** | **PARTIAL** | All 11/11 runs traversed the real 6-node live graph (`supervisor_plan -> flow_tracer -> parallel_specialists -> hypothesis_evaluation -> supervisor_replan_check -> reporter_critic -> human_gate`), **but 11/11 runs fell back to forced `request_info`** because `reporter_critic` (`max_tokens=1536`) truncated `finish` JSON 21/21 times and `supervisor_replan_check` (`max_tokens=512`) truncated 11/11 times. |
| **C2 Supervisor Dynamic Routing** | **PARTIAL** | Supervisor generated case-specific objectives and plans (`11/11` `finish_reason="stop"`), and `build_routing_plan` enforced mandatory 4-role coverage & reserved critic budgets; however, **all 4 specialist roles are mandatory** (none conditionally skipped) and the supervisor's replan decision failed 11/11 times due to hardcoded `max_tokens=512`. |
| **Dynamic MCP Tool Selection & RBAC** | **PASS** | `4/4` live specialists selected only permitted tools; `8/8` unauthorized/invalid/out-of-bounds/malformed-JSON/error probes were cleanly rejected and logged. |
| **Competing Hypothesis Evaluation** | **PARTIAL** | Deterministic `hypothesis_assessment` evaluated both suspicious and benign typologies (`7` suspicious_supported, `3` benign_supported, `7` tie/insufficient) and avoided blind guilt inference; however, LLM-generated final hypotheses never completed via `finish` due to `max_tokens` truncation. |
| **Evidence Grounding & Verification** | **PARTIAL** | `17/17` final worksheets passed deterministic `verify_worksheet`; `4/5` negative probes passed cleanly (5th probe also rejected the worksheet, failing earlier at `citations_exist` due to harness fixture setup); `4/51` claims (`CLM-01` on forced-finish C1 runs without citations) were flagged `ungrounded`. Online semantic assessment is currently structural/deterministic, not an LLM semantic judge. |
| **Evidence-Driven Replanning** | **PARTIAL** | **Live C1 `S2` proved full replanning (`RPL-01`)**: observed `0` paths in 7d window -> widened to `30d/4h/0.15` -> preserved `initial_fund_flow_paths=0` -> uncovered `5` multi-hop paths (`improved=True`). **Live C2 replanning FAILED (`0/11` executed)** because `_supervisor_should_replan` hardcoded `max_tokens=512`, truncating every reply (`finish_reason="length"`). |
| **Checkpointing & Crash Recovery** | **PASS** *(on reached stages)* | `6/6` reached crash boundaries (`supervisor_plan`, `flow_tracer`, `parallel_specialists`, `hypothesis_evaluation`, `reporter_critic`, `c1:agent_loop`) recovered cleanly with `0` repeated stages and `1` worksheet row. `flow_replan` crash recovery was **NOT TESTED** live because live C2 never reached `flow_replan`. |
| **Human Approval & Disposition Gate** | **PASS** | `6/6` live gate enforcement checks passed (single-use HMAC minting, wrong-hash rejection, edit hash invalidation, stale-token rejection, valid commit, and replay rejection `ALREADY_COMMITTED`). |

---

## 3. Major Production Risks Discovered
1. **P0 — `max_tokens` Truncation on Hybrid-Reasoning Models (`anthropic/claude-haiku-5.5`):**
   - `c2_loop.py:263` hardcodes `max_tokens=512` for `_supervisor_should_replan` -> **11/11 calls truncated (`finish_reason="length"`)**, completely disabling live C2 replanning.
   - `config/models.yaml` sets `max_tokens=1536` for `c2_specialists` (`reporter_critic`) and `2048` for `c1_investigator` -> **21/21 C2 `finish` calls and 5 C1 `finish` calls truncated mid-JSON (`INVALID_TOOL_JSON`)**, collapsing 100% of live runs to fail-closed forced `request_info`.
2. **P0 — Optional `transactions` Array in `LLMFindFlowsInput` Schema Causes Token Waste & Truncation:**
   - Exposing `transactions: list[TransactionEdge]` in the OpenAI tool schema caused the live LLM to copy-paste 40+ transactions inline into `find_candidate_fund_flows`, generating **20 `INVALID_TOOL_JSON` failures** (`16` C1 + `4` C2) and massive prompt bloat.
3. **P0 — Prompt Bloat vs. `$0.15` Per-Case Cost Cap on Pricier Models:**
   - Average prompt consumption was `~115K` tokens/case (`2,154,574` total tokens, `$2.38` across 17 runs, `93.2%` average budget utilization) on `anthropic/claude-haiku-5.5` (`$0.80/$4.00` per 1M). Hard `$0.15` caps halted `S1-C1`, `S10-C1`, and `S7-C2` before `finish`.
4. **P2 — Forced-Finish Rationale Grounding Gap:**
   - `persist_forced_finish` produces a rationale without inline evidence IDs; when `regulatory_citations` is empty (budget hit before `search_regulations`), `CLM-01` is flagged `ungrounded` (`4/51` claims).

---

## 4. Production-Readiness Assessment
**NOT READY for live production deployment with `anthropic/claude-haiku-5.5` (or other reasoning-token models) until P0 items 1–3 are resolved and re-validated live.**
The deterministic safety core (MCP RBAC, policy bounds, thread-safe `BudgetLedger` hard caps, fail-closed verifier, durable LangGraph multi-stage checkpointing, and single-use HMAC human approval gate) performed **reliably and safely under live failure stress** — every single failing/truncated LLM run degraded safely to `request_info` with `0` autonomous filings, `0` RBAC bypasses, and `0` unhandled crashes.
