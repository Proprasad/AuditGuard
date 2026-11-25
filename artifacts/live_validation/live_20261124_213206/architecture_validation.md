# Component-by-Component Live Architecture Validation (`live_20261124_213206`)

## 1. C1 — Single-Agent ReAct (`src/agent/loop.py`, `src/agent/tools.py`)
- **Status:** **PARTIAL**
- **Live Evidence:** Executed 6 live scenarios (`47` live LLM calls, `113` tool executions logged in `execution_log.jsonl`).
  - Confirmed real observation-driven behavior: in `S2` (`trace_id=s2_c1_single_*`), C1 observed `0` paths in the 7d scan (`root_account_not_in_window`), reasoned about the date gap, and dynamically called `replan_graph(30d, 4h, 0.15)`, discovering 5 paths and then calling `compute_flow_conservation`. In `S9`, C1 handled `ACCOUNT_NOT_FOUND` on missing KYC accounts and shifted to `get_account_transactions` + `search_regulations`.
  - Confirmed tool error & budget resilience: `BUDGET_EXCEEDED`, `INVALID_TOOL_JSON`, and `ACCOUNT_NOT_FOUND` were surfaced cleanly without crashing the loop.
- **Live Defect / Limitation:** **6/6 C1 runs degraded to fail-closed forced `request_info`** due to: (a) `max_tokens=2048` truncating `finish` tool JSON (`S2, S6, S8`), (b) `find_candidate_fund_flows` JSON truncation when the LLM attempted to inline 40+ transactions (`16` occurrences), and (c) `$0.15` cost budget exhaustion (`S1, S10`).

## 2. C2 — Multi-Stage Supervisor & 4 Specialists (`src/agent/c2_stages.py`, `src/agent/c2_routing.py`, `src/agent/c2_loop.py`)
- **Status:** **PARTIAL**
- **Live Evidence:** All 11/11 scenarios (`152` live LLM calls) traversed the real compiled 6-stage path `supervisor_plan -> flow_tracer -> parallel_specialists -> hypothesis_evaluation -> supervisor_replan_check -> reporter_critic -> human_gate`.
  - `supervisor_plan` completed cleanly (`finish_reason="stop"`, `1,109–1,583` completion tokens) on all 11 scenarios, producing tailored objectives and budgets.
  - `benign_investigator` and `regulatory_analyst` ran concurrently via `asyncio.gather` under the shared thread-safe `BudgetLedger` with zero race errors.
  - `reporter_critic` consistently executed `calc` / `compute_flow_conservation` before attempting `finish`, and `build_routing_plan` prevented specialist budgets from starving `reporter_critic`.
- **Honest Control Assessment:**
  - **All 4 specialist roles (`flow_tracer`, `benign_investigator`, `regulatory_analyst`, `reporter_critic`) are mandatory** by design (`MANDATORY_ROLES` coverage invariant in `src/agent/c2_routing.py`); none can be conditionally skipped. The supervisor dynamically controls **objectives, tool budget slices (clamped within global reserve), execution ordering metadata, and replan authorization** — NOT omitting core coverage roles.
  - **Live Defect:** `supervisor_replan_check` failed 11/11 times (`finish_reason="length"` at hardcoded `max_tokens=512`), and `reporter_critic` `finish` truncated 21/21 times (`finish_reason="length"` at `max_tokens=1536`), causing 11/11 forced finishes.

## 3. Dynamic MCP Tool Selection & Role Isolation (`src/guardrails/hooks.py`, `src/agent/tooling.py`, `src/agent/tools.py`)
- **Status:** **PASS**
- **Live Evidence (`SUITE_C` in `execution_log.jsonl`):**
  - `flow_tracer` (7 tools advertised) -> live LLM selected `get_alert_context`.
  - `benign_investigator` (5 tools advertised) -> live LLM selected `get_kyc_profile`.
  - `regulatory_analyst` (2 tools advertised) -> live LLM selected `search_regulations` (3 case-specific queries).
  - `reporter_critic` (5 tools advertised) -> live LLM selected `calc`.
  - `8/8` security probes rejected unauthorized calls (`flow_tracer.get_kyc_profile`, `flow_tracer.submit_case_disposition`, `regulatory_analyst.find_candidate_fund_flows`, `benign_investigator.draft_disposition_report`, `c1_single.nonexistent_mcp_tool`), out-of-bounds params (`time_window_days=99 -> POLICY_BOUNDS_EXCEEDED`), malformed JSON (`INVALID_TOOL_JSON`), and nonexistent alert (`INVALID_ALERT_ID`).

## 4. Competing Suspicious vs. Benign Hypothesis Evaluation (`src/agent/hypothesis_eval.py`)
- **Status:** **PARTIAL**
- **Live Evidence:** Every live run produced a populated `CompetingHypothesisAssessment` (`7` `suspicious`, `3` `benign`, `7` `tie_inconclusive` across the 17 runs), confirming the evaluator does NOT blindly classify alerts as suspicious.
- **Important Distinction & Limitation:**
  - `hypothesis_evaluation_node` and `run_independent_critique` are **deterministic structural/rule-based evaluators** (0 LLM calls), NOT live LLM semantic verification.
  - Because `finish(...)` truncated on 100% of live runs with `claude-haiku-5.5`, the LLM's own written competing hypotheses were replaced by `persist_forced_finish`'s generic 50/50 fallback hypotheses in the persisted worksheets.
  - On benign lookalike cases that had multi-hop paths (`S3` payroll, `S5` wedding), `hypothesis_evaluation` classified `suspicious/supported` when `benign_investigator` had not yet fetched full 365d counterparty history or corroborated registry within its sub-budget.

## 5. Evidence Grounding & Claim Verification (`src/core/claims.py`, `src/core/verifier.py`)
- **Status:** **PARTIAL**
- **Live Evidence:**
  - **Deterministic validation:** `17/17` persisted worksheets passed `verify_worksheet`; `47/51` claims verified (`4` `CLM-01` forced-finish rationales flagged `ungrounded` when `regulatory_citations=[]`). Negative probes confirmed deterministic rejection of `WRONG_CASE_EVIDENCE`, `UNRESOLVED_EVIDENCE_ID`, and `UNGROUNDED_CLAIM`.
  - **Semantic support assessment:** Online `CriticAssessment` caught `contradictory_evidence`, `missing_regulatory_support`, and `unsupported_benign` structurally, but **true prose-level LLM semantic entailment is not executed online** (only offline via `eval/judge.py`).

## 6. Evidence-Driven Replanning (`src/agent/replanning.py`, `src/agent/tools.py`, `src/agent/c2_stages.py`)
- **Status:** **PARTIAL**
- **Live Evidence:**
  - **C1 PASS (`S2`, `RPL-01`):** Live C1 observed `0` paths in 7d window -> invoked `replan_graph(30d, 4h, 0.15)` -> preserved `initial_fund_flow_paths` (`0`) -> discovered `5` new paths (`evidence_delta=+5`, `improved=True`).
  - **C2 FAIL (`0/11` executed):** `_supervisor_should_replan` hardcoded `max_tokens=512`, causing `finish_reason="length"` on 11/11 live C2 runs so `flow_replan` was never triggered.

## 7. Checkpointing, Crash Recovery & Human Gate (`src/agent/graph.py`, `src/api/services/approval.py`)
- **Status:** **PASS** *(graph-stage checkpointing & human gate)* / **NOT TESTED** *(`flow_replan` live branch)*
- **Live Evidence (`SUITE_G`):**
  - **6/6 reached stages recovered cleanly** (`c2_multi`: `supervisor_plan`, `flow_tracer`, `parallel_specialists`, `hypothesis_evaluation`, `reporter_critic`; `c1_single`: `agent_loop`): zero repeated stages, zero extra LLM calls after `reporter_critic`/`agent_loop`, and exactly `1` worksheet row in SQLite.
  - **Distinction:** Checkpointing operates at **LangGraph stage boundaries**, not inside individual turns of C1's internal `_drive_tool_loop`.
  - **Human Approval Gate:** `6/6` enforcement checks passed (`prepare_token_issued`, `wrong_hash_rejected`, `edit_invalidated_old_hash`, `stale_token_rejected_after_edit`, `valid_commit_succeeded`, `replay_commit_rejected`).
