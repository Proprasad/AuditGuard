# Failures, Anomalies & Forensic Root Causes (`live_20261124_213206`)

All anomalies below occurred during real live OpenRouter execution (`anthropic/claude-haiku-5.5`) and are documented without silently patching or hiding failures.

---

## Anomaly 1 — P0: `max_tokens=512` Truncated 11/11 C2 Supervisor Replan Decisions
- **Location:** `src/agent/c2_loop.py` (`_supervisor_should_replan`, `max_tokens=512`)
- **Observed Impact:** **11/11 live C2 scenarios** (`S1–S11`) hit `finish_reason="length"` at exactly `512` completion tokens. `8/11` returned empty visible text (`None`); `3/11` (`S4, S5, S11`) returned truncated JSON (`'{"request_replan": true, ...'`, `'{"request_replan": false, ...'`, `'{"'`).
- **Consequence:** `_parse_json_obj` returned `None` on all 11 runs; `flow_replan` was **never executed** in Suite B or Suite G, causing `S6` (staggered) to miss delayed consolidation in live C2.
- **Root Cause:** `anthropic/claude-haiku-5.5` consumes internal reasoning tokens out of `max_tokens` before emitting visible JSON. `512` tokens is insufficient for reasoning + JSON output.
- **Recommended Fix:** Raise `_supervisor_should_replan` `max_tokens` from `512` to `>= 2048` (or use `spec.max_tokens`) and consider `reasoning: {"effort": "low"}` or concise JSON schema instructions.

## Anomaly 2 — P0: `max_tokens=1536` / `2048` Truncated 26/26 Live `finish` Tool Calls
- **Location:** `config/models.yaml` (`c2_specialists.max_tokens=1536`, `c1_investigator.max_tokens=2048`)
- **Observed Impact:**
  - `reporter_critic:finish:INVALID_TOOL_JSON`: **21 occurrences** across `S1–S11` (every single C2 `finish` call hit `finish_reason="length"` at `1536` completion tokens!).
  - `c1_single:finish:INVALID_TOOL_JSON`: **5 occurrences** (`S2, S6, S8`), hitting `2048` completion tokens mid-JSON.
- **Consequence:** **17/17 live scenarios fell back to fail-closed `persist_forced_finish` (`request_info`)**, discarding the model's intended dispositions (e.g., `escalate_str` in `S1-C2`, `S6-C1`, `S8-C1`).
- **Recommended Fix:** Increase `max_tokens` in `config/models.yaml` to `>= 4096` for `c1_investigator`, `c2_supervisor`, and `c2_specialists` (especially `reporter_critic`), and instruct the model to keep `finish` rationale concise (2–3 sentences).

## Anomaly 3 — P0: Inline Transaction Copying Caused 20 `find_candidate_fund_flows` JSON Truncations
- **Location:** `src/agent/tool_schemas.py` (`LLMFindFlowsInput.transactions: Optional[list[TransactionEdge]]`)
- **Observed Impact:** `c1_single:find_candidate_fund_flows:INVALID_TOOL_JSON` (**16 occurrences**) and `flow_tracer:find_candidate_fund_flows:INVALID_TOOL_JSON` (**4 occurrences**), including 7 consecutive failures in `S10-C1`.
- **Root Cause:** Although `AgentToolRuntime._hydrate_graph_args` automatically populates `transactions` from session state, exposing the full nested `transactions` array in the OpenAI tool schema tempted `claude-haiku-5.5` into serializing 30–60 transactions verbatim, exceeding `max_tokens`.
- **Recommended Fix:** Remove `transactions` from the LLM-advertised `LLMFindFlowsInput` JSON schema (hydrate exclusively from `runtime.transactions`) — note that this will require updating/re-recording `eval/cassettes/e1_smoke_10.jsonl` if applied to replay mode.

## Anomaly 4 — P0: Prompt Token Bloat & `$0.15` Cost Budget Exhaustion
- **Observed Impact:** Total live run consumed `2,154,574` tokens (`$2.3765` across 17 runs, avg `93.2%` of the `$0.15`/case budget). Cost cap directly aborted `S1-C1` (`$0.1539`), `S10-C1` (`$0.1663`), and `S7-C2` (`$0.1509`) before `finish`.
- **Root Cause:** Full raw 40–60 transaction JSON arrays from `get_alert_context` remain in message history across 8–15 turns, multiplied by `anthropic/claude-haiku-5.5`'s `$0.80/$4.00` per-1M pricing (`3.2x` `gpt-5-mini`).
- **Recommended Fix:** Summarize/compact `get_alert_context` tool responses in LLM message history (keeping full transactions in `runtime.transactions` and `evidence_registry`!) and reserve cost headroom for `finish` / `reporter_critic`.

## Anomaly 5 — P1: Specialist Sub-Budget & Global Tool-Budget Contention
- **Observed Tool Errors (Non-JSON):**
  - `c1_single` `BUDGET_EXCEEDED`: `16` calls (`check_commercial_registry: 5`, `get_counterparty_history: 5`, `search_regulations: 3`, `calc: 2`, `find_candidate_fund_flows: 1`) — C1 spent too many calls on per-account `get_kyc_profile` loops before checking regulations/registry.
  - `benign_investigator` `SPECIALIST_BUDGET_EXCEEDED`: `7` calls (`calc: 6`, `check_commercial_registry: 1`).
  - `regulatory_analyst` `SPECIALIST_BUDGET_EXCEEDED`: `1` call.
  - `c1_single:get_kyc_profile:ACCOUNT_NOT_FOUND`: `2` calls (expected on `S9` missing-KYC case — handled gracefully!).

## Anomaly 6 — P2: Forced-Finish `CLM-01` Ungrounded & Suite E Probe 3 Detail
1. **Forced-Finish Claim Grounding:** On `S1, S2, S6, S10` (C1), forced finish ran before `search_regulations` succeeded, leaving `regulatory_citations=[]` and a rationale without inline IDs -> `build_evidence_claims` marked `CLM-01` as `ungrounded` (`4/51` claims total). Fix: include gathered `PATH-*`/`KYC-*`/`TXN-*` IDs in `persist_forced_finish`'s rationale.
2. **Suite E Probe 3 (`irrelevant_regulatory_citation`):** The worksheet WAS deterministically rejected (`passed=False`), but failed at `citations_exist` (`UNRESOLVED_CITATION`) rather than `citations_relevant` because the harness replaced only top-level `regulatory_citations` while leaving real clause IDs inside `hypotheses[].regulatory_citations` that were absent from the single-entry `corpus_ids` stub.
