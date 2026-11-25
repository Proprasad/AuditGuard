# Live Scenario-by-Scenario Validation Results (`live_20261124_213206`)

All expected behaviors were pre-registered before live execution and were not altered after observing model responses. Every row below comes directly from `execution_log.jsonl` and `raw_audit_results.json`.

---

## Suite A — Live C1 Single-Agent ReAct (6 Scenarios)

| Scenario | Case / Alert | Expected Disp. | Actual Disp. (Mode) | Forced Finish? | Replan | Paths (`init->final`) | Deterministic Hypothesis Eval (`leading / outcome`) | Tool Calls / Errors | LLM Calls / Tokens / Cost | Outcome |
|---|---|---|---|---|---:|---:|---|---:|---|---|
| **S1** | `CASE-V2-0020` (`ALT-V2-D0020`) | `escalate_str` | `request_info` | **YES** (cost `$0.1539/$0.15`) | 0 | `0 -> 0` | `benign / supported` *(incomplete flow scan)* | `15 / 3` | `9 / 155,490 / $0.1539` | **FAIL** |
| **S2** | `CASE-V2-0024` (`ALT-V2-D0024`) | `close_benign` or `request_info` | `request_info` | **YES** (`finish` `INVALID_TOOL_JSON`) | **1** (`RPL-01`, `improved=True`) | `0 -> 5` | `suspicious / supported` | `15 / 5` | `7 / 161,686 / $0.1594` | **PARTIAL** *(replan worked, finish truncated)* |
| **S6** | `CASE-V2-0011` (`ALT-V2-D0011`) | `escalate_str` | `request_info` | **YES** (`finish` `INVALID_TOOL_JSON`; attempted `escalate_str`) | 0 | `5 -> 5` | `suspicious / supported` | `15 / 2` | `5 / 77,119 / $0.0802` | **FAIL** *(intended `escalate_str`, truncated at `max_tokens`)* |
| **S8** | `CASE-V2-0005` (`ALT-V2-D0005`) | `escalate_str` or `request_info` | `request_info` | **YES** (`finish` `INVALID_TOOL_JSON`; attempted `escalate_str`) | 0 | `0 -> 0` | `benign / supported` | `15 / 4` | `8 / 166,611 / $0.1713` | **PARTIAL** *(attempted `escalate_str`, truncated)* |
| **S9** | `CASE-V2-0014` (`ALT-V2-D0014`) | `request_info` | `request_info` | **YES** (stopped without calling `finish`) | 0 | `0 -> 0` | `tie_inconclusive / insufficient_evidence` | `15 / 6` | `8 / 154,804 / $0.1549` | **PARTIAL** *(handled `ACCOUNT_NOT_FOUND`, hit budget)* |
| **S10** | `CASE-V2-0028` (`ALT-V2-D0028`) | `request_info` | `request_info` | **YES** (cost `$0.1663/$0.15` after 7 `find_candidate_fund_flows` JSON errors) | 0 | `0 -> 0` | `tie_inconclusive / insufficient_evidence` | `7 / 1` | `10 / 140,742 / $0.1663` | **PARTIAL** *(safe fail-closed, but repeated JSON truncation)* |

### C1 Key Runtime Observations
- **Genuine observation-driven reasoning confirmed in `S2`:** After `find_candidate_fund_flows` returned 0 paths (`root_account_not_in_window`), the C1 LLM explicitly reasoned *"Root outbound legs (TXN-D0024-001..007, Sep 5-7 2026) ... fall outside the 7-day window"* and invoked `replan_graph(time_window_days=30, max_hops=4, amount_tolerance="0.15")`, uncovering 5 paths (`PATH-01E4F8D69D8A`..`PATH-2271ED75F0DB`) while preserving `initial_fund_flow_paths = []`.
- **Genuine intent vs. truncation:** On `S6` and `S8`, the truncated `finish` payload explicitly started with `{"recommended_disposition": "escalate_str", ...}` — proving the LLM reached the right conclusion before `max_tokens=2048` severed its JSON.

---

## Suite B — Live C2 Multi-Stage Supervisor + 4 Specialists (11 Scenarios)

All 11 C2 scenarios executed nodes: `['supervisor_plan', 'flow_tracer', 'parallel_specialists', 'hypothesis_evaluation', 'supervisor_replan_check', 'reporter_critic']` -> paused at `human_gate (interrupt())` -> verified (`verification_status="passed"`).

| Scenario | Case / Alert | Expected Disp. | Actual Disp. | Critic Intended Disp. (Before Truncation) | Replan | Paths (`init->final`) | Deterministic Hypothesis Eval (`leading / outcome`) | Calls / Errs | LLM / Tokens / Cost | Outcome |
|---|---|---|---|---|---:|---:|---|---:|---|---|
| **S1** | `CASE-V2-0020` | `escalate_str` | `request_info` *(forced)* | `escalate_str` (`0.7...`) | 0 | `0 -> 5` | `suspicious / supported` | `12 / 5` | `15 / 129,493 / $0.1448` | **FAIL** *(truncation)* |
| **S2** | `CASE-V2-0024` | `close_benign` / `request_info` | `request_info` *(forced)* | `request_info` (`0.3...`) | 0 | `0 -> 0` | `tie_inconclusive / insufficient_evidence` | `11 / 3` | `13 / 107,659 / $0.1240` | **PARTIAL** |
| **S3** | `CASE-V2-0013` | `close_benign` / `request_info` | `request_info` *(forced)* | `escalate_str` (`0.6...`) | 0 | `5 -> 5` | `suspicious / supported` | `14 / 2` | `14 / 135,054 / $0.1534` | **FAIL** *(truncation & topology over-flag)* |
| **S4** | `CASE-V2-0002` | `close_benign` / `request_info` | `request_info` *(forced)* | `request_info` (`0.4...`) | 0 | `1 -> 1` | `tie_inconclusive / additional_investigation_required` | `13 / 2` | `14 / 112,604 / $0.1303` | **PARTIAL** |
| **S5** | `CASE-V2-0012` | `close_benign` / `request_info` | `request_info` *(forced)* | `escalate_str` (`0.7...`) | 0 | `5 -> 5` | `suspicious / supported` | `14 / 2` | `14 / 151,760 / $0.1645` | **FAIL** *(truncation)* |
| **S6** | `CASE-V2-0011` | `escalate_str` | `request_info` *(forced)* | `request_info` (`0.5...`) | 0 *(sup truncated)* | `0 -> 0` | `tie_inconclusive / insufficient_evidence` | `12 / 4` | `14 / 103,729 / $0.1230` | **FAIL** *(replan blocked by `max_tokens=512`)* |
| **S7** | `CASE-V2-0022` | `escalate_str` | `request_info` *(forced)* | Cost exhausted (`$0.1509/$0.15`) | 0 | `0 -> 5` | `suspicious / supported` | `14 / 1` | `14 / 137,457 / $0.1509` | **FAIL** *(cost cap + truncation)* |
| **S8** | `CASE-V2-0005` | `escalate_str` / `request_info` | `request_info` *(forced)* | `request_info` (`0.4...`) | 0 | `0 -> 0` | `benign / supported` | `11 / 5` | `14 / 106,574 / $0.1269` | **PARTIAL** |
| **S9** | `CASE-V2-0014` | `request_info` | `request_info` *(forced)* | `escalate_str` (`0.6...`) | 0 | `5 -> 5` | `suspicious / supported` | `14 / 3` | `15 / 124,111 / $0.1367` | **PARTIAL** |
| **S10** | `CASE-V2-0028` | `request_info` | `request_info` *(forced)* | `request_info` (`0.3...`) | 0 | `0 -> 0` | `tie_inconclusive / insufficient_evidence` | `11 / 3` | `14 / 110,366 / $0.1355` | **PARTIAL** |
| **S11** | `CASE-V2-0003` | `request_info` / `escalate_str` | `request_info` *(forced)* | `request_info` (`0.5...`) | 0 | `0 -> 0` | `tie_inconclusive / additional_investigation_required` | `10 / 2` | `11 / 79,315 / $0.1003` | **PARTIAL** |

---

## Suite C, E, and G Scenario Summaries
- **Suite C (Live Specialist Role Selection & RBAC):** **PASS** — `4/4` live specialists selected exclusively from their role-scoped tool catalogue (`flow_tracer -> get_alert_context`, `benign_investigator -> get_kyc_profile`, `regulatory_analyst -> search_regulations`, `reporter_critic -> calc`), and `8/8` security probes (`RBAC_DENIED`, `POLICY_BOUNDS_EXCEEDED`, `INVALID_TOOL_JSON`, `INVALID_ALERT_ID`) passed.
- **Suite E (Negative Grounding Probes on live S1 C2 worksheet):** **4/5 PASS, 1/5 HARNESS-LIMITED** — `wrong_case_evidence` (`WRONG_CASE_EVIDENCE`), `nonexistent_evidence_id` (`UNRESOLVED_EVIDENCE_ID`), `contradictory_evidence_and_unsupported_disposition` (flagged by `CriticAssessment` with `contradictory_evidence`, `missing_regulatory_support`, `unsupported_benign`), and `claim_without_evidence` (`UNGROUNDED_CLAIM`) all passed. On `irrelevant_regulatory_citation`, the worksheet was still rejected (`passed=False`), failing earlier at `citations_exist` because the live worksheet's `hypotheses[].regulatory_citations` retained real clause IDs excluded from the custom `corpus_ids` stub.
- **Suite G (Live Crash Recovery & Human Gate):**
  - Crash Recovery: **6/6 reached stages PASS** (`c2_multi:supervisor_plan`, `c2_multi:flow_tracer`, `c2_multi:parallel_specialists`, `c2_multi:hypothesis_evaluation`, `c2_multi:reporter_critic`, `c1_single:agent_loop`); `c2_multi:flow_replan` **NOT TESTED** live because `_supervisor_should_replan` truncated at `max_tokens=512` before emitting `request_replan=true`.
  - Human Approval Gate: **6/6 PASS** (`prepare_token_issued`, `wrong_hash_rejected`, `edit_invalidated_old_hash`, `stale_token_rejected_after_edit [APPROVAL_HASH_MISMATCH]`, `valid_commit_succeeded`, `replay_commit_rejected [ALREADY_COMMITTED]`).
