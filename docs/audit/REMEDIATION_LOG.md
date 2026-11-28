# AuditGuard Remediation Log

Each wave references finding IDs in [AUDIT_REPORT.md](AUDIT_REPORT.md) and is compared against [BASELINE.md](BASELINE.md). Per `AGENTS.md` rule 6, nothing is committed: every change is left in the working tree for review.

## Wave 1: critical security, state integrity, graph wiring (2026-11-28)

### Decisions taken before starting (answered by the project owner)

| Finding | Decision |
|---|---|
| AG-02 | Neither the **requester** nor the **last editor** may approve |
| AG-03 | Reject `LES-9ADC37` with a reason, and add a guard test. Full regeneration waits for the Wave 2 review CLI |
| AG-15 | Screen **every** external string field now. Deny-by-default `<untrusted_data>` wrapping is deferred until cassettes can be re-recorded (wrapping changes LLM input, so every cassette would miss) |
| AG-16 | With defences off, RBAC, the approval hook, bounds and budgets **stay on**. Only post-tool guardrails are disabled |
| Commits | None (`AGENTS.md` rule 6) |

### Changes

| Finding | Change | Files |
|---|---|---|
| **AG-02** (CRITICAL) | Registration writes an append-only `audit_logs` row (`investigation_requested`, actor = JWT `sub`). `prepare_decision` and `approve` refuse the requester or the worksheet's `edited_by` with `403 SELF_APPROVAL_FORBIDDEN`; an unknown requester fails closed (`409 REQUESTER_UNKNOWN`). The same check runs again inside the `commit_case` transaction. Editors are no longer handed an approval token for their own edit | `src/api/services/runner.py`, `src/api/services/approval.py`, `src/api/routes/investigations.py`, `src/db/case_repo.py` |
| **AG-01** (CRITICAL) | Chainlit uses `@cl.password_auth_callback`, so each person signs in with their own AuditGuard account. The API JWT lives in that user's Chainlit session only. The module-level `_token_cache` and the `UI_API_PASSWORD`/`REVIEWER_PASSWORD` fallback are removed. The UI's combined "edit then approve" now stops after the edit and says a different reviewer must approve. `CHAINLIT_AUTH_SECRET` is added to `.env.example` and `scripts/init_env.py` | `src/ui/app.py`, `.env.example`, `scripts/init_env.py`, `README.md` |
| **AG-03** (CRITICAL) | `LES-9ADC37` is marked `rejected` with its reason in `config/reflexion_playbook.json`. Added `label_leak_findings()` and `PROMPT_FACING_LESSON_FIELDS` | `config/reflexion_playbook.json`, `src/reflexion/loop.py` |
| **AG-17** | Approval tokens are stored as `sha256:` digests only, and `current_approval` never returns a bearer token. The commit node strips `approval_token` from the LangGraph `gate` channel | `src/db/case_repo.py`, `src/agent/graph.py` |
| **AG-15** (partial) | `post_tool_hook` screens every string field (dict values and list items) of external tool outputs for injection, and withholds matches. Clean values are byte-identical. The agent's own write-tool echoes (`draft_disposition_report`, `submit_case_disposition`) and the curated corpus are exempt | `src/guardrails/hooks.py` |
| **AG-16** | The defences-off path now runs the full `pre_tool_hook` and skips only `post_tool_hook` | `src/agent/tooling.py` |
| **AG-30** | `calc_log` and `tool_execution_log` merge append-only (prior entries kept, duplicates skipped by canonical JSON). `as_state` logs any keys it drops | `src/agent/graph.py` |
| **AG-35** | Approve without a token now ends at `current_node="approval_missing_token"` with no `human_decision`, instead of claiming `committed` | `src/agent/graph.py` |
| **AG-38** | The `interrupt_required` SSE event sends `confidence_score` as an exact Decimal string | `src/api/services/runner.py` |
| Docs | Threat model (spoofing/tampering rows), architecture approval sequence, README quick-start | `docs/threat_model.md`, `docs/architecture.md`, `README.md` |

### Tests

New file `tests/test_audit_wave1.py` with 17 tests. All 17 were run **before** the fixes: 16 failed for the intended reason, and 1 (the clean-path half of AG-15) passed. All 17 pass after the fixes.

Four existing tests were adapted. None was weakened:

| Test | Why it changed |
|---|---|
| `test_adversarial_step6.py::test_04_concurrent_double_approval_atomic_single_winner` | The same `reviewer` started and approved the thread, which is now forbidden. It now starts as `analyst`; the concurrency assertion is unchanged |
| `test_audit_wave2_closure.py::test_w2_01_…` | Its hand-built thread had no requester, so it now failed closed before reaching the interrupt check it targets. A requester row is added to the setup |
| `test_audit_wave2_closure.py::test_w2_09_chainlit_ui_handlers` | Its `chainlit` stub gained `password_auth_callback` and `User` |
| `test_graph_step5.py::test_c1_replans_when_evidence_contradicts_and_pauses_at_interrupt` | **It asserted the AG-35 defect** (approve without a token ⇒ `committed`). It now asserts `approval_missing_token` and no `human_decision` |

### Verification

| Check | Baseline | After Wave 1 |
|---|---|---|
| ruff (CI scope) | 0 | 0 |
| ruff (whole repo) | 6 (data generator) | 6 (same) |
| mypy `--strict` | 0 / 87 files | 0 / 87 files |
| pytest | 191 passed | **208 passed** (+17), 0 failed |
| `eval.verify_gates` | smoke replay ✓, held-out zero-drift ✓ | ✓ / ✓ (all cassettes still hit) |
| E1 dev offline (60): C0 / rule / C1 / C2 | 30.0 / 51.7 / 51.7 / 51.7 % | identical |
| E1 dev replay smoke (10): C0 / rule / C1 / C2 | 30 / 80 / 30 / 30 %; $0.0316 / $0.0300 | identical |
| Retrieval Recall@5 (hybrid+rerank) | 0.915 | 0.915 (whole table identical) |
| E2 ASR off / on; E2E ASR off / on; false blocks | 0.8788 / 0.0227; 1.0 / 0.0; 0 / 0 | identical (committed `e2_security_summary.json` still accurate) |
| Graph exports (5 sha256) | BASELINE §5 | identical |
| Tool catalogue (12 sha256) | BASELINE §4 | identical |

**Live check.** Real API (:8100) and real Chainlit (:8101) were run against a scratch DB copy:

- Chainlit reports `requireLogin=true`.
- Unauthenticated requests and wrong passwords get 401.
- `analyst` signs in as `analyst` with role `analyst`.
- Chainlit logout ends the session (`/user` returns 401 afterwards).

Both servers were stopped afterwards, and the `chainlit.md` Chainlit generated was removed.

`make verify` includes the repo's held-out zero-drift gate, which makes the harness score held-out cases. The auditor did not open or read held-out files.

### Behaviour changes to know about

- The edit response now always returns `approval_token: null`. The editor cannot approve; another senior reviewer calls `/decision/prepare`.
- `GET …/state` → `approval.approval_token` is always `null` now. The token is shown only once, in the `/decision/prepare` response. The workbench already works this way.
- Threads registered **before** this change have no requester record, so their approval fails closed with `409 REQUESTER_UNKNOWN`. Re-run those investigations.
- Approval tokens issued before this change are stored in plaintext. They no longer validate (`INVALID_HMAC_SIGNATURE`); they expired within 15 minutes anyway.
- **Action needed for Chainlit:** run `python scripts/init_env.py` once to add `CHAINLIT_AUTH_SECRET` to your existing `.env`. It only adds missing keys.

### Deferred or residual, with reason

| Item | Why it isn't fully closed |
|---|---|
| AG-15 deny-by-default wrapping | Changes every LLM message, so every replay cassette would miss. Needs a re-record with a paid key. **Code done in the AG-15 follow-up below; cassette re-record pending** |
| AG-17 checkpoint history | Earlier LangGraph checkpoint versions (the `human_gate` step) still hold the token until it is consumed or expires (15 min, single-use, bound to one reviewer). Removing it needs a topology change; proposed for Wave 2 |
| AG-03 other lessons | `LES-22267B` and `LES-6B2801` have clean prompt-facing text, but their `observed_failure` ("instead of escalate_str") shows a reflector that saw dev gold labels. That breaks the repo's own `FORBIDDEN_TRACE_LABEL_KEYS` rule. `observed_failure` is never injected into prompts. Regenerate with human review in Wave 2 (AG-04) |
| AG-01 logout revocation | Chainlit logout ends the Chainlit session but does not yet revoke the user's API JWT. That's part of Wave 2's AG-10 |

## AG-15 follow-up: deny-by-default `<untrusted_data>` containment (2026-11-28)

The project owner asked for the untrusted-data residual from Wave 1 to be fixed. The owner first chose to re-record the smoke cassette themselves, then asked for the re-record to be run here.

### Change

The wrapping happens at the **LLM boundary**, not in agent state. `tool_message()` (used by both the C1 loop and the C2 specialists) now serialises results through `llm_tool_content()` in `src/guardrails/hooks.py`:

- With defences on, every tool result is sent as **one** `<untrusted_data source="tool:<name>">…</untrusted_data>` envelope with an XML-escaped payload. That covers MCP data, graph outputs, corpus text, error envelopes, `replan_graph`, write-tool echoes and any tool added later. No field, listed or not, can close the envelope or inject tags.
- The only exceptions are `INTERNAL_RESULT_TOOLS = {"calc", "finish"}`. AuditGuard computes their output itself, and `finish` repair feedback has to stay readable as instructions.
- The existing field-level wrappers are flattened before enveloping, so each value is escaped exactly once (no `&amp;lt;`).
- With defences off (the E2 "off" arm), results stay plain JSON. This matches the Wave 1 AG-16 decision that the flag disables only the post-tool guardrails.
- Agent state, worksheets and the deterministic modes are untouched. They read the same structured values as before, which is why wrapping was not applied to every field in state: that would have broken the Decimal and enum comparisons in C0/rule_engine.

Files: `src/guardrails/hooks.py`, `src/agent/loop.py`, `src/agent/c2_loop.py`, `docs/threat_model.md`, `docs/architecture.md`.

### Tests

New file `tests/test_untrusted_envelope.py` with 18 tests. The breakout test uses an unlisted field (`entity_type`). The others cover: single envelope with no early close; flattening without double escaping; 13 tool names wrapped by default, including an unknown future tool; `calc`/`finish` and defences-off stay plain; and the C1 loop sending the wrapped KYC result and plain `calc` to the LLM. All 18 failed before the change (import error on the new API) and pass after it.

Adapted, not weakened: the scripted fake LLMs that read tool messages with `json.loads` now use `decode_llm_tool_content`. Their assertions are unchanged. Affected: `tests/test_agent_loop.py`, `tests/test_intelligence_c1_c2.py`, `tests/test_verifier_v2.py`, `tests/test_adversarial_e2e_step6.py`, and the E2 poisoning probe in `eval/red_team_runner.py`.

### Found while re-recording: C2 replay ran a different code path from live (new finding, fixed)

The first fresh recording replayed for C1 but missed for C2 at `supervisor_replan_check`. The cause predates this work. Commit `930b0d6` ("c1 and c2 restructure") added branches to C2 that ran only when `llm_mode == "replay"`:

- `_allocate_budgets` used a different specialist budget formula.
- `_finding_for_prompt` sent a 6-field findings summary instead of the full finding.
- The critic prompt reordered findings and left out the hypothesis assessment, preliminary critique and replan records.

So the committed smoke gate replayed a legacy C2 path, not the one that runs live, and no C2 cassette recorded from the current code could ever replay. A second cause hid behind it: the full findings included `execution_metadata.duration_ms` (wall-clock timing), which made every C2 critic request unique.

Fix (`src/agent/c2_loop.py`, `src/agent/c2_routing.py`): the replay-only branches are removed, so replay sends exactly what live sends, and `execution_metadata` (run telemetry, not evidence) is excluded from prompts. Live and record behaviour is unchanged apart from dropping those timing fields from the prompt. Test: `test_c2_sends_identical_requests_in_record_and_replay` in `tests/test_untrusted_envelope.py` failed before the fix (different budget, then the timing) and passes after it.

### Re-record (run 2026-11-28 on the owner's OpenRouter key)

- Attempt 1 (before the C2 fix): $0.0603 of live calls. C1 replayed, C2 did not. It was discarded and kept at `scratchpad/e1_smoke_10.first_attempt.jsonl`.
- Attempt 2 (after the C2 fix): $0.0622 of live calls (C1 $0.0274, C2 $0.0348). A replay of the new cassette matched the recording on all 14 gate metrics in all 4 modes.
- Installed `eval/cassettes/e1_smoke_10.jsonl` and rebuilt `eval/baselines/e1_smoke_expected.json` from the replay. The rebuild script was first checked to reproduce the old baseline byte-for-byte from the old replay output. Then `make replay` regenerated `eval/replay_bundle/*` and `docs/evaluation_report.md`.
- The originals of the cassette, baseline, bundle and report were copied to the session scratchpad before being replaced.

**Smoke slice (10 dev cases), old cassette → new cassette:**

| Metric | c1_single | c2_multi |
|---|---|---|
| Disposition accuracy | 30% → 30% | 30% → 30% |
| Macro-F1 | 0.154 → 0.154 | 0.229 → 0.154 |
| Weighted error cost | 1.40 → 1.40 | 1.20 → 1.40 |
| False-close rate | 0% → 0% | 0% → 0% |
| Evidence recall / precision | 19.3 / 56.1% → 25.2 / 57.9% | 11.7 / 46.3% → 6.7 / 44.3% |
| Citation validity | 70% → 40% | 100% → 100% |
| INR arithmetic error rate | 0% → 2.9% | 0% → 0% |
| Tool error rate | 10.7% → 13.8% | 20.5% → 35.3% |
| Cost per case | $0.0316 → $0.0274 | $0.0300 → $0.0348 |

c0_fixed and rule_engine are unchanged. With 10 cases and one repeat, none of these differences is statistically meaningful; the report's paired tests stay `inconclusive` for c1 vs c2. The changes mix three effects that one sample can't separate: the envelope, the C2 path now matching live, and ordinary run-to-run LLM variation.

### Verification

| Check | Wave 1 | Now |
|---|---|---|
| ruff (CI scope) / mypy `--strict` | 0 / 0 | 0 / 0 |
| pytest | 208 passed | **227 passed** (+19), 0 failed |
| `make verify` | ✓ | **✓** (smoke replay ✓ on the new cassette, held-out zero drift ✓) |
| E1 dev offline (60): every non-timing metric, all 4 modes | 30.0 / 51.7 / 51.7 / 51.7 % | identical |
| E2 (both arms, including E2E ASR) and the replay-bundle E2 summary | 0.8788 / 0.0227; 1.0 / 0.0 | identical |
| E1 deterministic held-out bundle, calibration status | — | identical apart from timings |
| Retrieval | 0.915 R@5 | identical (bundle `benchmark_path` now uses `/` instead of `\`) |

### Housekeeping

- While diagnosing, three standalone scripts ran C2 outside pytest and wrote test rows for thread `thr-c2-mode` into the operational DB. That was 1 worksheet, 7 `draft_created` audit-log rows (ids 32–38), 1 thread checkpoint, and 56 checkpoints + 105 writes in `data/auditguard.langgraph.sqlite`, all from 13:06–13:07 UTC today.
- Both DB files were copied to `scratchpad/db_backup_before_cleanup/` first. Then exactly those rows were deleted. No other rows were touched.

### Still open

`eval/cassettes/phase4_packet_agents.jsonl` (used only by `eval/packet_builder.py`, not by CI or tests) is stale for the same two reasons. Re-record it only if that packet is still used.
