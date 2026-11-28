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

## Wave 2: resilience, targeted reviews, boundaries (2026-11-28)

### Decisions taken before starting (answered by the project owner)

| Item | Decision |
|---|---|
| Results-changing items | All approved: AG-12, AG-05/06, AG-11, AG-24; one smoke re-record at the end |
| AG-07/08 (Q4) | Neural retrieval opt-in through the `[rag]` extra; default unchanged |
| AG-20 (Q6) | CI floor `--min-accuracy 0.45` on the offline dev split |
| Scope | AG-28 stale-thread resume and an explicit Compose name are in; Q5 US SAR was selected, then **deferred to a design doc** once its scope was clear (see below); Q3 local-LLM default declined |

### Changes

| Finding | Change | Main files |
|---|---|---|
| **AG-14** | Tipping-off detector: a disclosure verb aimed at the customer side plus an STR, suspicion or investigation object, with a sentence-scoped negation guard. Wired into the verifier (new fail-closed check `no_tipping_off`, code `TIPPING_OFF`), the output guardrail, and the case-actions server-side draft check | `src/core/verifier_patterns.py`, `src/core/verifier.py`, `src/guardrails/guardrails.py`, `src/mcp_servers/case_actions.py` |
| **AG-18** | Erasure order: checkpoint saver first, then one operational transaction. Each failure writes a `customer_erasure_failed` audit row and returns `503 ERASURE_INCOMPLETE`; retries are idempotent. The docstring and `memory_policy.md` now state the transcript and Loki limits | `src/api/services/erasure.py`, `src/api/routes/investigations.py` |
| **AG-25** | Hard-coded numbers moved to `config/models.yaml` **with values unchanged**: C1/C2 turn limits, C2 replan hand-off budget and turns, token TTL, reflector temperature/tokens, BM25 `k1`/`b`, dense blend, rerank weights, every abstention threshold (including 3 more found inline), typology query cut-offs | `src/core/policy.py`, `src/agent/{loop,c2_loop,c2_stages,gathering}.py`, `src/mcp_servers/compliance_kb.py`, `src/db/case_repo.py`, `src/reflexion/loop.py` |
| **AG-27** | MCP annotations (`readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint`) on all 12 tools. A generator (`python -m eval.tool_catalogue`, `make catalogue`) writes `docs/tool_catalogue.md`, and a test fails if the catalogue is stale. All 12 schema hashes match BASELINE §4 | `src/mcp_servers/annotations.py`, all four servers, `eval/tool_catalogue.py` |
| **AG-09** | Correlation ID: `X-Correlation-ID` middleware with validation that replaces bad values. A contextvar carries it into background runs, durable SSE events, Loki records, MCP calls (`meta`) and masked-500 responses. Prometheus gains `auditguard_mcp_tool_calls_total{server,tool,status}`, MCP latency, and LLM calls/latency/tokens/cost by `{model,mode,status}`. New `MCPRepeatedFailures` alert (5+ failures in 5 min). The LLM metrics use model, not role, as a label: the chat protocol carries no role | `src/observability/{correlation,metrics}.py`, `src/api/main.py`, `src/mcp_servers/client.py`, `src/llm/client.py`, `monitoring/alerts.yml` |
| **AG-29** | Live per-tool SSE events (`tool_executed`) from the C1 loop and C2 specialists as each call completes. No graph topology change | `src/agent/planning.py`, `src/agent/loop.py`, `src/agent/c2_loop.py`, `src/api/services/runner.py` |
| **AG-10** | Workbench: signed-in user label and a log-out button (closes the SSE stream, revokes the JWT server-side, clears the session, reloads). `Cache-Control: no-store` on all `/api` responses. Chainlit `@cl.on_logout` revokes the API token held in the signed session cookie (closes the Wave 1 AG-01 residual) | `src/ui/static/{index.html,js/api.js,js/app.js}`, `src/api/main.py`, `src/ui/app.py` |
| **AG-21 / AG-19** | `scripts/start.sh` / `stop.sh` (Compose by default, `--local` for venv-only; health waits; PID files) and `make start/stop/start-local/stop-local`. Compose: `name: auditguard-v3`, fixed `container_name`s removed, image tags pinned (checked against the registry), healthchecks on 4 MCP servers, the API and the UI, `service_healthy` dependencies, **all published ports bound to 127.0.0.1**, configurable `POSTGRES_HOST_PORT` | `scripts/{start,stop}.sh`, `docker-compose.yml`, `Makefile`, `README.md` |
| **AG-33** | Correction to the audit: a scoped `auditguard_case_writer` role already existed, but both data services connected with the **superuser** login and only `SET ROLE` down. Now each has its own LOGIN role and password (set at first boot by `scripts/init_db_roles.sh`; generated by `init_env.py`). `init_db` skips DDL for logins that cannot create in the schema. Password hashes (`users`) are readable by neither service role, and `revoked_tokens` is not readable by the writer | `docker-compose.yml`, `scripts/{init_db.sql,init_db_roles.sh,init_env.py}`, `src/db/database.py`, `.env.example` |
| **AG-28** | On start-up, threads still `running` (owned by a dead process) become `interrupted`, with a terminal `error`/`INTERRUPTED` event; the existing `/resume` endpoint continues them, and `prepare` answers `NOT_READY`. Single-worker deployment documented | `src/api/services/runner.py`, `src/api/main.py`, `src/api/services/approval.py` |
| **AG-20** | `make eval-gate` (offline dev split, `--min-accuracy 0.45`) runs as a CI step after `make verify`. **Note:** the existing flag checks each non-C0 mode, not the mean over 4 modes as I first described; today every gated mode is at 51.7% | `.github/workflows/ci.yml`, `Makefile` |
| **AG-04 / AG-32** | `auditguard lessons list/accept/reject/edit/freeze/unfreeze` on the playbook JSON:<br>• decisions record reviewer, reason and time;<br>• approval runs the gold-label leak check;<br>• an edit sends the lesson back to pending;<br>• freezing needs zero pending lessons and writes `frozen_sha256`, which `load_playbook` verifies (`PlaybookIntegrityError`).<br>The build script stops at pending (no scripted approvals or planted rejection). E3: `lesson_ablation` arms, plus a `lesson_report` (sha256, cost delta, prompt size, lessons without a reviewer, harmful flag). The committed playbook gained its hash, labelled as scripted (no human reviewer recorded) | `src/reflexion/review.py`, `src/cli_lessons.py`, `src/memory/store.py`, `scripts/build_frozen_playbook.py`, `eval/lesson_report.py`, `eval/run_eval.py`, `config/experiments/E3.yaml`, `config/reflexion_playbook.json` |
| **AG-07 / AG-08** | Opt-in `retrieval.backend: neural`: a sentence-transformers bi-encoder supplies dense candidates and a cross-encoder does the final rerank. Abstention stays on the calibrated builtin signals, and it falls back to builtin with a warning when `[rag]` is missing. The configured model names were changed from the unused `BAAI/bge-m3` / `bge-reranker-base` (about 3 GB) to `bge-small-en-v1.5` / `ms-marco-MiniLM-L-6-v2` (about 220 MB). The lexicon was moved to `retrieval_lexicon.py` and frozen with `expansion_table_sha256` (a test fails if it changes). `retrieval-bench --backend` added | `src/mcp_servers/{neural_retrieval,retrieval_lexicon,compliance_kb}.py`, `src/cli.py` |
| **AG-12** | C2 replan check gated on the supervisor-side `replan_attempts` counter, `budgets.max_replans` and the ledger. `flow_replan` increments the counter whether or not the LLM complies, so the loop always ends; C2 can replan more than once | `src/models.py`, `src/agent/c2_stages.py` |
| **AG-05** | Subject history: up to 3 prior human-approved episodes of the **root account's customer** only, excluding this alert's own episodes. Labelled possibly stale, wrapped as `<untrusted_data>`, gated by `memory_enabled`, and omitted when empty (so prompts are byte-identical without history). Added to the C1 alert message and the C2 supervisor plan | `src/memory/subject_history.py`, `src/agent/loop_context.py`, `src/agent/c2_loop.py` |
| **AG-06** | Lessons are offered only when their precondition shares at least 3 content words with a description of the **observed** flow (top 2): C1 after the tool turn, the C2 supervisor at the replan check, and the deterministic plan node. A constant alert query now matches nothing | `src/reflexion/retrieval.py`, `src/agent/{loop_context,planning,c2_loop}.py` |
| **AG-11** | `trim_live_context` before each C1 and C2-specialist `chat()` beyond `memory.live_context_window_messages` (**40, a new value**: the 12-message checkpoint window would have cut almost every C1 run). It pins the system prompt and alert, keeps tool pairs, and adds a wrapped summary | `src/memory/store.py`, `src/agent/loop.py`, `src/agent/c2_loop.py` |
| **AG-24** | C2 supervisor and specialist prompts moved to `config/prompts/c2_{supervisor,specialist}.yaml` v1.0.0. The rendered bodies are byte-identical, with a `[PROMPT_VERSION=… \| AGENT=…]` header added as in C1. Every transcript entry records `prompt_version` and `prompt_agent` | `src/agent/prompts.py`, `src/llm/{replay,schemas}.py` |
| **Q5** | Deferred by the owner to [ADR 0001](../adr/0001-us-sar-jurisdiction-profile.md). Money is INR-typed in every public schema, and there is no verified US corpus | `docs/adr/0001-…`, README Limitations |

### Pre-existing defects found and fixed along the way

1. **Compose stack could not start:**
   - `numpy` is imported by compliance-kb but was never a declared dependency; now declared `numpy>=1.26`, which is already satisfied locally.
   - Postgres seeding crashed on a synthetic PAN shared by two customer IDs. SQLite's `INSERT OR REPLACE` had been silently deleting one of the two customers. The seeder now keeps both with a per-customer hash. CI gates, E1, E2 and held-out zero-drift are unchanged.
2. **`init_db.sql` is re-applied on every owner start-up**, so a REVOKE placed in the first-boot hook was silently undone. Grants now live only in `init_db.sql`, after the blanket GRANT.
3. **Dead code (not removed; for Wave 3 simplification):** `run_c2_agent_team` and `_maybe_replan_flow` in `src/agent/c2_loop.py` have no callers.

### Tests

New file `tests/test_audit_wave2.py` with **63 tests**. Each feature's tests were written and run red before the code; the tests for already-correct behaviour (post-logout 401) passed from the start and stay as guards.

Adapted, not weakened: `tests/test_audit_wave2_closure.py::test_w2_09_chainlit_ui_handlers`. Its Chainlit stub gained `on_logout` and the two `chainlit.auth` modules, and it now restores the real `src.ui.app` afterwards instead of leaking the stub-built copy.

### Verification

| Check | After Wave 1 | After Wave 2 |
|---|---|---|
| ruff (CI scope) / mypy `--strict` | 0 / 0 (87 files) | 0 / 0 (97 files) |
| pytest | 227 passed | **290 passed**, 0 failed |
| `make verify` (smoke replay, held-out zero drift) | ✓ | ✓ |
| `make eval-gate` (0.45) | n/a | ✓ (fails at 0.52, so the gate is live) |
| E1 dev offline (60), every non-timing metric | 30.0 / 51.7 / 51.7 / 51.7 % | identical |
| E2, both arms, every metric | 0.8788 / 0.0227; E2E 1.0 / 0.0 | identical |
| Retrieval (builtin) | R@5 0.915 | identical (full table) |
| Retrieval (neural, opt-in, measured once) | n/a | hybrid+rerank R@5 0.939, nDCG@5 0.903, R@1 0.898 (builtin 0.915 / 0.888 / 0.909); MRR and abstention identical. 2 of 88 queries; not significant |
| MCP tool contracts (12 schema hashes) | BASELINE §4 | identical (annotations added) |

**Smoke re-record ($0.0708 of live calls).** C1 prompts were byte-identical, confirmed by replaying the old cassette with zero misses. So the installed cassette keeps the **old C1 entries plus the new C2 entries**, which avoids mixing LLM run-to-run noise into C1's numbers. The merged cassette replays fully: C1 matches the old baseline exactly, and C0 and rule_engine are unchanged. C2 on 10 cases moved as follows:

| C2 metric | Wave 1 | Wave 2 |
|---|---|---|
| Accuracy / weighted error cost | 30% / 1.40 | 30% / 1.40 |
| Macro-F1 | 0.154 | 0.232 |
| Evidence recall / precision | 6.7% / 44.3% | 11.7% / 51.5% |
| Tool calls / tool error rate | 11.9 / 35.3% | 14.3 / 31.5% |
| Cost per case / tokens | $0.0348 / 71k | $0.0456 / 94k |

10 cases and 1 repeat: directional only. The extra cost and tool calls are what replanning beyond once costs. The full fresh recording is kept at `scratchpad/e1_smoke_10.w2_full_record.jsonl`.

**Live Compose end-to-end** (project `auditguard-v3`, HTTP MCP, Postgres 16, from a fresh volume):
- All 10 services were healthy, and `scripts/start.sh` returned 0.
- Investigation flow: `rule_engine` run → requester `prepare` 403 → reviewer approve 200 `committed` → replayed approve 409.
- Logout 200, then the same token got 401.
- Audit trail: `investigation_requested:analyst → draft_created → case_committed:reviewer`.
- 10 of 10 events carried the request's correlation ID.
- MCP metrics were recorded through the HTTP transport.
- Prometheus loaded `MCPRepeatedFailures`.
- Inside the containers: case-actions ran as `auditguard_case_writer` and bank-records as `auditguard_ro`. Probes from those logins:
  - INSERT on customers was denied;
  - CREATE TABLE was denied;
  - UPDATE as RO was denied;
  - password hashes were not readable.

  The stack was stopped and its volumes deleted afterwards. The other local `auditguard` stack (genai-project) was never touched.

**Not verified:** clicking through the workbench logout in a browser. No browser automation is available here, so this is **BLOCKED** per AGENTS.md. Covered by DOM-contract tests and a Node syntax check of `api.js` and `app.js`.

### Environment changes outside the repo tree (for awareness)

- `.env`: `init_env.py` appended the 3 missing keys (`POSTGRES_RO_PASSWORD`, `POSTGRES_CASE_WRITER_PASSWORD`, `CHAINLIT_AUTH_SECRET`); nothing was overwritten. A backup is in the session scratchpad.
- `.venv`: `sentence-transformers` 6.3 and its dependencies (torch and others) were installed, pinned against the existing versions, so no existing package changed. The two small models are cached under `~/.cache/huggingface` (about 220 MB).
- Docker: the `auditguard-v3-*` images (6) are kept, so `make start` is quick. Remove them with `docker compose down --rmi local`.

### Deferred or residual, with reason

| Item | Why |
|---|---|
| Q5 US SAR | ADR 0001: needs currency-agnostic schemas (a breaking API change) and a human-verified US corpus |
| AG-08 held-out NL retrieval report | Not run. The auditor does not open held-out material; the owner can run it once the lexicon is frozen (it is) |
| AG-03/AG-04 lesson regeneration | Needs a human reviewer: the two approved lessons have no recorded reviewer (flagged in E3 `lesson_report`) |
| AG-17 token copy in older checkpoint history | Unchanged since Wave 1 (single-use, 15-minute TTL) |
| AG-09 LLM metrics by role | The chat protocol carries no role; model is used as the label |
| E3 memory arms | Cannot differ in evaluation, which never commits a human approval, so no episodes exist; documented in `memory_policy.md` |
