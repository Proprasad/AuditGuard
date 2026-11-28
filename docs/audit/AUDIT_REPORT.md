# AuditGuard Stage 1 Audit Report (read-only)

**Audit date:** 2026-11-28. **Commit:** `930b0d6` (`dev`). **Baseline:** [BASELINE.md](BASELINE.md).

No code, config, test, script or existing doc was changed by this audit. The only files created are this report and `BASELINE.md`. The held-out and challenge sets were not opened, listed or grepped. The one exception is that the existing pytest suite invokes the harness on them (see BASELINE §1).

> **Scope check, please confirm before Stage 2.** The prompt's template names (`auditguard/` package, `configs/base.yaml`, `infra/docker-compose.yml`, `docs/PROGRESS.md`, `CLAUDE.md`, Qdrant, the local LLM at `127.0.0.1:8888`, India/US jurisdiction profiles) do not match this repository. They closely match another local repo, `/Users/chandra/git/genai-project`, whose Compose stack (`auditguard-postgres-1`, `auditguard-qdrant-1`) is running now. This audit covers **`/Users/chandra/git/AuditGuard`** only. §0.1 maps every name to what exists here.

---

## 0. Name map and baseline

### 0.1 Name map

| Template name | This repo | Notes |
|---|---|---|
| `auditguard/` / `src/` package | `src/` | |
| `configs/base.yaml` (+ `configs/experiments/*.yaml`) | `config/models.yaml` + `config/experiments/E1..E4.yaml` + `config/prompts/c1_investigator.yaml` | |
| `CLAUDE.md`, `docs/PROGRESS.md`, `docs/specs/*` | `AGENTS.md`, `docs/AGENT_GUIDE.md`, `docs/IMPLEMENTATION_GUIDE.md`, `docs/preregistration.md` | No PROGRESS or specs files exist |
| `infra/docker-compose.yml` | `docker-compose.yml` (repo root) | |
| `transactions` MCP | `bank-records` ([src/mcp_servers/bank_records.py](../../src/mcp_servers/bank_records.py)) | |
| `regulatory_kb` MCP | `compliance-kb` ([src/mcp_servers/compliance_kb.py](../../src/mcp_servers/compliance_kb.py)) | |
| `filing_portal` / `submit_approved_payload` | `case-actions` / `submit_case_disposition` ([src/mcp_servers/case_actions.py](../../src/mcp_servers/case_actions.py)) | |
| `aml_engine` rule engine | `graph-engine` MCP + [src/core/graph_math.py](../../src/core/graph_math.py), and the `rule_engine` mode ([src/agent/rule_engine.py](../../src/agent/rule_engine.py)) | |
| Evidence critic / checker code | [src/core/verifier.py](../../src/core/verifier.py) (`verify_worksheet`) + [src/agent/hypothesis_eval.py](../../src/agent/hypothesis_eval.py) (`run_independent_critique`) | |
| Investigator / Regulatory Researcher / Drafter / Evidence Critic | `flow_tracer` / `benign_investigator` / `regulatory_analyst` / `reporter_critic` | |
| `CaseState` | `InvestigationState` ([src/models.py:233-295](../../src/models.py#L233-L295)) wrapped in the LangGraph `GState.inv` channel ([src/agent/graph.py:117-119](../../src/agent/graph.py#L117-L119)) | |
| `Payload` (canonical JSON + SHA-256) | `DispositionWorksheet.canonical_payload()` / `compute_hash()` ([src/models.py:172-196](../../src/models.py#L172-L196)); server side `canonical_sha256` over the stored JSON ([src/db/case_repo.py:72](../../src/db/case_repo.py#L72)) | |
| `HandOff` / specialist outputs | `SpecialistHandOff` / `SpecialistFinding` ([src/models.py:199-230](../../src/models.py#L199-L230)) | |
| `HELDOUT_DIR` | `eval/golden_v2/held_out/` (120), `eval/golden_v2/challenge/` (30), `eval/held_out/` (v1, 40), `eval/retrieval_held_out_nl.jsonl` | Counts come from generator/harness output, not from reading the files |
| C0 / C1 / C2 graphs | `build_c0_graph`, `build_graph` (rule_engine + offline C1), `build_llm_c1_graph`, `build_c2_graph` (offline), `build_llm_c2_graph` ([src/agent/graph.py:330-477](../../src/agent/graph.py#L330-L477)) | |
| Tag `c1-frozen` | none | `git tag` is empty |
| `LLM_BASE_URL`, local `127.0.0.1:8888` | `OPENAI_BASE_URL`, default `https://openrouter.ai/api/v1` ([.env.example](../../.env.example)); `provider: "openrouter"` for every role in [config/models.yaml](../../config/models.yaml) | No local-LLM default in this tree |
| India STR / US SAR profiles | India only | No jurisdiction setting exists |
| Vector store (Qdrant) | none in Compose; in-process numpy index | `qdrant-client` is only an optional `[rag]` extra |
| Tracing backend (LangSmith/Langfuse) | none wired; Loki logs + per-run JSONL transcripts | `LANGFUSE_HOST` appears in `.env.example` but nothing reads it |

### 0.2 Budget and policy values: configured vs enforced

| Value | Config ([config/models.yaml](../../config/models.yaml)) | Runtime enforcement point | Enforced? |
|---|---|---|---|
| `max_tool_calls` | 15 | `pre_tool_hook` → `BudgetLedger.try_consume_tool_call` ([hooks.py:153-160](../../src/guardrails/hooks.py#L153-L160), [policy.py:347-362](../../src/core/policy.py#L347-L362)); `should_replan` ([nodes.py:311](../../src/agent/nodes.py#L311)) | **Yes**, except when `defenses_enabled=False`: the verdict is ignored at [tooling.py:67-72](../../src/agent/tooling.py#L67-L72) |
| `max_cost_usd_per_case` | 0.15 | `check_llm_allowed` before every LLM turn ([loop.py:445](../../src/agent/loop.py#L445), [c2_loop.py:115,180,229,339](../../src/agent/c2_loop.py#L115)); tool-call cost check ([policy.py:355](../../src/core/policy.py#L355)) | **Yes** |
| `max_replans` | 3 | `BudgetLedger.try_replan` ([nodes.py:323](../../src/agent/nodes.py#L323), [tools.py:277](../../src/agent/tools.py#L277)); `recursion_limit` = 24 ([graph.py:126-128](../../src/agent/graph.py#L126-L128)) | **Yes for C0/C1/offline.** LLM C2 hard-codes **1** replan ([c2_stages.py:279](../../src/agent/c2_stages.py#L279)) |
| `max_critique_retries` | 2 | `try_critique_retry` ([drafting.py:161](../../src/agent/drafting.py#L161), [loop.py:322,356](../../src/agent/loop.py#L322)) | **Yes** |
| `time_window_days` | 1..30 (default 7) | `validate_graph_bounds` in `pre_tool_hook` ([hooks.py:146-149](../../src/guardrails/hooks.py#L146-L149)) | **Yes** |
| `max_hops` | 2..5 (default 3) | same | **Yes** |
| `amount_tolerance` | 0.01..0.25 (default 0.10) | same | **Yes** |
| `min_intermediaries` | 2..10 (default 2) | same | **Yes** |
| C1 max turns | **hard-coded 12** ([loop.py:46](../../src/agent/loop.py#L46)) | loop bound | Not in config |
| Approval token TTL | **hard-coded 15 min** ([case_repo.py:25](../../src/db/case_repo.py#L25)) | `_validate_commit_token` | Not in config |

Values were reported only; none were changed.

---

## 1. Executive verdict and scorecard

**Overall verdict: `CRITICAL FAILURES DETECTED`**

The deterministic core is strong: Decimal arithmetic, the hash-bound single-use HMAC token, the fail-closed verifier, the RBAC allow-lists and structured MCP errors are all genuinely wired and tested. The critical failures are in **who** may approve, and in the **integrity of the improvement loop**. Several minimum-bar areas (memory, Reflexion, judge calibration, observability, cross-encoder reranking) are present on disk but hollow on the live path.

### Automated checks

| Check | Result |
|---|---|
| ruff (CI scope) | 0 errors |
| ruff (whole repo) | 6 errors, all in `data/synthetic_generator.py` |
| mypy `--strict` | 0 errors / 87 files |
| pytest | 191 collected / 191 passed / 0 skipped |
| shellcheck | n/a (no shell scripts) |
| Secret grep | no secrets in `src/`, `config/`, `scripts/` (only `.env.example` placeholders) |
| Case/account-ID branching | none found |
| `TODO`/`FIXME`/`NotImplementedError` in `src/` | 0 |
| `print()` in `src/` | 0 |
| Naive `datetime.now()`/`utcnow()` in `src/` | 0 |

### Severity counts

| CRITICAL | HIGH | MEDIUM | LOW |
|---:|---:|---:|---:|
| 3 | 10 | 19 | 7 |

### Top 5 systemic takeaways

1. **Identity is the weakest link, not cryptography.** The token is hash-bound and replay-proof, but nothing stops the requester from being the approver. The optional Chainlit UI also makes every visitor the same `senior_reviewer` (AG-01, AG-02).
2. **The improvement loop is not trustworthy as evidence.**
   - "Human review" is a script that approves every lesson.
   - One frozen lesson repeats a gold category label and the gold answer.
   - Lesson retrieval returns the same three lessons for every case (AG-03, AG-04, AG-06).
3. **Long-term memory is write-only.** Agents never read it. As a result the E3 "memory on vs off" arms run identical code, and `docs/memory_policy.md` describes reads that do not exist (AG-05).
4. **Several minimum-bar components are simulated rather than real.**
   - The "dense embeddings" are SVD over hand-written features.
   - The "cross-encoder" is a hand-weighted linear formula.
   - The configured `bge-m3` and `bge-reranker-base` are never loaded (AG-07).
   - The judge has 0 human labels, so no kappa can be reported (AG-13).
5. **Observability and operations lag the core.** There is no LLM tracing and no correlation ID. There are only 4 Prometheus metrics, and the required MCP-failure alert is missing. The workbench has no logout. There are no start/stop scripts, and the Compose stack has no vector store and only one healthcheck (AG-09, AG-10, AG-21).

---

## 2. Capstone requirement compliance matrix

| # | Area | Verdict | Proof (File:Line) | Evidence artefact |
|---|---|---|---|---|
| 1 | Retrieval | **PARTIAL** | Metadata kept (effective_date, retrieval_date, source_url) [compliance_kb.py:450-463](../../src/mcp_servers/compliance_kb.py#L450-L463); BM25 [246-264](../../src/mcp_servers/compliance_kb.py#L246-L264); "dense" = SVD over hand features [196-226](../../src/mcp_servers/compliance_kb.py#L196-L226); RRF with config `rrf_k` [396-406](../../src/mcp_servers/compliance_kb.py#L396-L406); **reranker is hand-weighted, not a cross-encoder** [319-362](../../src/mcp_servers/compliance_kb.py#L319-L362); decomposition [469-519](../../src/mcp_servers/compliance_kb.py#L469-L519), live via `" ; ".join` [gathering.py:275](../../src/agent/gathering.py#L275); citations must be in corpus **and** this run's registry [verifier.py:280-295](../../src/core/verifier.py#L280-L295) | Recall@5 staircase on 110 queries exists and regenerates (`retrieval-bench`). The reranker adds **+0.000** R@5 over hybrid. No latency numbers |
| 2 | Tools & MCP | **PARTIAL** | 4 FastMCP servers [client.py:31-36](../../src/mcp_servers/client.py#L31-L36); typed `extra="forbid"` I/O; structured errors [client.py:146-175](../../src/mcp_servers/client.py#L146-L175); allow-lists at the execution layer [hooks.py:20-93](../../src/guardrails/hooks.py#L20-L93); **no read/write MCP annotations** (BASELINE §4) | No tool-catalogue doc or generator. Per-tool tests not confirmed for every tool |
| 3 | Orchestration | **PASS** | Typed state [models.py:233](../../src/models.py#L233); conditional edges [graph.py:342-347](../../src/agent/graph.py#L342-L347); self-correction [drafting.py:140-163](../../src/agent/drafting.py#L140-L163), [loop.py:307-369](../../src/agent/loop.py#L307-L369); durable checkpointer [graph.py:186-213](../../src/agent/graph.py#L186-L213); stop/resume [graph.py:495-542](../../src/agent/graph.py#L495-L542) and `tests/test_checkpoint_resume.py` | Hand-drawn Mermaid in `docs/architecture.md`; no export generator. LLM C1 runs the whole ReAct loop inside **one** node (AG-29) |
| 4 | Memory | **FAIL** | Trimming only after the loop [loop.py:522-524](../../src/agent/loop.py#L522-L524) vs untrimmed live context [loop.py:450](../../src/agent/loop.py#L450); long-term store never read (AG-05); policy doc claims reads [memory_policy.md:13](../memory_policy.md) | Policy page exists but is inaccurate. On/off comparison is vacuous |
| 5 | Planning | **PARTIAL** | Plan object streamed (`plan_updated`) [runner.py:87-100](../../src/api/services/runner.py#L87-L100); replan on contradiction [nodes.py:308-319](../../src/agent/nodes.py#L308-L319); ReAct inside specialists [c2_loop.py:154-215](../../src/agent/c2_loop.py#L154-L215) | `replan_records` + SSE `replan_triggered`. LLM C2 capped at 1 replan (AG-12) |
| 6 | Multi-agent | **PARTIAL** | Supervisor + 4 specialists, each with its own toolbox [graph.py:140-146](../../src/agent/graph.py#L140-L146); typed hand-offs [c2_stages.py:86-91](../../src/agent/c2_stages.py#L86-L91) | E1 config exists, but C1 and C2 do not share the replan budget (3 vs 1), so the comparison is not like-for-like |
| 7 | Improvement (Reflexion) | **FAIL** | Dev-only guard [reflexion/loop.py:58-60](../../src/reflexion/loop.py#L58-L60); **scripted approvals** [build_frozen_playbook.py:59-71](../../scripts/build_frozen_playbook.py#L59-L71); label-derived lesson `LES-9ADC37` in [config/reflexion_playbook.json](../../config/reflexion_playbook.json); retrieval with no relevance threshold [store.py:252-261](../../src/memory/store.py#L252-L261) | Playbook + one rejected lesson exist, but the rejection is a planted example. No git tag or file hash for the freeze. No lesson cost or harmful-lesson report |
| 8 | Evaluation & monitoring | **PARTIAL** | Golden set 60 dev / 120 held-out / 30 challenge; judge is a different family (`google/gemini-3.1-flash-lite` vs `openai/gpt-5-mini`); **0 human labels** [calibration_status.json](../../eval/replay_bundle/calibration_status.json); dashboard [monitoring/grafana/dashboards/auditguard_overview.json](../../monitoring/grafana/dashboards/auditguard_overview.json) | Eval report regenerates. Judge kappa is **missing**. Traces are JSONL transcripts only |
| 9 | Human control & hooks | **PARTIAL** | `interrupt()` [graph.py:247-272](../../src/agent/graph.py#L247-L272); approve/edit/reject [approval.py](../../src/api/services/approval.py); payload-bound token [case_repo.py:231-261](../../src/db/case_repo.py#L231-L261); pre-hooks [hooks.py:124-162](../../src/guardrails/hooks.py#L124-L162); post-hook audit list **not passed** by the toolbox [tooling.py:98](../../src/agent/tooling.py#L98) (only errors and detections are logged); **no requester ≠ approver** (AG-02) | Edit→`TOKEN_INVALIDATED_BY_EDIT` tested in `tests/test_approval_invalidation.py` |
| 10 | Security | **PARTIAL** | Threat model (18 lines) [docs/threat_model.md](../threat_model.md); layered guardrails [guardrails.py](../../src/guardrails/guardrails.py); red team 132 attacks + 320 clean memos, including the data path ([eval/build_red_team_v2.py](../../eval/build_red_team_v2.py)); **no tipping-off check** (AG-14); limited untrusted-field coverage (AG-15) | E2 reports ASR and false-block rate with Wilson CIs ([red_team_runner.py:443-495](../../eval/red_team_runner.py#L443-L495)) |
| 11 | Deployment | **PARTIAL** | FastAPI SSE [investigations.py:105-148](../../src/api/routes/investigations.py#L105-L148); Compose has no vector store and only 1 healthcheck [docker-compose.yml:16](../../docker-compose.yml#L16); CI runs `make verify` (drift gate, no accuracy threshold) [.github/workflows/ci.yml](../../.github/workflows/ci.yml); 2 alerts, neither for MCP failure [monitoring/alerts.yml](../../monitoring/alerts.yml) | Clean-machine install needed 4 manual fixes on 2026-11-28 (pydantic pin, `literalai` `tests` shadowing, chainlit mypy, CRLF hashes). No recorded failed CI run |

| Cross-cutting | Verdict | Proof |
|---|---|---|
| Experiments: one harness, one YAML per experiment | **PARTIAL** | `eval/run_eval.py` + `config/experiments/E1..E4.yaml`. E3 memory arms are vacuous (AG-05). E3 omits lesson cost and harmful lessons (AG-37) |
| Reporting (successes, violations, ASR, false blocks, cost, p50/p95, errors, 3 repeats) | **PARTIAL** | p50/p95 + CIs in [eval/exp_report.py](../../eval/exp_report.py); `repeats: 3` in E1/E3/E4. Inclusion of failed and timed-out runs not verified |
| Prompts: six slots; context and temperature from config | **PARTIAL** | C1 six-slot YAML [config/prompts/c1_investigator.yaml](../../config/prompts/c1_investigator.yaml); C2 prompts inline in Python [prompts.py:106-160](../../src/agent/prompts.py#L106-L160); `max_turns` hard-coded |
| Models: exact IDs per run; judge from another family; no gold in prompts | **FAIL** | IDs recorded in transcripts and in `investigator_agent`; judge family OK; **`LES-9ADC37` injects the gold disposition text into prompts** (AG-03) |
| Submission artefacts | **PARTIAL** | README, architecture (Mermaid + walkthrough), threat model, memory policy and eval report exist. **Missing:** one-command `docker compose up` quick start, experiment log, contribution log, tool catalogue, graph export |
| Signature A: auditable numbers and narrative | **PASS** | Decimal-only types [canonical.py:39-83](../../src/core/canonical.py#L39-L83); `calc_log` grounding of prose numbers [verifier.py:228-246](../../src/core/verifier.py#L228-L246) |
| Signature B: hypothesis-driven under a budget | **PARTIAL** | Competing hypotheses + ledger. LLM C2 replans once regardless of evidence, and its loop exit depends on the LLM (AG-12) |

---

## 3. Workflow assurance matrix (C0 / C1 / C2)

**Traced call chain (common to all modes):**

1. `POST /api/v1/investigations[/run]` ([investigations.py:46-87](../../src/api/routes/investigations.py#L46-L87))
2. `runner.register_thread` / `run_thread` ([runner.py:59-82, 304-322](../../src/api/services/runner.py#L59-L82))
3. `execute_mode` → `run_graph` ([graph.py:495-542](../../src/agent/graph.py#L495-L542))
4. `select_graph` ([graph.py:464-477](../../src/agent/graph.py#L464-L477)) → node `_wrap` (merge + `_persist` + SSE `emit`) ([graph.py:234-244](../../src/agent/graph.py#L234-L244))
5. `GuardedToolbox.call` → `pre_tool_hook` → `call_mcp_tool` (FastMCP in-memory or HTTP) → `post_tool_hook` ([tooling.py:59-112](../../src/agent/tooling.py#L59-L112))
6. `case-actions.draft_disposition_report` → `case_repo.upsert_draft` (SQLite/Postgres)
7. `human_gate` `interrupt()`
8. `POST …/decision/prepare` → `POST …/decision` → `resume_and_commit_gate` → `commit_disposition` → `submit_case_disposition` → `case_repo.commit_case` (one transaction)
9. Durable `investigation_events`, read by SSE ([investigations.py:105-132](../../src/api/routes/investigations.py#L105-L132))

| Concern | C0 | C1 | C2 |
|---|---|---|---|
| Genuine execution / hypothesis testing | **PASS**: fixed scan→draft, no agent decisions ([graph.py:379-389](../../src/agent/graph.py#L379-L389)); scores from config ([c0_fixed.py:215-251](../../src/agent/c0_fixed.py#L215-L251)) | **PASS (live/replay)**: real tool-calling loop ([loop.py:428-503](../../src/agent/loop.py#L428-L503)); competing hypotheses via `finish` schema. **Note:** without an LLM, C1 silently becomes the rule_engine graph ([graph.py:469-477](../../src/agent/graph.py#L469-L477)), so offline C1 = rule_engine (both 51.7%, BASELINE §2) | **PASS (live/replay)**: supervisor + specialist LLM loops ([c2_stages.py:151-467](../../src/agent/c2_stages.py#L151-L467)). Same silent offline fallback |
| Topology / reducers / termination | **PASS**: no orphans, all paths reach END or interrupt (BASELINE §5) | **PASS** topology. **PARTIAL** reducers: list keys use replace semantics, relying on cumulative returns; `as_state` drops unknown keys ([graph.py:76-123](../../src/agent/graph.py#L76-L123)) | **PARTIAL**: replan loop exits only when `replan_count ≥ 1`, which depends on the LLM actually calling `replan_graph` ([c2_stages.py:278-309, 470-471](../../src/agent/c2_stages.py#L278-L309)); otherwise the backstop is cost or `recursion_limit` |
| Critique/replan feedback wiring | **PASS**: verifier discrepancies fed back ([drafting.py:156-163](../../src/agent/drafting.py#L156-L163)) | **PASS**: structured `VERIFICATION_FAILED` errors + known IDs fed back to the next turn ([loop.py:356-368](../../src/agent/loop.py#L356-L368)) | **PASS** (reporter_critic uses the same verifier). **PARTIAL** for replan (hard cap 1) |
| Budget enforcement | **PASS** | **PASS** (tool, cost, critique). `max_turns` hard-coded | **PARTIAL**: replan budget ignored (1 vs 3); hand-off sub-budget 2 and `max_turns` 2 hard-coded ([c2_stages.py:324, 341](../../src/agent/c2_stages.py#L324)) |
| Idempotency / crash-resume / MCP failures | **PASS**: draft upsert keyed on (thread_id, revision) ([case_repo.py:95-147](../../src/db/case_repo.py#L95-L147)); commit guarded by token rowcount + status + unique case per alert ([case_repo.py:271-311](../../src/db/case_repo.py#L271-L311)); MCP errors → envelopes → `tool_errors` | **PARTIAL**: a crash inside `agent_loop` replays the whole loop (one node) | **PASS**: per-stage checkpoints |
| Specialist isolation / held-out isolation | n/a / **PASS** | n/a / **PASS** | **PASS**: per-role `GuardedToolbox` with the allow-list enforced in `pre_tool_hook`; `src/` never reads held-out paths (seeder refuses `eval/` [seeder.py:134-150](../../src/db/seeder.py#L134-L150)); eval overlay strips labels ([bank_records.py:46-79](../../src/mcp_servers/bank_records.py#L46-L79)) |
| API/SSE fidelity | **PASS**: per-node events | **PARTIAL**: plan/tool/replan events for LLM C1 are synthesised *after* the loop finishes ([runner.py:149-205](../../src/api/services/runner.py#L149-L205)). The values are real, but nothing streams during the ReAct loop | **PASS**: per-stage events |

---

## 4. Non-negotiable invariants (5/5)

### 4.1 Zero LLM arithmetic (Decimal purity): **PASS**

- **Wiring:**
  - `to_decimal` rejects `float`/`bool` ([canonical.py:39-56](../../src/core/canonical.py#L39-L56)).
  - The `Money`/`Ratio`/`Usd` Pydantic types serialise to fixed-point strings ([canonical.py:87-110](../../src/core/canonical.py#L87-L110)).
  - The graph engine and verifier recompute net and retention ([verifier.py:191-226](../../src/core/verifier.py#L191-L226)).
  - Prose INR and % figures must appear in `calc_log` or tool outputs ([verifier.py:228-246](../../src/core/verifier.py#L228-L246)).
  - Measured: 77/77 paths satisfy `outflow − consolidated = net` exactly (BASELINE §4).
- **Edge cases:**
  - `float` appears only for confidence and display: [runner.py:284](../../src/api/services/runner.py#L284), [c0_fixed.py:215-251](../../src/agent/c0_fixed.py#L215-L251), [gathering.py:47](../../src/agent/gathering.py#L47) (a `retention_pct` comparison only), [app.py:206](../../src/ui/app.py#L206).
  - No money reaches the LLM as a float.
  - The policy loader converts YAML floats through `str` ([policy.py:28-32](../../src/core/policy.py#L28-L32)).

### 4.2 Cryptographic human gating: **PARTIAL**

**What is wired and correct:**

- The only caller of `submit_case_disposition` is the `commit_disposition` node. It runs only after `human_gate` resumes with `action=approve` and a token ([graph.py:275-311](../../src/agent/graph.py#L275-L311)). The hook denies the call without the flag ([hooks.py:139-144](../../src/guardrails/hooks.py#L139-L144)).
- The token is HMAC-SHA256 over `hash|reviewer|nonce`, compared with `hmac.compare_digest` ([case_repo.py:38-44, 258-260](../../src/db/case_repo.py#L38-L44)).
- It is bound to the recomputed SHA-256 of the stored content ([case_repo.py:243-253](../../src/db/case_repo.py#L243-L253)).
- It is consumed atomically (`UPDATE … WHERE consumed_at IS NULL` with a rowcount check) in the same transaction as the case insert ([case_repo.py:264-330](../../src/db/case_repo.py#L264-L330)).
- An edit supersedes all tokens ([case_repo.py:150-185](../../src/db/case_repo.py#L150-L185)).
- Expiry and reviewer-identity binding are checked on the server ([case_repo.py:254-257](../../src/db/case_repo.py#L254-L257)).

**Bypass and edge-case analysis:**

- **FAIL: requester = approver is allowed.**
  - `owner` is written at registration ([runner.py:67](../../src/api/services/runner.py#L67)).
  - It is then overwritten by the first graph `_persist`, because `inv` has no `owner` field ([graph.py:219-231](../../src/agent/graph.py#L219-L231)).
  - It is never compared in `prepare_decision`/`approve` ([approval.py:86-112, 237-294](../../src/api/services/approval.py#L86-L112)).
  - A `senior_reviewer` who edits is immediately handed a fresh token for their own edit ([approval.py:154-158](../../src/api/services/approval.py#L154-L158)).
- **FAIL (optional UI): shared Chainlit identity.** Every Chainlit session uses one module-level `reviewer` token ([app.py:28-49](../../src/ui/app.py#L28-L49)).
- **MEDIUM: tokens at rest.** The plaintext token is stored in `approval_tokens.hmac_token` ([case_repo.py:214-219](../../src/db/case_repo.py#L214-L219)) and in the LangGraph `gate` channel checkpoint ([graph.py:263-271](../../src/agent/graph.py#L263-L271)).
- **Double-click:** serialised in-process by `_lock_for_thread`. Across processes, the DB rowcount guard means the second request gets `INTERRUPT_NOT_ACTIVE`/`ALREADY_CONSUMED`: safe.
- **`has_human_approval_token` is a caller-asserted boolean**, not verified in the hook. Safe today only because `case_repo` re-validates the token.

### 4.3 Untrusted-data delimiting and breakout prevention: **PARTIAL**

- **Wiring:**
  - `post_tool_hook` runs on every successful tool result ([tooling.py:98](../../src/agent/tooling.py#L98)).
  - Values are XML-escaped before wrapping, so an embedded `</untrusted_data>` becomes `&lt;/untrusted_data&gt;` ([guardrails.py:199-202](../../src/guardrails/guardrails.py#L199-L202)).
  - The source ID is sanitised.
- **Gap:** wrapping and injection screening apply only to keys in `UNTRUSTED_TEXT_FIELDS` (7 names) ([hooks.py:95-103](../../src/guardrails/hooks.py#L95-L103)). Every other string (for example KYC `entity_type`/occupation, `bank_name`, registry fields, tool error messages that echo input) is only PII-masked ([hooks.py:224-225](../../src/guardrails/hooks.py#L224-L225)).
- **By design:** the regulatory corpus is wrapped but not screened ([hooks.py:106](../../src/guardrails/hooks.py#L106)).
- **Off path:** with `defenses_enabled=False`, no wrapping happens at all ([tooling.py:67-72](../../src/agent/tooling.py#L67-L72)). This is intended for the E2 ablation.

### 4.4 Output guardrails and evidence grounding: **PARTIAL**

- **Wiring:**
  - Guilt-assertion families are checked server-side in `draft_disposition_report`, which downgrades to `request_info` ([case_actions.py:88-122](../../src/mcp_servers/case_actions.py#L88-L122)), and again in LLM narrative synthesis ([llm_client.py:300, 387](../../src/agent/llm_client.py#L300)).
  - Every referenced ID must be in **this run's** `evidence_registry` and owned by this case ([verifier.py:385-398](../../src/core/verifier.py#L385-L398)).
  - Citations must be in both the corpus and the registry ([verifier.py:280-295](../../src/core/verifier.py#L280-L295)).
- **Gap: no tipping-off detection anywhere.** [verifier_patterns.py:17-65](../../src/core/verifier_patterns.py#L17-L65) covers guilt only. The corpus has a tipping-off SOP, but nothing enforces it.

### 4.5 Durable checkpointing, trimming and erasure: **PARTIAL**

- **Checkpointing:**
  - `AsyncSqliteSaver` locally; `AsyncPostgresSaver` when `USE_POSTGRES=true` (Compose) ([graph.py:186-213](../../src/agent/graph.py#L186-L213)). Never `MemorySaver`.
  - Resume works; covered by tests.
  - Default local execution is SQLite, not Postgres.
- **Trimming:** `trim_messages_with_summary` keeps system messages and never splits an assistant tool call from its tool results ([store.py:34-64](../../src/memory/store.py#L34-L64)). However, it is applied **only to the stored copy after the loop**, not to the live context ([loop.py:450 vs 522](../../src/agent/loop.py#L450)). Evidence and approval state are separate channels and are never summarised: PASS.
- **Erasure:**
  - The SQL purge/redaction runs in one `get_db()` transaction ([erasure.py:86-134](../../src/api/services/erasure.py#L86-L134)).
  - The LangGraph saver purge runs **afterwards**, on a separate connection ([erasure.py:136](../../src/api/services/erasure.py#L136)). This contradicts the module docstring.
  - Per-run transcripts (`runs/*/transcripts.jsonl`) and Loki logs are not purged.

---

## 5. Targeted reviews

### 5.1 MCP: per-tool table

| Server.tool | Label (docstring) | Works | Correct (measured) | Error handling | Test exists | Defects |
|---|---|---|---|---|---|---|
| bank-records.get_alert_context | read | Y | Y (22/22 alerts) | Y | Y | — |
| bank-records.get_account_transactions | read | Y | **Y: 40/40 accounts exact rows + Decimal sum vs SQL** | Y (range, extra, missing → envelope) | Y | `days_back` capped at 365 with no hint in the error |
| bank-records.get_kyc_profile | read | Y | not measured | Y (`ACCOUNT_NOT_FOUND`) | Y | `entity_type` not wrapped (AG-15) |
| bank-records.get_counterparty_history | read | Y | not measured | Y | Y | — |
| bank-records.check_commercial_registry | read | Y | not measured | Y | Y | — |
| graph-engine.find_candidate_fund_flows | compute | Y | **Y: 77/77 paths conserve exactly** | Y (bounds hook; schema) | Y | Input schema (`sender`/`receiver`) ≠ bank-records output (`sender_account`/…); needs the `graph_tx_payload` adapter (AG-34) |
| graph-engine.compute_flow_conservation | compute | Y | not measured separately | Y | Y | — |
| graph-engine.compare_graph_runs | compute | Y | not measured | Y | Y | — |
| compliance-kb.search_regulations | read | Y | IDs exist; R@5 0.915 | Y (abstain) | Y | No superseded or jurisdiction filter; corpus has no `superseded_by` field |
| compliance-kb.get_clause_by_id | read | Y | Y | Y (`CLAUSE_NOT_FOUND`) | Y | — |
| case-actions.draft_disposition_report | write | Y | idempotent per (thread, rev 1) | Y | Y | — |
| case-actions.submit_case_disposition | write (gated) | Y | prepare→approve→submit→receipt consistent; replay/stale/double rejected (tests) | Y | Y | No maker-checker (AG-02) |

- **Rule-engine precision/recall per rule:** not computed. There is no per-rule label in the dev set, and only disposition labels exist. The rule_engine mode scores 51.7% disposition accuracy on 60 dev cases.
- **Liveness over HTTP:** covered by `tests/test_mcp_http_transport.py` (passes). Not re-run manually, because the Compose fleet was not started.
- **Rogue-server protection:** a shared service token header ([http_auth.py](../../src/mcp_servers/http_auth.py)). No pinned server list and no tool-description hash check. The template marks this "if specified", so it is noted only.

### 5.2 RAG

| Item | Status | Evidence |
|---|---|---|
| Ingestion metadata | **PARTIAL**: `effective_date`, `retrieval_date`, `source_url`, `category`, `source_type`. No version, `superseded_by` or jurisdiction field. `human_verified` is a stored flag | 165 passages (145 regulatory / 20 internal); 0 with `superseded_by` |
| Re-ingestion idempotency | **PASS**: index rebuilt in-process from JSONL; no external vector store to duplicate into | [compliance_kb.py:438-466](../../src/mcp_servers/compliance_kb.py#L438-L466) |
| BM25 | **PASS** (k1/b hard-coded 1.5/0.75) | [246-264](../../src/mcp_servers/compliance_kb.py#L246-L264) |
| Vectors | **FAIL vs spec**: TF-IDF→SVD (96-dim) over hand features + a 40/60 blend; same encoder at index and query time. The configured `embedding_model: BAAI/bge-m3` is never used | [196-226, 266-273](../../src/mcp_servers/compliance_kb.py#L196-L226); `grep embedding_model src` → only `policy.py:155` |
| RRF with config `k` | **PASS** (`rrf_k: 60`) | [396-406](../../src/mcp_servers/compliance_kb.py#L396-L406) |
| Cross-encoder reranker | **FAIL vs spec**: linear mix of RRF/BM25/dense/coverage/bigram/title/ID-hit with hand weights. `reranker_model` unused | [319-362](../../src/mcp_servers/compliance_kb.py#L319-L362) |
| Query technique | **PASS (deterministic path)**: decomposition on `;`, used by `gather_evidence`. For LLM agents it only fires if the LLM writes `;` | [469-519](../../src/mcp_servers/compliance_kb.py#L469-L519), [gathering.py:275](../../src/agent/gathering.py#L275) |
| Metadata filters | **PARTIAL**: `source_type` only. No effective-date or superseded filter | [228-231](../../src/mcp_servers/compliance_kb.py#L228-L231) |
| Citation integrity | **PASS** | [verifier.py:280-295](../../src/core/verifier.py#L280-L295) |
| Staircase | BM25 0.875 → dense 0.799 → hybrid 0.915 → +rerank 0.915 → +decomposition (not measured) | BASELINE §3 |
| Overfitting risk | **MEDIUM**: the 40-stem `DOMAIN_CONCEPTS` synonym table ("politician", "dodge", "bucket", "video", "dirty") and 5 abstention thresholds are hand-tuned with no separate tuning/test split in the reported numbers | [55-104](../../src/mcp_servers/compliance_kb.py#L55-L104) |

**Optimisation candidates.** None will be applied without measurement and your approval.

1. Replace the hand reranker with the configured cross-encoder. This needs the `[rag]` extra and a dependency decision.
2. Add `superseded_by` + `effective_to` to the corpus and an as-of filter.
3. Move BM25 `k1`/`b`, blend weights and abstention thresholds into `config/models.yaml` `retrieval:`.
4. Add p50/p95 retrieval latency to `retrieval-bench`.
5. Add a decomposition step to the staircase.
6. Report the existing held-out NL query file once, after tuning is frozen.

Index caching and loading once per process are already done (singleton [430-466](../../src/mcp_servers/compliance_kb.py#L430-L466)).

### 5.3 Human approval test matrix

| # | Requirement | Verdict | Proof |
|---|---|---|---|
| 1 | Every world-changing action pauses at `interrupt()` and resumes via `Command(resume=…)` | **PASS** | [graph.py:247-272, 561, 576](../../src/agent/graph.py#L247-L272); the only write tool caller is `commit_disposition` (grep in §4.2) |
| 2 | Exact payload + hash shown to the approver | **PASS (API/workbench)** | Terminal SSE event carries `worksheet` + `payload_hash` ([runner.py:278-300](../../src/api/services/runner.py#L278-L300)) |
| 3 | Approve executes that payload once | **PASS** | [case_repo.py:264-330](../../src/db/case_repo.py#L264-L330); unique case per alert |
| 4 | Edit → new hash → old approval invalid → fresh approval required | **PASS** | [case_repo.py:150-185](../../src/db/case_repo.py#L150-L185); `tests/test_approval_invalidation.py` |
| 5 | Reject → nothing executed, reason recorded | **PASS** | [approval.py:297-318](../../src/api/services/approval.py#L297-L318), [case_repo.py:380-401](../../src/db/case_repo.py#L380-L401). `_release_gate` swallows resume errors (logged) ([approval.py:47-52](../../src/api/services/approval.py#L47-L52)) |
| 6a | Replay of a used token | **PASS** | `ALREADY_CONSUMED` [case_repo.py:250-251, 278-279](../../src/db/case_repo.py#L250-L251) |
| 6b | Expired token | **PASS** | [case_repo.py:256-257](../../src/db/case_repo.py#L256-L257) |
| 6c | Requester = approver | **FAIL** | AG-02 |
| 6d | Double-click | **PASS** | Thread lock + DB guards |
| 7 | Approval survives a restart mid-pause, no earlier node re-runs | **PASS (SQLite)**; Postgres path not executed in this audit | `tests/test_checkpoint_resume.py`; `_is_paused` resume [graph.py:518-520](../../src/agent/graph.py#L518-L520) |
| 8 | No code path to the write tool without the gate | **PASS** | Only [graph.py:278-289](../../src/agent/graph.py#L278-L289) calls it. The defences-off toolbox skips the hook, but `case_repo` still validates the token |

### 5.4 Reflection

**(a) Drafter ↔ critic loop: PASS (code-only).**

- Code checks run first; there is no judge step.
- Structured discrepancies (code, field, detail) and the known evidence IDs are fed back into the next attempt ([drafting.py:156-163](../../src/agent/drafting.py#L156-L163), [loop.py:356-368](../../src/agent/loop.py#L356-L368)).
- The loop is bounded by `max_critique_retries`, and only retries when a live LLM can change the output.
- A planted wrong amount is caught: tests in `tests/test_verifier_v2.py` and `tests/test_agent_loop.py`.

**(b) Reflexion loop: FAIL**

| # | Requirement | Verdict | Proof |
|---|---|---|---|
| 1 | Dev-only | **PASS** | [reflexion/loop.py:58-60, 275, 298](../../src/reflexion/loop.py#L58-L60) |
| 2 | Checker-code scoring | **PASS** | `score_case` in `eval/run_eval.py` |
| 3 | One short lesson with preconditions | **PARTIAL**: the current generator is fine ([reflexion/loop.py:130-178](../../src/reflexion/loop.py#L130-L178)), but the committed `LES-9ADC37` names a gold `category` ("marketplace_payout", a v1 label; [data/synthetic_generator.py:38](../../data/synthetic_generator.py#L38)) and the gold answer ("Predicted request_info instead of close_benign"). The current generator cannot produce that text, so the artefact is stale | [config/reflexion_playbook.json](../../config/reflexion_playbook.json) |
| 4 | Human review: accept / edit / reject-with-reason | **FAIL**: no CLI or UI. The build script auto-approves every generated lesson with one canned rationale | [build_frozen_playbook.py:59-71](../../scripts/build_frozen_playbook.py#L59-L71) |
| 5 | ≤2 relevant lessons (similarity + applicability) | **FAIL**: top-3 by word overlap with no threshold. The query is `f"{rule_name} scatter gather"`, and `rule_name` is `SCATTER_GATHER` for every dev case, so every case gets the same 3 lessons | [store.py:252-261](../../src/memory/store.py#L252-L261), [loop.py:259-263](../../src/agent/loop.py#L259-L263), [planning.py:219-220](../../src/agent/planning.py#L219-L220) |
| 6 | Freeze (git tag + file hash) before held-out; E3 loads the frozen file | **PARTIAL**: a `frozen` flag is in the JSON and `system_flags`. No tag, no hash check. `load_playbook` **deletes** the DB playbook before reloading ([store.py:222-226](../../src/memory/store.py#L222-L226)) | — |
| 7 | Rejected lesson with reason | **PARTIAL**: `LES-REJ-001` is a planted example, not a reviewed candidate | [build_frozen_playbook.py:49-56](../../scripts/build_frozen_playbook.py) |
| 8 | E3 reports lesson cost and harmful lessons | **FAIL**: not in the harness | `grep lesson_cost\|harmful eval/` → none |

### 5.5 Memory

**Short-term**

| Item | Verdict | Proof |
|---|---|---|
| Thread persisted by the checkpointer | **PASS** | §4.5 |
| Trimming at the configured threshold (12) | **PARTIAL**: only for storage after the loop | [loop.py:522-524](../../src/agent/loop.py#L522-L524) |
| System prompts and tool-call pairs never split | **PASS** | [store.py:44-56](../../src/memory/store.py#L44-L56) |
| Evidence and approval state never summarised | **PASS** | Separate state keys |
| Long case completes without overflow | **PASS by bound**: `max_turns=12`, not by trimming | — |

**Long-term**

| Item | Verdict | Proof |
|---|---|---|
| Persistent store | **PASS**: SQLite/Postgres tables | [store.py:100-134](../../src/memory/store.py#L100-L134) |
| Written exactly per policy | **PASS**: after a human-approved commit only | [approval.py:202-234](../../src/api/services/approval.py#L202-L234) |
| Read for the matching subject only | **FAIL: never read.** `get_entity_profile` and `get_case_episodes` have no callers outside the store, so cross-subject leakage and the stale-memory trap cannot occur, and memory has no effect | `grep -rn get_entity_profile\|get_case_episodes src eval` → definitions only |
| Correct and delete | **PARTIAL**: delete endpoint exists ([investigations.py:288-296](../../src/api/routes/investigations.py#L288-L296)); not atomic with the saver purge; no "correct" operation | §4.5 |
| `memory_policy.md` matches the code | **FAIL** | [memory_policy.md:13](../memory_policy.md) claims agents read `entity_profiles` |
| On/off comparison from config | **FAIL (vacuous)**: in E3, `memory_enabled` only gates lesson retrieval, together with `reflexion_enabled` | [config/experiments/E3.yaml](../../config/experiments/E3.yaml), [loop.py:260](../../src/agent/loop.py#L260) |

### 5.6 Observability

| Requirement | Status | Proof |
|---|---|---|
| Every LLM request traced (ids, node, role, base URL, model, prompt version, temperature, tokens, latency, cost, retries, errors) | **PARTIAL**: `src/llm/client.py` appends JSONL transcripts per `run_id` (model, tokens, Decimal cost, latency). Missing: node/role, prompt version, base URL, correlation to API request. The secondary narrative client `src/agent/llm_client.py` writes no transcript. No tracing backend | [llm/replay.py:67-154](../../src/llm/replay.py#L67-L154) |
| Every tool call traced (server, tool, caller, redacted args, size/status, latency, hook decision) | **PARTIAL**: `AgentToolRuntime.tool_execution_log` (agent tools) + audit rows for errors and injection only. No latency, no per-call Prometheus metric | [tools.py:401](../../src/agent/tools.py#L401), [tooling.py:53-57, 99-107](../../src/agent/tooling.py#L53-L57) |
| One correlation ID API → graph → MCP → logs → SSE | **FAIL**: a correlation ID is generated only on errors ([main.py:109](../../src/api/main.py#L109), [runner.py:314](../../src/api/services/runner.py#L314)). `thread_id` exists but is not sent to MCP | — |
| Structured JSON logging + redaction | **PARTIAL**: Loki shipper with redaction ([observability/](../../src/observability/)). The std `logging` config is not JSON | — |
| Prometheus, low cardinality | **PARTIAL**: 4 metrics only (`mode`, `disposition`, `status` labels: low cardinality, good). Missing: LLM requests/latency/tokens/cost, tool errors, replans, critic rejections, guardrail blocks, pending approvals | [metrics.py:5-12](../../src/api/metrics.py#L5-L12) |
| Grafana + required MCP-failure alert | **PARTIAL**: dashboard with 6 panels exists. Alerts exist only for citation failures and p95 latency; **no MCP-failure alert** | [monitoring/alerts.yml](../../monitoring/alerts.yml) |
| Sample C2 trace | **Not producible**: no tracing backend and no correlation ID. The nearest equivalent is the `investigation_events` rows for one `thread_id` plus `runs/<run_id>/transcripts.jsonl` | — |

### 5.7 Frontend logoff

- **Framework:**
  - Primary: vanilla ES-module workbench ([src/ui/static/](../../src/ui/static/)). Its JWT is kept in `sessionStorage` ([api.js:8-26](../../src/ui/static/js/api.js#L8-L26)).
  - Optional: Chainlit ([src/ui/app.py](../../src/ui/app.py)). It has **no** auth callback and uses a shared service-account token.
- **Logout control:** **FAIL.** The words `logout`, `sign out` and `log out` appear nowhere in `index.html` or `js/*.js`. The server endpoint `POST /api/v1/auth/logout` revokes the `jti` ([ui.py routes](../../src/api/routes/ui.py), [auth.py:69-99](../../src/api/auth.py#L69-L99)) and is tested (`tests/test_audit_wave2_closure.py:190-193`), but the UI never calls it. SSE close-on-logout and back-button protection: not implemented.
- **Identity:** taken from the JWT, never from the body ([models.py:335-336](../../src/models.py#L335-L336)). Good. But maker-checker is absent (AG-02), and Chainlit collapses all users into `reviewer` (AG-01).
- **Planned design (Wave 2):**
  - Add a "Log out" button that calls the logout endpoint, clears `sessionStorage`, closes the open `EventSource`, and redirects to login. Set `Cache-Control: no-store` on protected API responses.
  - For Chainlit, use `@cl.password_auth_callback`, so Chainlit's built-in user-menu logout appears. Mint each user's own JWT, held per session instead of in a module-level cache.
  - Tests: post-logout request → 401, post-logout approve → 401.

### 5.8 Start/stop scripts

- **Current state:** none (`scripts/start_local.ps1` only, Windows, API only). No `make start`/`stop`. The README quick-start does not use Compose.
- **Planned design:** as specified in the prompt (§7.8), plus:
  - An explicit project name (`-p auditguard-v3` / `COMPOSE_PROJECT_NAME`), to avoid the collision described in BASELINE §6.
  - Healthchecks added to the MCP, API and UI services so `start.sh` can wait on them.
  - A `--with-llm` profile, only once you decide the local-LLM question (Q3 below).

### 5.9 Simplification proposals

These are a proposal table only; nothing is applied without approval.

| # | Candidate | File:Line | Why over-engineered | Replacement | ~Lines removed | Risk | Requirement touched |
|---|---|---|---|---|---:|---|---|
| S1 | Dead monolithic C2 runner | [c2_loop.py:395-574](../../src/agent/c2_loop.py#L395-L574) (`_merge_specialist_runtimes`, `_maybe_replan_flow`, `_gather_c2_specialists`, `_c2_state_update`, `run_c2_agent_team`) + runner `c2_agent_team` branches [runner.py:144, 205](../../src/api/services/runner.py#L144) | Superseded by `c2_stages.py`; reachable from nowhere | Delete | ~185 | Low | none |
| S2 | Re-export shim | [src/guardrails/verifier.py](../../src/guardrails/verifier.py) (15 lines) | Only forwards `src.core.verifier` | Import `src.core.verifier` directly | 15 | Low | none |
| S3 | Aliases | `tag_untrusted` [guardrails.py:211-212](../../src/guardrails/guardrails.py#L211-L212), `INJECTION_PATTERNS` [148](../../src/guardrails/guardrails.py#L148) | One-line aliases | Use the canonical names | ~4 | Low | none |
| S4 | Duplicate route | `POST /decision/prepare` [investigations.py:168-172](../../src/api/routes/investigations.py#L168-L172) | Duplicates the per-thread route | Remove (public API change, needs approval) | 6 | Medium (UI may call it) | none, because the per-thread route remains |
| S5 | Near-duplicate gate resumes | `resume_gate` / `resume_and_commit_gate` [graph.py:553-579](../../src/agent/graph.py#L553-L579) | Same body, different return | One function returning the commit result | ~12 | Low | #9 still met (same interrupt/commit path) |
| S6 | Custom saver init cache | `_SAVER_INIT_LOCKS`, `_INITIALIZED_SAVER_PATHS`, `_saver_lock` [graph.py:55-56, 174-213](../../src/agent/graph.py#L174-L213) | Reimplements `setup()` idempotency, and clears locks at 64 entries | Call `saver.setup()` (idempotent) under one lock | ~25 | Medium (SQLite busy errors under concurrency) | #3 still met (same checkpointer) |
| S7 | Two LLM clients | [src/llm/client.py](../../src/llm/client.py) + [src/agent/llm_client.py](../../src/agent/llm_client.py) (430 lines; narrative synthesis, flags, shared httpx) | Two HTTP paths, only one with transcripts and replay | Route narrative synthesis through `LLMClient` | ~150 | **High**: changes cassette keys and replay results | Experiments must be re-recorded; needs approval |
| S8 | Offline C1/C2 rubric graphs | [graph.py:469-477](../../src/agent/graph.py#L469-L477) | Without an LLM, "C1"/"C2" silently run the rule_engine graph (identical 51.7%) | Fail fast, or label offline runs explicitly as `rule_engine` | ~0–40 | Medium: E1 offline numbers change meaning | #6: still met because the LLM C1/C2 graphs remain |
| S9 | Dual thread persistence | `_persist`/`save_checkpoint` per node [graph.py:219-244](../../src/agent/graph.py#L219-L244) + LangGraph saver | Two sources of truth for state (the cause of the lost `owner`, AG-02) | Read thread views from `compiled.aget_state` | ~100+ | **High**: SSE, approval and erasure depend on it | #3/#9 still met if done carefully. Recommend deferring |

**Protected list respected:** none of S1–S9 removes an MCP server, a RAG stage, the checkpointer, hooks, approval, guardrails, the critic loop, Reflexion, the judge, any of C0/C1/C2, or the harness.

---

## 6. Code quality, architecture and security findings

| ID | Severity | Category | File:Line | Exact defect | Concrete fix | Requirement |
|---|---|---|---|---|---|---|
| AG-01 | CRITICAL | Security / UI | [src/ui/app.py:28-49](../../src/ui/app.py#L28-L49) | Chainlit has no user auth. A module-level `_token_cache` holds one `reviewer` (`senior_reviewer`) JWT shared by every session, so any visitor to :8001 can approve, and all actions are attributed to `reviewer` | `@cl.password_auth_callback` → per-session JWT from `/api/v1/auth/token` stored in `cl.user_session`; drop the module cache and the env-password fallback | #9, #10, invariant 2 |
| AG-02 | CRITICAL | Security / Approval | [runner.py:67](../../src/api/services/runner.py#L67), [graph.py:219-231](../../src/agent/graph.py#L219-L231), [approval.py:86-112, 154-158, 237-294](../../src/api/services/approval.py#L86-L112) | No requester ≠ approver check. `owner` is stored, then lost on the first node persist, and never compared. A senior who edits receives a token for their own edit | Persist `requested_by` in `InvestigationState` (or the thread row); in `prepare_decision`/`approve`, reject when `principal.sub` is the requester or last editor (`SELF_APPROVAL_FORBIDDEN`, 403); bind the check in `case_repo.commit_case` too | Invariant 2, #9 |
| AG-03 | CRITICAL | Eval integrity | [config/reflexion_playbook.json](../../config/reflexion_playbook.json) (`LES-9ADC37`) | The frozen, approved lesson is derived from the gold `category` label and states the gold disposition. Because retrieval is constant (AG-06), it is injected into every case in E3/live runs | Regenerate the playbook from the current label-free generator; add a test that every lesson's text is free of `category`/`family` names and disposition-pair phrasing; re-freeze. (The playbook is a Reflexion artefact, not a role-1 golden-set file) | #7, "gold never in prompts" |
| AG-04 | HIGH | Reflexion | [scripts/build_frozen_playbook.py:59-71](../../scripts/build_frozen_playbook.py#L59-L71) | "Human review" is scripted: every generated lesson is auto-approved with one canned rationale; the rejected lesson is a planted example | Add `auditguard lessons review` (CLI: list pending / accept / edit / reject `--reason`) writing reviewer + timestamp; the build script stops at `pending`; freezing requires zero pending | #7 |
| AG-05 | HIGH | Memory | [store.py:111-144](../../src/memory/store.py#L111-L144); [memory_policy.md:13](../memory_policy.md); [E3.yaml](../../config/experiments/E3.yaml) | Long-term `entity_profiles`/`case_episodes` are written but never read by any agent; the policy doc claims reads; E3 memory arms are identical | Add a `subject_history` read in `plan`/`gather_evidence`, scoped to the alert's customer and wrapped as untrusted, labelled "prior human-approved disposition (may be stale)"; make `memory_enabled` gate it; add cross-subject and stale-trap tests; fix the doc | #4 |
| AG-06 | HIGH | Reflexion / Memory | [store.py:252-261](../../src/memory/store.py#L252-L261), [loop.py:259-263](../../src/agent/loop.py#L259-L263), [planning.py:219-220](../../src/agent/planning.py#L219-L220) | Lesson retrieval: constant query, no minimum score or applicability check, top-3 (spec ≤2) | Query from observed case features (span, depth, skim, registry flags, as computed by `_telemetry_signals`); require overlap ≥ a config threshold **and** precondition match; `top_k` from config (2) | #7 |
| AG-07 | HIGH | RAG | [compliance_kb.py:196-273, 319-362](../../src/mcp_servers/compliance_kb.py#L196-L273); [models.yaml retrieval](../../config/models.yaml) | "Dense" = SVD over hand features; "reranker" = hand-weighted formula; `embedding_model`/`reranker_model` configured but unused | Behind config: real embedding + cross-encoder (`[rag]` extra), loaded once; keep the current path as a fallback; re-measure the staircase. Requires a dependency decision (Q4) | #1 |
| AG-08 | MEDIUM | RAG | [compliance_kb.py:55-104](../../src/mcp_servers/compliance_kb.py#L55-L104) | Hand-written synonym table and abstention thresholds with no tuning/test split; reported R@5 may be optimistic | Freeze the table; report once on `eval/retrieval_held_out_nl.jsonl` after freezing; move thresholds to config | #1 |
| AG-09 | HIGH | Observability | [metrics.py:5-12](../../src/api/metrics.py#L5-L12), [alerts.yml](../../monitoring/alerts.yml), [llm/client.py](../../src/llm/client.py) | No LLM-call tracing backend or correlation ID; 4 metrics only; the required MCP-failure alert is missing | Correlation ID middleware → `RunContext` → MCP `meta`/header → logs → SSE; LLM and tool Prometheus metrics with `role`/`model`/`server`/`tool`/`status` labels; `MCPRepeatedFailures` alert; reuse Loki (no new platform) | #8, #11 |
| AG-10 | HIGH | UI / Security | [src/ui/static/js/api.js:8-26](../../src/ui/static/js/api.js#L8-L26), `index.html` | No logout control; the server revocation endpoint is unused by the UI; SSE not closed; no `no-store` | See §5.7 | #10, §7.7 |
| AG-11 | MEDIUM | Memory | [loop.py:450 vs 522](../../src/agent/loop.py#L450) | Short-term trimming never applied to the live LLM context (bounded only by `max_turns`) | Trim before each `chat()` when messages exceed the window (pairs preserved) and inject `rolling_summary` | #4 |
| AG-12 | HIGH | Orchestration / Budget | [c2_stages.py:278-309, 324, 341, 470-471](../../src/agent/c2_stages.py#L278-L309) | LLM C2 replans at most once (hard-coded), not `max_replans`; the loop exit depends on the LLM obeying the replan directive (otherwise ends via cost or `recursion_limit` → error); hand-off budget and turns hard-coded | Increment a supervisor-side `replan_attempts` counter in `flow_replan` regardless of LLM compliance; gate on `ctx.ledger.try_replan()` and `policy.budgets.max_replans`; move the 2/2 values to config. **Changes experiment results → ask first** | #5, #6, Signature B |
| AG-13 | HIGH | Evaluation | [calibration_status.json](../../eval/replay_bundle/calibration_status.json) | Judge calibrated on 0 human labels; no Cohen's kappa | Human task: label ≥20 packets (the packets exist: 60); then `eval.calibration` computes kappa. Code cannot fix this | #8 |
| AG-14 | HIGH | Security | [verifier_patterns.py:17-65](../../src/core/verifier_patterns.py#L17-L65), [case_actions.py:88-122](../../src/mcp_servers/case_actions.py#L88-L122) | No tipping-off detection (for example "inform the customer that an STR…") | Add a tipping-off pattern family to the output guardrail and the server-side draft check; red-team cases | Invariant 4, #10 |
| AG-15 | HIGH | Security | [hooks.py:95-103, 213-214](../../src/guardrails/hooks.py#L95-L103) | Only 7 named fields are wrapped and screened; every other tool string reaches the LLM unwrapped (PII-masked only) | Invert to a deny-by-default rule: wrap every string field except a small allow-list of IDs, enums and numeric strings; screen all external fields | Invariant 3 |
| AG-16 | MEDIUM | Security | [tooling.py:67-72](../../src/agent/tooling.py#L67-L72) | The defences-off path skips RBAC, the approval hook and the budget verdict entirely (wider than "guardrails off") | Keep RBAC + budget + approval hook always on; let the E2 flag disable only wrapping, screening and PII | #10 (E2 validity) |
| AG-17 | MEDIUM | Security | [case_repo.py:214-219](../../src/db/case_repo.py#L214-L219), [graph.py:263-271](../../src/agent/graph.py#L263-L271) | Plaintext approval tokens at rest (DB and checkpoint `gate` channel) | Store `sha256(token)`; strip `approval_token` from the `gate` state after commit or reject | Invariant 2 |
| AG-18 | MEDIUM | Memory / DB | [erasure.py:86-136](../../src/api/services/erasure.py#L86-L136) | Erasure is not one transaction (saver purge after commit; transcripts and Loki untouched), contrary to the docstring | Purge the saver first in the same logical unit, with compensating failure handling; document the transcript and Loki retention limits | #4, invariant 5 |
| AG-19 | MEDIUM | Ops | [docker-compose.yml](../../docker-compose.yml) | No vector-store service; healthcheck on postgres only; `:latest` images; implicit project name collides with another local stack | Explicit `name:`; healthchecks for MCP, API and UI; pin image tags; vector store only if AG-07 adds one | #11 |
| AG-20 | MEDIUM | Ops / CI | [ci.yml](../../.github/workflows/ci.yml), [eval/run_eval.py:492](../../eval/run_eval.py#L492) | The CI gate is a zero-drift check; `--min-accuracy` exists but is unused; no recorded failed CI run | Add a dev-split threshold step (value to be chosen by you) | #11 |
| AG-21 | MEDIUM | Ops | repo root | No `scripts/start.sh`/`stop.sh`, no `make start`/`stop`; README quick-start is not one-command Compose | §5.8 | #11, §7.8 |
| AG-22 | MEDIUM | Config | [.env.example](../../.env.example), [models.yaml](../../config/models.yaml) | Default LLM is hosted OpenRouter, not the local OpenAI-compatible server the prompt expects; the env var is `OPENAI_BASE_URL`, not `LLM_BASE_URL` | Decision needed (Q3) | Prompt §2 |
| AG-23 | MEDIUM | Domain | whole repo | Jurisdiction is India-only; no US SAR profile | Decision needed (Q5): likely out of scope for this repo | Prompt §2 |
| AG-24 | MEDIUM | Prompts | [prompts.py:106-160](../../src/agent/prompts.py#L106-L160) | C2 supervisor and specialist prompts are inline Python, not versioned six-slot config; prompt version not recorded per LLM call | Move them to `config/prompts/c2_*.yaml` with versions; add `prompt_version` to transcripts. **Changes cassette keys → ask** | Prompts |
| AG-25 | MEDIUM | Hardcoding | [loop.py:46](../../src/agent/loop.py#L46), [case_repo.py:25](../../src/db/case_repo.py#L25), [gathering.py:47-60](../../src/agent/gathering.py#L47-L60), [compliance_kb.py:100-104, 248, 272, 347-358](../../src/mcp_servers/compliance_kb.py#L100-L104), [reflexion/loop.py:242-243](../../src/reflexion/loop.py#L242-L243) | Magic numbers: max_turns 12, token TTL 15 min, typology thresholds, BM25 `k1`/`b`, blend and reranker weights, reflector temperature and tokens | Move them to `config/models.yaml` (values unchanged) | Configuration as truth |
| AG-26 | MEDIUM | Architecture | [c2_stages.py:151](../../src/agent/c2_stages.py#L151) (317 lines), [hypothesis_eval.py:120, 207, 381](../../src/agent/hypothesis_eval.py#L207) (85/172/107), [c2_stages.py:375](../../src/agent/c2_stages.py#L375) (83), [tools.py:256](../../src/agent/tools.py#L256) (83) | Functions over the 80-line limit in AGENTS.md | Split into named helpers (Wave 3) | AGENTS.md §4 |
| AG-27 | MEDIUM | MCP | all servers | No `readOnlyHint`/`destructiveHint` annotations; no tool-catalogue doc or generator | `@mcp.tool(annotations=…)`; `python -m eval.tool_catalogue` → `docs/tool_catalogue.md` | #2 |
| AG-28 | MEDIUM | Concurrency | [graph.py:54](../../src/agent/graph.py#L54), [runner.py:20, 325-328](../../src/api/services/runner.py#L20) | Thread locks and background tasks are process-local; a restart leaves threads `running` with no auto-resume; multi-worker deploys lose the in-process guard (DB guards still protect commit) | Mark stale `running` threads on startup and expose resume; document single-worker or use a DB advisory lock | Resilience |
| AG-29 | MEDIUM | Orchestration / SSE | [graph.py:422-438](../../src/agent/graph.py#L422-L438), [runner.py:149-205](../../src/api/services/runner.py#L149-L205) | The LLM C1 ReAct loop is a single node: no mid-loop checkpoint, and SSE plan/tool events are synthesised after the loop | Emit per-tool events from `AgentToolRuntime.execute` through `ctx.emit` (no topology change) | #3, §4 item 6 |
| AG-30 | MEDIUM | State | [graph.py:76-123](../../src/agent/graph.py#L76-L123) | Replace-semantics reducers rely on each node returning cumulative lists; `as_state` silently drops unknown keys (which lost `owner`) | Log or raise on unknown keys; add reducer tests for `calc_log`, `tool_execution_log` and `critiques` across replans and resume | Reducers |
| AG-31 | MEDIUM | Artefacts | docs/ | Missing experiment log, contribution log, tool catalogue, graph-export generator | Add generators; the contribution log is a human task | Submission |
| AG-32 | MEDIUM | Reflexion | [store.py:213-250](../../src/memory/store.py#L213-L250) | Freeze has no git tag or file hash; `load_playbook` deletes the DB playbook; E3 reports no lesson cost or harmful lessons | Record the `sha256` of the frozen file in the run summary and verify it on load; per-lesson ablation in E3 | #7 |
| AG-33 | MEDIUM | DB | [postgres_backend.py](../../src/db/postgres_backend.py), [init_db.sql:187](../../scripts/init_db.sql#L187) | The Postgres write side uses the same login role with an app-level table allow-list; only the read side has a DB role (`auditguard_ro`) | Add an `auditguard_case_rw` role with grants on 4 tables; the case-actions server uses it | §6 item 5 |
| AG-34 | LOW | MCP | [graph_engine.py:41-48](../../src/mcp_servers/graph_engine.py#L41-L48) vs bank-records output | Field-name mismatch between servers requires an adapter | Accept both shapes, or document the adapter in the catalogue | #2 |
| AG-35 | LOW | Dead code | [graph.py:268](../../src/agent/graph.py#L268), [c2_loop.py:395-574](../../src/agent/c2_loop.py#L395-L574) | `approve` without a token sets `current_node="committed"` with no commit (unreachable via API); ~180 dead C2 lines | Return `rejected`/error; delete the dead code (S1) | — |
| AG-36 | LOW | Concurrency | [store.py:76-78, 103, 127](../../src/memory/store.py#L76-L78) | The singleton's in-memory caches grow unbounded and are never read in persist mode | Skip caching when `persist=True` | — |
| AG-37 | LOW | Lint | [data/synthetic_generator.py:101-197](../../data/synthetic_generator.py#L101) | 6 ruff errors outside the CI lint scope | Fix, or include in scope | — |
| AG-38 | LOW | Typing | [runner.py:284](../../src/api/services/runner.py#L284) | SSE `confidence_score` sent as `float` | Send `dec_str` | Decimal purity (display only) |
| AG-39 | LOW | Security | [auth.py:30-99](../../src/api/auth.py#L30-L99), [planning.py:65-66](../../src/agent/planning.py#L65-L66) | Hand-rolled HS256 JWT; a token without `jti` skips the revocation check; `ctx.box(name)` silently falls back to the primary (write-capable) toolbox for unknown role names | Require `jti`; raise on an unknown box role; consider PyJWT (dependency, ask first) | — |

---

## 7. Test-suite honesty and coverage gaps

**Tautological or over-mocked tests:** none found that mock the verifier, approval/HMAC, hooks or graph and then assert the mock.

- The only `call_mcp_tool` monkeypatches ([test_phase0_acceptance.py:119](../../tests/test_phase0_acceptance.py#L119), [test_adversarial_step6.py:424](../../tests/test_adversarial_step6.py#L424)) inject MCP faults to test degradation, which is legitimate.
- Three tests use real `asyncio.sleep` for SSE or HTTP timing ([test_mcp_http_transport.py:43](../../tests/test_mcp_http_transport.py#L43), [test_adversarial_e2e_step6.py:360](../../tests/test_adversarial_e2e_step6.py#L360), [test_audit_wave2_closure.py:101](../../tests/test_audit_wave2_closure.py#L101)). They are a flakiness risk.
- Every test gets an isolated DB (`conftest.py` guard).

| Required adversarial or edge test | Exists? | Where / gap |
|---|---|---|
| 1-INR tampered payload | Yes | `test_approval_invalidation.py`, `test_core_step2.py` |
| Expired and replayed tokens | Yes | Expiry: `test_phase0_acceptance.py:260-278`; replay: `test_approval_invalidation.py` |
| Double-submit | Partial | Sequential second commit → `ALREADY_COMMITTED` (`test_approval_invalidation.py:49`); no truly concurrent double-click test |
| `</untrusted_data>` breakout | Yes | `test_security_hooks.py`, `test_security_step3.py` |
| Injection in memo or counterparty fields | Yes | red-team v2 + `test_adversarial_step6.py` |
| Injection in **non-listed** fields (AG-15) | **No** | — |
| Budget exhaustion halts | Yes | `test_security_hooks.py`, `test_core_step2.py` |
| MCP timeout / empty / error envelope | Yes | `test_phase0_acceptance.py`, `test_mcp_http_transport.py` |
| Concurrent cases with no state bleed | Partial | `test_adversarial_step6.py`; no two concurrent `run_graph` calls on different alerts asserting disjoint registries and ledgers |
| Kill-and-resume at each gate | Partial | `test_checkpoint_resume.py`; not for every node, and not for LLM C2 stages |
| Trimming keeps tool-call pairs | Yes (function only) | `test_memory_policy.py`; no test that the live context is trimmed |
| Memory delete purge | Yes | `test_memory_policy.py`, `test_adversarial_e2e_step6.py`; no atomicity or failure-injection test |
| Cross-subject memory leakage | **No** (memory is never read) | — |
| Stale-memory trap | **No** | — |
| Unreviewed lesson rejected from playbook | Partial | `test_memory_policy.py` checks that `status=pending` is not retrieved; nothing forbids the scripted approval |
| Lesson free of gold labels (AG-03) | **No** | — |
| Held-out path unreadable | Yes | seeder `PermissionError`, `test_dataset_v2.py`, `test_memory_policy.py` |
| Requester ≠ approver | **No** (feature missing) | — |
| Logout → 401; post-logout approve → 401 | Partial | API revoke → 401 tested; no UI logout and no approve-after-logout test |
| Chainlit per-user identity | **No** | — |
| Tipping-off blocked | **No** | — |
| C2 replan terminates when the LLM ignores the directive | **No** | — |
| Start/stop idempotency | **No** (scripts missing) | — |

---

## 8. Prioritised, dependency-safe remediation plan

Each wave starts only after you reply `proceed wave N`.

**Conflict to resolve first.** §10.1 of the prompt asks for one commit per fix. `AGENTS.md` rule 6 forbids `git commit`. Unless you override it for this work, I will leave changes uncommitted and grouped per finding in `docs/audit/REMEDIATION_LOG.md`.

### Wave 1: critical security, state integrity, graph wiring

1. **AG-02** Requester ≠ approver: persist the requester in state, enforce in `approval.py` + `case_repo`. Failing test first.
2. **AG-01** Chainlit per-user auth (password callback, per-session JWT).
3. **AG-03** Regenerate a label-free playbook, plus a test that lessons contain no gold vocabulary. The playbook is a Reflexion artefact, not a role-1 file, but it changes E3, so I'll confirm with you first.
4. **AG-30** Reducer and unknown-key hardening, with tests; this underpins AG-02.
5. **AG-17** Hash tokens at rest; strip the token from the `gate` channel.
6. **AG-15** Deny-by-default untrusted wrapping, with a red-team test on non-listed fields.
7. **AG-16** Keep RBAC, budget and the approval hook on when defences are off (E2 semantics: confirm with you).
8. **AG-35** (dead `approve`-without-token branch) and **AG-38** (float in SSE).

### Wave 2: resilience, targeted reviews, boundaries

1. **AG-12** C2 replan counter and budget from config. Ask first: it changes E1.
2. **AG-14** Tipping-off guardrail.
3. **AG-05, AG-06, AG-11, AG-18** Memory:
   - subject-history read with scoping;
   - relevant lesson retrieval (≤2, thresholded);
   - live trimming;
   - erasure ordering;
   - corrected `memory_policy.md`.
4. **AG-04, AG-32** Lesson review CLI, freeze hash, E3 lesson cost and harmful-lesson report.
5. **AG-09, AG-29** Correlation ID, LLM and tool metrics, MCP-failure alert, per-tool SSE events.
6. **AG-10** Workbench logout + tests.
7. **AG-21, AG-19** `scripts/start.sh`/`stop.sh` + `make start`/`stop` + compose healthchecks, explicit project name, README.
8. **AG-07, AG-08** RAG. Only if Q4 allows a dependency, and measured against BASELINE §3.
9. **AG-25, AG-27, AG-33, AG-20, AG-28** Config-ise magic numbers (values unchanged), MCP annotations + catalogue generator, Postgres write role, CI threshold (Q6), stale-thread handling.
10. **AG-24** C2 prompts into versioned YAML. Ask first: re-records cassettes.

### Wave 3: tests, then simplification, then typing and complexity

1. Add the missing tests from §7.
2. Approved simplifications from §5.9, one at a time, each with a baseline comparison. Recommended: S1, S2, S3, S5. Ask about S4, S6, S8. Defer S7 and S9.
3. **AG-26** split god functions; **AG-37, AG-39, AG-34, AG-36**.
4. Human-only items, which I can prepare but not complete: **AG-13** judge labels, **AG-31** contribution log.

### Decisions I need from you (nothing below is assumed)

| Q | Decision |
|---|---|
| Q1 | Is this repo (`/Users/chandra/git/AuditGuard`) the intended target, rather than `/Users/chandra/git/genai-project`? |
| Q2 | Commits: keep AGENTS.md's no-commit rule (my default), or allow one local commit per fix (never pushed)? |
| Q3 | Should the default LLM become a local OpenAI-compatible server (`LLM_BASE_URL`, `127.0.0.1:8888`)? This changes config defaults, not cassettes. |
| Q4 | May Wave 2 add the `[rag]` dependencies (sentence-transformers / cross-encoder) to replace the hand-built dense model and reranker (AG-07)? |
| Q5 | Is a US SAR jurisdiction profile in scope, or out of scope for this repo? |
| Q6 | CI accuracy threshold value for the dev split (AG-20). |
| Q7 | May I regenerate `config/reflexion_playbook.json` (AG-03) and change C2 replan behaviour (AG-12), knowing both change E1/E3 results? |
