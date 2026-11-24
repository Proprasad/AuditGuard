# AuditGuard v3 — Implementation Plan & Coding-Agent Guide

*Audience: a coding agent (Claude Code or similar) working inside the `Proprasad/AuditGuard` repo, supervised by the 4-person team. Every claim about the current code below was verified by reading and running the repo (commit `ed7956c`).*

## 0. How the agent must work

1. **Source code is the only truth.** Before editing any file, open and read it. Do not trust README, docs or docstrings; they currently overstate what the code does.
2. **Work phase by phase** (Section 4). Finish a phase, run its acceptance checks, commit with message `phase-N: <summary>`, then stop and print a short status report before starting the next phase.
3. **Never fake a result.** No hard-coded metrics, no `continue`-style skips that make a number true by construction, no tests that assert on values the code itself just wrote. If a metric cannot be computed, raise an error.
4. **Keep the deterministic safety core.** Graph engine (Decimal math), RBAC allow-lists, approval-hash gate, checkpointing stay. They become tools and guards around the LLM, not replacements for it.
5. **Held-out discipline.** Nothing in `data/` or runtime code may read `eval/held_out/`. Prompts, lessons and judge rubrics are tuned on dev only.
6. **Reproducibility.** Every LLM call is logged (prompt, response, model, tokens, cost, latency) to `runs/<run_id>/transcripts.jsonl`; support a `--replay` mode that serves recorded responses so CI never needs an API key.
7. **Ask a human when blocked** on: API keys, labeling work (Phase 4), policy choices marked **[HUMAN]**.

**Definition of done for the whole project:** `make verify` passes; `python -m eval.run_eval --config E1` runs on the held-out split with the YAML honoured; a generated report contains mean ± 95% CI for every metric; no metric listed in a YAML is silently ignored.

## 1. What is wrong today (verified facts)

| # | Finding | Where |
| --- | --- | --- |
| F1 | No LLM client is imported anywhere. `models.yaml`, `config/prompts/c1_investigator.yaml`, `openai_api_key` are dead config. C1/C2 are if/else pipelines (disposition = f(hop count, root risk_category, root registered flag, income vs amount)). Cost, tokens always 0. | `src/agent/c1_single.py` `hypothesis_node`, `draft_worksheet_node`; `c2_multi.py` |
| F2 | 60 cases = 10 templates × 6. All 40 held-out are structurally identical to a dev case. | `data/synthetic_generator.py` |
| F3 | Label is a function of root `(risk_category, is_commercially_registered)` with 100% purity; memos and `kyc_notes` contain label words; registry check re-reads the same flag. | generator + `bank_records.check_commercial_registry` overlay branch |
| F4 | `eval/judge.py` has only `cohens_kappa`; no judge, no rubric, no human labels; never imported. | `eval/judge.py` |
| F5 | `run_eval.py` reads only `modes` and `variants` from YAML. `repeats`, `split`, `budgets`, `metrics`, `defenses_enabled` are ignored (CLI defaults used: 1 repeat, dev split). | `eval/run_eval.py` `run()` |
| F6 | E2 defenses-OFF branch does `continue`, so 0 attacks run; ASR 100% is true by construction. | `evaluate_red_team_suite` |
| F7 | "Replan recovery" = accuracy on a subset; `replan_recovered` computed but unused. Missing metrics: evidence_recall, inr_arithmetic_error_rate, cost, citation validity (only `len>0`). | `run_eval.py` |
| F8 | `verify_inr_math` never called by `verify_worksheet`; `math_verified` = regex format check on citations; citation existence not checked. | `src/guardrails/verifier.py` |
| F9 | C0 can never emit `close_benign` (straw-man baseline). | `c0_fixed.py` |
| F10 | Reflexion lessons are templated from ground-truth `category`; `plan_node` string-matches `"14-30"`. Nothing in `run_eval` populates/freezes a playbook. | `src/reflexion/loop.py`, `c1_single.plan_node` |
| F11 | Retrieval: BM25-only R@1=100%, MRR=1.0; hybrid R@1=85.7%, MRR=0.917 (worse). Corpus = 32 one-sentence clauses. Agent query is a constant string, so all cases get identical citations. | `compliance_kb.py`, `eval/retrieval_bench.jsonl` |
| F12 | Graph uses `nx.DiGraph`: parallel transfers between the same pair overwrite (true 3,00,000 reported as 1,50,000, retention −96%). | `graph_engine._build_graph` |
| F13 | `call_mcp_tool` swallows all exceptions into an error dict, silently becoming `request_info`. | `src/mcp_servers/client.py` |
| F14 | Approval token is minted by the server inside `submit_human_decision`; `approved_hash` optional; `/api/v1/auth/token` issues any role without credentials; `auth_required=False` default. | `src/api/main.py`, `auth.py`, `config.py` |
| F15 | CI installs no `fastmcp`; eval gate has no threshold. | `.github/workflows/ci.yml` |
| F16 | Injection regexes (10 literal English phrases) miss paraphrase/obfuscation/other languages and block legitimate memos ("You are now registered…", "Jailbreak Fitness Studio"). PII misses lowercase PAN, +91 phones, email. | `src/guardrails/guardrails.py` |
| F17 | Forged-registry probe: scatter-gather with root registered + low/medium risk flips C1/C2 to `close_benign` (C0 stays `escalate_str`). | `hypothesis_node` |

## 2. Target architecture (v3)

```
Alert ─► Detector (graph-engine, deterministic) ─► candidate paths
                │
                ▼
   Investigator  (LLM tool-calling loop; modes below)
     tools: bank-records (read), graph-engine (compute), compliance-kb (read),
            calc (decimal helper), draft_disposition_report (write-gated)
     guards: pre/post tool hooks, RBAC, budgets, untrusted-data tagging
                │
                ▼
   Verifier (deterministic): numbers ↔ CALC outputs, citations ↔ corpus, no guilt claims
                │
                ▼
   Worksheet + SHA-256 hash ─► Human approval gate (analyst-signed token) ─► case DB
```

Agent modes (all share tools, budgets, hooks):

| Mode | Description |
| --- | --- |
| `c0_fixed` | Fixed workflow, **fair** baseline: wider fixed window (14d/4 hops), root+counterparty KYC and registry, can output all three dispositions |
| `rule_engine` | Current C1 logic renamed. Strong deterministic baseline; no LLM |
| `c1_single` | One LLM agent, ReAct/tool-calling, bounded replanning via tools |
| `c2_multi` | Supervisor + 4 specialists (flow_tracer, benign_investigator, regulatory_analyst, reporter_critic), each an LLM with RBAC-restricted tools |

Research question for E1: *does an LLM agent beat a strong rule engine, and where?* Expected honest answer: agent wins on messy/contradictory evidence and rationale quality; rule engine wins on cost/latency. Report either outcome.

## 3. Repo layout changes

```
src/llm/            client.py (OpenRouter/OpenAI-compatible via httpx), cost.py, replay.py, schemas.py
src/agent/          c0_fixed.py (fair), rule_engine.py (old c1), c1_single.py (LLM), c2_multi.py (LLM), tools.py, loop.py
src/guardrails/     verifier.py (rewritten), injection.py, pii.py, structural.py
data/generator_v2/  families.py, noise.py, labels.py, build.py
data/golden_v2/dev/              (development split only; accessible for dev workflows)
eval/golden_v2/{held_out,challenge}/  (held-out & challenge splits physically isolated outside runtime data/)
eval/               run_eval.py (rewritten), metrics.py, stats.py, judge.py, judge_rubric.md,
                    shortcuts.py, adjudication.py, human_labels/*.csv, calibration.py, red_team_v2/, report.py
runs/               generated, gitignored
Makefile            verify, data, eval-e1..e4, report
```

## 4. Phases

Each phase lists tasks, then **Acceptance** (agent must run these and show output).

### Phase 0 — Hygiene and safety fixes (½ day)

Tasks:

1. `eval/run_eval.py`: load the YAML fully. Honour `split`, `repeats`, `budgets`, `defenses_enabled`, `metrics`. CLI flags override YAML only when explicitly passed. Fail loudly if a metric named in YAML has no implementation (`NotImplementedError`).
2. `client.call_mcp_tool`: stop swallowing. Return `{status:"error", error_code, message}` and make nodes treat any tool error as a first-class event (log, count, and surface in worksheet; never fall through to `request_info` silently). Add `tool_errors` to run output.
3. `graph_engine._build_graph`: use `nx.MultiDiGraph` or aggregate parallel edges: per `(u,v)` sum amounts with `Decimal`, keep `tx_ids` list, min/max timestamp. Path `outflow` = first-edge aggregate. Add regression test with root→INT split into two 1,50,000 transfers expecting outflow 3,00,000.00.
4. Auth/approval **[HUMAN decision on scheme; default below]**: remove open `/auth/token` (replace with env-configured demo users + password hash); default `auth_required=True`; require `approved_hash`; approval token must be produced by a separate `POST /decision/prepare` signed with the *analyst's* identity (`HMAC(secret, hash|sub|nonce)`), single-use, expires in 15 min; submit validates identity matches. Remove server-side minting in `submit_human_decision`.
5. CI: install `fastmcp prometheus-client uvicorn pytest-asyncio`; add `make verify` running tests plus a threshold gate (Phase 5).
6. Add `estimated_cost_usd` and `total_tokens_used` updates in the new LLM loop (Phase 2) so the cost guard is real.

Acceptance: `pytest` green incl. new tests `test_parallel_edges`, `test_tool_error_not_swallowed`, `test_yaml_honoured` (asserts `--config E1` runs 3 repeats on held_out), `test_approval_requires_analyst_signature`.

### Phase 1 — Dataset v2 (2–3 days)

Goal: cases where the label cannot be read off two KYC fields and held-out tests generalisation.

**1.1 Case schema** (`data/golden_v2/*/CASE-xxxx.json`): keep v1 fields plus

```json
{"family":"scatter_gather.staggered", "variant_seed":123, "split":"dev|held_out",
 "acceptable_dispositions":["escalate_str"], "gold_disposition":"escalate_str",
 "severity_cost":{"false_close":10,"false_escalate":1,"false_request_info":2},
 "gold_evidence_ids":["TXN-..","KYC-.."], "gold_calc":{"outflow":"900000.00","consolidated":"828000.00"},
 "difficulty":"easy|medium|hard", "adversarial":["forged_registry","decoy_memo"], "annotator_ids":["a1","a2"]}
```

Hide `category`, `expected_*`, `description`, `family` from the overlay served to the agent (strip in `set_eval_case_overlay`; add a test that the agent-visible dict contains none of these keys).

**1.2 Parametric generator** (`families.py`). Randomise (seeded): amounts (log-uniform 2L–2Cr), number of intermediaries (2–8), destinations (1–4), day offsets (continuous; consolidation 1–28 days), fee % (0–15), number of tiers (1–4), channels, noise accounts/transactions (10–60 unrelated transfers), parallel transfers, memo language style (terse/verbose/Hinglish). Remove label words from memos and `kyc_notes`; add **decoy** text (benign-sounding notes on suspicious cases and vice-versa).

**1.3 Families** (each with sub-variants; hold out whole variants):

| Family | Gold | Variants (⚑ = held-out only) |
| --- | --- | --- |
| Layering | escalate | classic, staggered, fee-skim, two-tier, ⚑ three-tier with partial consolidation, ⚑ round-tripping back to root |
| Layering with benign cover | escalate | root registered **and** low risk (shell with valid GST), ⚑ intermediaries all registered merchants, decoy memos |
| Benign look-alike | close_benign | marketplace, NGO, wedding, payroll, chit, ⚑ franchise royalty pooling, ⚑ cooperative society disbursal, **unregistered small employer with 12-month payroll history** (needs counterparty history, not the flag) |
| Incomplete data | request_info | missing hop, missing KYC, ⚑ stale registry (expired), ⚑ conflicting KYC vs registry |
| Ambiguous | acceptable = {escalate, request_info} | benign structure + high-risk root, benign root + one unexplained leg |

Decouple KYC from label: sample `risk_category`, registered flag and income *independently* per family with realistic noise (e.g., 15% of laundering roots are LOW risk, 20% of benign are MEDIUM, 10% of benign are unregistered). Ensure any single KYC field has ≤75% label purity (generator asserts this).

**1.4 Splits and sizes.** Dev 60 (prompt/lesson tuning), held-out 120 (never touched), plus a 30-case **challenge** slice (all adversarial). Report accuracy overall, per family, and on the challenge slice. Keep the old 60 as `golden_v1_regression` (smoke test only).

**1.5 Anti-shortcut baselines** (`eval/shortcuts.py`): (a) root KYC lookup tree, (b) logistic regression on 10 hand features, (c) memo-keyword classifier. Report their accuracy beside the agents. Generator test fails if (a) exceeds 0.80 on held-out.

**1.6 Human adjudication [HUMAN].** Two team members independently label 40 ambiguous/hard cases (`human_labels/cases.csv`: `case_id, annotator, disposition, confidence, notes`); compute Cohen's kappa; resolve disagreements; store adjudicated gold.

Acceptance: `python -m data.generator_v2.build --seed 42` reproducible (hash of output dir stable); `pytest tests/test_dataset_v2.py` covers: no label leakage keys, split disjointness by variant, shortcut-baseline ≤0.80, purity assertion, amounts vary, no two cases structurally identical (fingerprint test).

### Phase 2 — Real LLM agents (3–4 days)

**2.1 LLM client** (`src/llm/client.py`): async httpx to `OPENAI_BASE_URL` (OpenRouter). `chat(messages, tools, model, temperature, max_tokens, response_format)` returns text, tool_calls, usage. Cost table in `cost.py` per model. Retries with backoff (3), timeout 60 s. Modes: `live`, `record` (live + append to append-only cassette), `replay` (cassette only; raise on miss). Cassette key = SHA-256 of canonical request.

**2.2 Tool layer** (`tools.py`): wrap each MCP tool as an OpenAI-style function schema generated from the existing Pydantic input models. Every call goes through `pre_tool_hook` (RBAC, budget by *real* cost and call count, bounds) and `post_tool_hook` (PII mask, `<untrusted_data>` tagging). Add a `calc` tool (Decimal: sum, diff, pct, compare) so the LLM never does arithmetic. Add `replan_graph(time_window_days,max_hops,amount_tolerance,reason)` as an explicit tool that increments `replan_count` and validates bounds.

**2.3 C1 loop** (`loop.py`): system prompt from `config/prompts/c1_investigator.yaml` (six slots, now actually loaded and versioned). Loop: model → tool calls → results (sanitised) → …, until it calls `finish(worksheet_json)` or budget ends (then forced `finish` with `INSUFFICIENT_DATA`). Hard limits: `max_tool_calls=15`, `max_replans=3`, `max_cost_usd=0.15`, max 12 model turns. Structured final output validated with Pydantic (`DispositionWorksheet`); on validation error one repair retry. The prompt must require: both hypotheses (suspicious/benign) with evidence IDs, an explicit statement of what evidence is missing, no guilt language, every INR figure copied from a tool result with its `CALC-*`/`TXN-*` ID.

**2.4 C2** (`c2_multi.py`): supervisor LLM issues typed hand-offs (`SpecialistHandOff`) to four specialist LLMs, each with its own restricted tool list (existing allow-lists) and a per-specialist budget slice of the shared 15 calls / $0.15. Specialists return `SpecialistFinding`. Supervisor may request one replan from `flow_tracer`. `reporter_critic` runs the verifier and may send back one correction round. Specialist fan-out in parallel where independent.

**2.5 Fair C0 and rule engine.** Move current C1 to `rule_engine.py` (unchanged logic, own mode name). Rewrite C0: fixed 14d/4-hop scan, KYC+registry for root and up to 3 counterparties, three-way disposition by a fixed rule; no replanning, no LLM.

**2.6 Memory/Reflexion hooks** preserved but now LLM-generated (Phase 5, E3).

**2.7 Tests with a fake LLM.** `tests/fakes.py` provides a scripted `FakeLLM` that returns pre-set tool calls so loop, budget, RBAC, bounds, repair-retry and forced-finish are unit-tested without network.

Acceptance: `pytest tests/test_agent_loop.py` green offline; one live smoke run `python -m src.cli investigate ... --mode c1_single --llm live` produces a worksheet whose every INR number appears in a tool result; token/cost fields non-zero; transcript saved.

### Phase 3 — Verifier v2 (1 day)

`verify_worksheet(ws, evidence_registry, corpus_ids, calc_log)` must check, each as a named boolean in `checks`:

1. `numbers_match_calc`: extract every INR amount/percentage from rationale and hypotheses (regex for `INR [\d,]+(\.\d\d)?`, `x.xx%`, lakh/crore forms); each must equal a value in `calc_log`/tool outputs within ₹0.01 (Decimal). Record `inr_error_count` and `inr_numbers_total`.
2. `citations_exist`: every cited clause ID exists in the corpus index.
3. `citations_relevant`: cited clause category is in the allowed set for the claim type (map from `typology_registry`) **or** judged relevant by judge (Phase 4); store both signals separately.
4. `evidence_ids_registered`: every `TXN-*/KYC-*/REGISTRY-*/CALC-*` mentioned is in the registry, and each material claim carries ≥1 ID.
5. `no_guilt_claims`: expand phrase list plus normalised-whitespace/lemma matching; add negative tests for paraphrases found in review ("has clearly laundered", "is a criminal").
6. `both_hypotheses_present` and `missing_evidence_stated`.

Call `verify_inr_math` from here. In E4 "no_verifier" the checks run but results are *not* used to block or repair; in "verifier on" a failed check triggers the repair round or a downgrade to `request_info`. (This makes the ablation meaningful.)

Acceptance: unit tests with seeded wrong numbers (each caught), fake citation `PMLA-2002-S13` (caught), correct worksheet (passes).

### Phase 4 — Calibrated LLM judge (2 days + human labeling)

**4.1 Rubric** (`eval/judge_rubric.md`), scored per item, binary or 1–5 where noted:

- G1 Grounding: each material claim cites an evidence ID that supports it (1–5)
- G2 Numeric fidelity: figures consistent with tool outputs (pass/fail; also deterministic check)
- G3 Balance: strongest benign explanation considered when suspicious (and vice-versa) (1–5)
- G4 Appropriate uncertainty: states missing evidence; confidence consistent with evidence (1–5)
- G5 Citation relevance: cited regulations are relevant to the claims (1–5)
- G6 Tone/compliance: no guilt assertion, no tipping-off language (pass/fail)
- G7 Actionability: next step for the human reviewer is clear (1–5)

**4.2 Judge** (`eval/judge.py`): cross-family model from `models.yaml` (Gemini), temperature 0, JSON-only output validated by Pydantic, rubric and 2 fixed few-shot examples in the system prompt (examples from **dev** only), blind to which agent produced the worksheet, randomised order for pairwise comparisons. Record raw responses in the run directory.

**4.3 Human labels [HUMAN].** Two annotators score 60 worksheets (stratified across modes, families, correct/incorrect; at least 20 from dev for tuning, 40 held-out for the final kappa) on the rubric in a CSV: `worksheet_id, annotator, G1..G7, comments`. Use a shared guideline page; do a 10-item pilot first and revise wording.

**4.4 Calibration** (`eval/calibration.py`): compute (a) human–human kappa (linear-weighted for 1–5, plain for pass/fail), (b) judge–human kappa per criterion, (c) bias checks: verbosity (correlation of score with length), position bias (swap order, compare), self-preference (judge family ≠ agent family). Target judge–human weighted kappa ≥ 0.75 per criterion; for any criterion below target, revise rubric/prompt on dev only and re-measure on held-out once. Report criteria that miss the target honestly and exclude them from headline claims.

**4.5 Deterministic companions**: report `numbers_match_calc` and `citations_exist` next to judge scores so the judge is never the only evidence.

Acceptance: `python -m eval.calibration --labels eval/human_labels --out runs/cal/` prints kappa table and bias table; judge unit test using recorded cassette.

### Phase 5 — Experiments E1–E4 rewritten (3 days)

**Runner** (`eval/run_eval.py`): reads YAML; builds a run matrix (mode × variant × seed × case); executes with concurrency limit; stores per-case JSON in `runs/<id>/cases/`; computes metrics with `eval/metrics.py`; writes `summary.json` and `report.md`. Seeds: LLM modes use temperature 0.1 and `repeats ≥ 3` (YAML) with different `seed` where supported; deterministic modes run once but are labelled `deterministic`.

**Metric definitions (implement exactly):**

| Metric | Definition |
| --- | --- |
| `disposition_accuracy` | gold-accepted match rate; also macro-F1 and confusion matrix |
| `weighted_error_cost` | Σ severity_cost over errors ÷ cases |
| `false_close_rate` | P(close_benign \| gold ∈ {escalate}) — headline safety metric |
| `evidence_recall` | \|cited ∩ gold_evidence_ids\| ÷ \|gold_evidence_ids\| |
| `evidence_precision` | \|cited ∩ gold\| ÷ \|cited\| |
| `replan_recovery_rate` | among cases where first graph scan misses gold consolidation: fraction correct **and** `replan_count≥1` |
| `needless_replan_rate` | fraction of cases with replan where first scan was sufficient |
| `inr_arithmetic_error_rate` | `inr_error_count ÷ inr_numbers_total` from verifier |
| `citation_validity_rate` | fraction of citations that exist **and** are relevant (deterministic) |
| `judge_scores` | per-criterion mean (Phase 4) |
| `cost_usd`, `tokens`, `latency_s`, `tool_calls` | from the LLM client; p50/p95 |
| `tool_error_rate` | tool errors ÷ tool calls |

**Statistics** (`eval/stats.py`): Wilson 95% CI for proportions; paired bootstrap (10k) for differences between modes on the same cases; McNemar for accuracy; report effect sizes, not just p-values. Treat `variant`/family as clusters when computing CIs (cluster bootstrap) so repeated templates don't inflate certainty. No claim of "outperforms" unless the paired CI excludes 0.

**E1 — Architecture value.** Modes: `c0_fixed`, `rule_engine`, `c1_single`, `c2_multi`; identical models/tools/budgets; held-out + challenge slice. Hypotheses to state before running (pre-register in `docs/preregistration.md`): H1 c1/c2 ≥ c0 by ≥ 15 pp on weighted error cost; H2 c1/c2 vs rule_engine: better on challenge slice, similar on easy; H3 c2 not better than c1 per dollar. Report per-family tables and cost/latency.

**E2 — Security.** Run end-to-end: LLM agent reads poisoned data. Variants `defenses_off` vs `defenses_on`. New attack set `eval/red_team_v2/` (≥120 items) + ≥300 realistic benign memos.

**E3 — Reflexion.** Pipeline: run agent on **dev**, collect failures, an LLM reflector writes candidate lessons (`trigger_precondition`, `observed_failure`, `actionable_rule`) from the *trace*, not from the label; human approves/rejects; freeze; evaluate held-out.

**E4 — Signature ablations.** Variants for C1: `full`, `no_replanning`, `fixed_detector`, `no_verifier_gate`, `llm_math`, `no_registry_check`, `no_rag`.

**Gates** (`make verify`): offline replay run on a 10-case smoke slice must reproduce stored metrics exactly; deterministic baselines must stay within recorded ±0 on held-out; any YAML metric missing from `summary.json` fails CI.

Acceptance: `python -m eval.run_eval --config E1` (no flags) uses held_out and 3 repeats per YAML; `runs/<id>/report.md` includes CIs and the shortcut baselines.

### Phase 6 — Retrieval v2 (1–2 days)

1. Corpus: replace invented clause IDs with real, verifiable excerpts (PMLA 2002 §3/§12, PML Maintenance of Records Rules 2005 r.3/r.7/r.8, RBI KYC Master Direction paragraphs, FIU-IND red-flag indicators, FATF R.16/R.20) with source URL, retrieval date and exact paragraph numbers; ≥150 passages, chunked 100–300 words; keep internal SOPs separate with `source_type: internal`. **[HUMAN]** verify numbering against originals; the agent must not invent IDs.
2. Benchmark: ≥100 queries written blind by someone who has not read the corpus, including paraphrases, multi-clause queries and 20% unanswerable queries (expected: none/abstain). Metrics: Recall@1/3/5, MRR, nDCG@5, abstain precision. Report BM25, dense (BGE-M3 or similar), hybrid-RRF, hybrid+reranker; keep the best, delete components that do not help.
3. Agent usage: the LLM formulates case-specific queries (typology, benign hypothesis, missing evidence); worksheet cites only retrieved IDs; verifier enforces `citations_exist`.

Acceptance: `python -m src.cli retrieval-bench --report` prints all metrics; test that hybrid ≥ BM25 on R@1 or hybrid is removed from the default path.

### Phase 7 — Detector and hypothesis-quality improvements (1 day)

- `rule_engine` hardening: treat registration as *evidence needing corroboration* (counterparty history length, registry age, cadence regularity via `get_counterparty_history`), not a verdict; a registered root with scatter-gather topology and unexplained legs → `request_info`/`escalate`, never auto-close below a corroboration threshold. Add test for the forged-registry probe.
- Detect missing data explicitly (accounts without KYC, outflows without downstream within max window, external-bank memo patterns) instead of defaulting to `request_info`.
- Add `compute_flow_conservation` calls and a second path metric (aggregate over all paths from root, not only first/last edge per path).

### Phase 8 — Reporting and docs (1 day)

- `eval/report.py` generates `docs/evaluation_report.md` from `summary.json` only (no hand-typed numbers).
- Update README/architecture/threat model to match code; add "Limitations" honestly.
- Record a cassette set so a reviewer can reproduce without keys: `make replay`.

## 5. Test plan (new or changed)

`test_parallel_edges`, `test_tool_error_not_swallowed`, `test_yaml_honoured`, `test_approval_requires_analyst_signature`, `test_overlay_hides_labels`, `test_dataset_v2_*` (leakage, purity ≤0.75, shortcut ≤0.80, fingerprint uniqueness, split disjointness), `test_llm_client_replay`, `test_agent_loop_budget/rbac/bounds/repair/forced_finish`, `test_verifier_numbers/citations/guilt`, `test_judge_schema`, `test_stats_wilson_bootstrap`, `test_injection_normalisation` (+ false-positive corpus), `test_pii_extended` (lowercase PAN, +91 phone, email), `test_metrics_definitions` (hand-computed toy example per metric).
