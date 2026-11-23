# AuditGuard — Testing, Validation & Empirical Evaluation Report

**Execution Environment:** Windows (`win32`), Python `3.10.8`, LangGraph `1.2.24`, FastMCP `4.1.8`, Isolated Temporary Evaluation DB (`prepare_isolated_eval_db()`; operational `data/auditguard.db` verified at `0` held-out rows across all 17 tables).  
**Datasets & Suites:** 60-Case Synthetic Dataset (`seed=42`: 20 dev in `data/synthetic/dev/`, 40 unseen held-out in `eval/held_out/`), 32-Clause Indian AML Corpus, 35-Query Dev + 28-Query Independent Plain-English NL Retrieval Benchmarks, and 32-Attack Red-Team Suite.

---

## 1. Static Analysis & Automated Test Suite

- **Linter (`ruff check src/ eval/ tests/ --select E,F,B,S,DTZ,BLE,T20,C901`):** `All checks passed!` (`0` errors; McCabe cyclomatic complexity `<= 12` across `src/`).
- **Type Checker (`mypy src/`):** `Success: no issues found in 61 source files`.
- **Automated Test Suite (`pytest tests/ -q`):** **`92 passed`** (`0` failed, `0` skipped), with every test isolated on `tmp_path / "test_auditguard.db"` and a session-level `mtime` assertion guarding `data/auditguard.db`.

| Test Module | Tests | Verified Capabilities |
|---|---:|---|
| [test_adversarial_step6.py](../tests/test_adversarial_step6.py) | 23 | All **18 Audit §5 adversarial scenarios**: bare `/decision {}` (`422`), `reviewer_id` spoofing (`422` + JWT `sub` check), read-only post-commit re-stream, concurrent `asyncio.gather` double-approval (`[200, 409]`), `</untrusted_data>` XML escaping across all 7 untrusted fields, Unicode/NBSP/homoglyph prompt-injection withholding across `C0`/`C1`/`C2`, guilt-phrase regex families, fabricated citations & broken INR math fail-closed, restricted worksheet edits (`422`), `BudgetLedger` caps (`15` calls, `\$0.15`, `3` replans, `2` critique retries), MCP timeout/empty-row graceful degradation, unknown alert/KYC (`404`/`ACCOUNT_NOT_FOUND`), `MultiDiGraph` 5 parallel edges + exact `Decimal`, full-DB 0-leakage scan, `/config/llm` newline `.env` injection (`422`) & RBAC (`403`), full-table Right-to-Erasure + Loki PII redaction, `respx` OpenRouter HTTP malformed JSON / ungrounded amount self-correction / USD cost accrual, and spawned FastMCP HTTP server + timeout |
| [test_core_step2.py](../tests/test_core_step2.py) | 14 | Pure `src/core/` (`Decimal` quantization, `0.10 + 0.20 == Decimal("0.30")`, `nx.MultiDiGraph` parallel transfers, deterministic `PATH-*`/`CALC-*` SHA-256 IDs, canonical JSON hash, `PolicyConfig` + `BudgetLedger`, fail-fast startup validator) |
| [test_security_step3.py](../tests/test_security_step3.py) | 9 | Auth enforcement (`401`), single-use HMAC replay (`409`), wrong hash (`403`), login sliding-window rate limiting (`429`), XML tag escaping, Unicode-obfuscated injection detection, admin-only LLM config |
| [test_api.py](../tests/test_api.py) | 9 | Workbench static assets, `/health`, `/metrics`, PBKDF2-HMAC-SHA256 login & server-assigned roles, navigation endpoints, `edit -> 403 stale token -> 200 fresh token -> 409 replay`, `senior_reviewer` memory erasure |
| [test_graph_step5.py](../tests/test_graph_step5.py) | 7 | Compiled LangGraph `StateGraph` topology (zero orphans, guaranteed `END`), deduplicating state reducers, `recursion_limit`, evidence-weighted rubric (requiring `multi_hop_path` for `>= 0.70` escalation), `interrupt()` pause & `Command(resume=...)` release, C2 4-specialist execution, and LLM registry grounding |
| [test_mcp_servers.py](../tests/test_mcp_servers.py) & [test_mcp_http_transport.py](../tests/test_mcp_http_transport.py) | 8 | Real `fastmcp.Client` in-memory and spawned streamable-HTTP contracts, schema validation errors (`MCP_TOOL_ERROR`), unreachable server (`MCP_UNAVAILABLE`), `POLICY_BOUNDS_EXCEEDED`, `INVALID_ALERT_ID`, `ACCOUNT_NOT_FOUND` |
| [test_security_hooks.py](../tests/test_security_hooks.py), [test_frontend_integrity.py](../tests/test_frontend_integrity.py), [test_approval_invalidation.py](../tests/test_approval_invalidation.py), [test_memory_policy.py](../tests/test_memory_policy.py), [test_graph_engine.py](../tests/test_graph_engine.py), [test_checkpoint_resume.py](../tests/test_checkpoint_resume.py), [test_compliance_kb.py](../tests/test_compliance_kb.py), [test_red_team_suite.py](../tests/test_red_team_suite.py), [test_verification_failed_event.py](../tests/test_verification_failed_event.py) | 22 | Pre/post tool hooks, DOM-ID & live SSE workbench contract, out-of-band DB tamper detection (`TOKEN_INVALIDATED_BY_EDIT`), pair-aware message trimming, mid-run crash recovery (`/resume`), retrieval benchmark, red-team suite, and fail-closed `verification_failed` SSE terminal state |

---

## 2. Regulatory Retrieval Benchmarks (`python -m src.cli retrieval-bench`)

All clause-ID tokens (`rf023`, `sopsg001`, etc.) were removed from `DOMAIN_CONCEPTS` in [compliance_kb.py](../src/mcp_servers/compliance_kb.py); expansion uses pure English domain synonyms plus character 3/4-grams fused with Okapi BM25 via RRF (`k=60`).

| Benchmark Split | Queries | BM25-Only Recall@5 | BM25-Only MRR | Hybrid RRF+Rerank Recall@5 | Hybrid RRF+Rerank MRR | Recall@5 Delta |
|---|---:|---:|---:|---:|---:|---:|
| **Dev Benchmark** ([retrieval_bench.jsonl](../eval/retrieval_bench.jsonl)) | 35 | 100.0% (35/35) | 1.000 | **100.0%** (35/35) | 0.917 | +0.0 pp |
| **Independent Plain-English NL Held-Out** ([retrieval_held_out_nl.jsonl](../eval/retrieval_held_out_nl.jsonl)) | 28 | 89.3% (25/28) | 0.746 | **96.4%** (27/28) | **0.748** | **+7.1 pp** |

---

## 3. Experiment E1 — Architecture Value (`C0` vs. `C1` vs. `C2`)

### 3A. Offline Evidence-Weighted Rubric Mode (`LLM_ENABLED=false`, `repeats=1`, Isolated Temp DB)

Confidences in offline mode are computed from `EvidenceFeatures` using weights in [config/models.yaml](../config/models.yaml) (`scoring:`), requiring a reconstructed multi-hop path (`multi_hop_path=True`) before suspicious confidence can reach `disposition_threshold = 0.70`.

| Split | Mode | Accuracy | Replan Recovery | Avg Tool Calls | Avg Replans | Avg Latency | Deterministically Verified |
|---|---|---:|---:|---:|---:|---:|---:|
| **Dev (20 cases)** | `c0_fixed` | 30.0% (6/20) | 50.0% | 5.00 | 0.00 | 343.3 ms | 100.0% |
| **Dev (20 cases)** | `c1_single` | **90.0%** (18/20) | **100.0%** | 13.10 | 0.40 | 490.6 ms | 100.0% |
| **Dev (20 cases)** | `c2_multi` | **90.0%** (18/20) | **100.0%** | 13.10 | 0.40 | **482.8 ms** | 100.0% |
| **Unseen Held-Out (40 cases)** | `c0_fixed` | 30.0% (12/40) | 50.0% | 5.00 | 0.00 | 332.6 ms | 100.0% |
| **Unseen Held-Out (40 cases)** | `c1_single` | **90.0%** (36/40) | **100.0%** | 13.10 | 0.40 | 585.4 ms | 100.0% |
| **Unseen Held-Out (40 cases)** | `c2_multi` | **90.0%** (36/40) | **100.0%** | 13.10 | 0.40 | **564.4 ms** | 100.0% |

*Note on the 10% (`2/20` dev, `4/40` held-out) conservative `request_info` cases:* On `marketplace_payout` alerts, multi-hop flagged dispersal (`+0.25`) competes against active commercial registration and low KYC risk (`-0.40`), yielding `benign = 0.65` (just below `disposition_threshold = 0.70`) and conservatively routing to `request_info` for human review rather than overfitting rubric weights to the synthetic generator.

### 3B. Live OpenRouter LLM Evaluation (`openai/gpt-5-mini`, `LLM_ENABLED=true`, 6 Dev Cases `CASE-0001..0014`)

| Mode | Accuracy (6 Cases) | Replan Recovery | Avg Tool Calls | Avg Replans | Avg Tokens / Case | Avg Cost / Case (USD) | Avg Wall Latency | Verified Rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `c0_fixed` (Deterministic Baseline) | 33.3% (2/6) | 0.0% | 5.00 | 0.00 | 0 | \$0.00000 | 746.3 ms | 100.0% |
| `c1_single` (Live `gpt-5-mini`) | 33.3% (2/6) | 25.0% | 14.67 | 0.83 | 11,880 | \$0.01116 | 64,356.7 ms | **100.0%** |
| `c2_multi` (Live `gpt-5-mini` Supervisor + 4 Specialists) | **50.0%** (3/6) | **75.0%** | 14.00 | 0.67 | **11,070** | **\$0.01053** | **57,425.2 ms** | **100.0%** |

*Measured Live LLM Findings:* Live `gpt-5-mini` assigned `0.65–0.68` suspicious confidence on several borderline cases (routing them conservatively to `request_info` under `disposition_threshold = 0.70` with zero false `close_benign` clearances). `c2_multi` achieved higher replan recovery (`75.0%` vs. `25.0%`), lower average token consumption (`11,070` vs. `11,880`, `0.93x` because fewer extra replan passes were needed), and `10.8%` lower latency (`57.4s` vs. `64.4s`), while staying at `~7%` of the `\$0.15/case` budget cap and passing deterministic verification on `100.0%` of cases.

---

## 4. Experiment E2 — Security Defenses & 32-Attack Red-Team Suite

`Defenses OFF` executes the 32 attack payloads with `apply_input_guardrails`, `pre_tool_hook`, `apply_output_guardrails`, and `mask_pii` disabled against the real MCP servers.

| Configuration | Attacks | Blocked | Attack Block Rate | Attack Success Rate (ASR) | Clean-Case False-Block Rate |
|---|---:|---:|---:|---:|---:|
| **Defenses OFF** (Hooks & Guardrails Disabled) | 32 | 7 | 21.9% | 78.1% (25/32) | 0.0% |
| **Defenses ON** (Full Guardrail + Hook Stack) | 32 | **31** | **96.9%** | **3.1%** (1/32) | **0.0%** (0/20) |

*Note:* The `7/32` (`21.9%`) blocked under `Defenses OFF` reflect intrinsic server-side defense-in-depth (`4` out-of-bounds parameter rejections inside `graph-engine` + `3` `submit_case_disposition` HMAC rejections inside `case_repo`). With `Defenses ON`, `31/32` (`96.9%`) are blocked with `0.0%` false blocks on clean dev cases.

---

## 5. Experiment E3 — Frozen Reflexion Playbook Generalization (40 Unseen Held-Out Cases)

Generated strictly from dev-split failures via [scripts/build_frozen_playbook.py](../scripts/build_frozen_playbook.py) (`run_dev_reflexion()` -> `review_lesson()` -> `freeze_playbook()` -> `export_playbook()`), producing `3` approved lessons (`LES-22267B`, `LES-6B2801`, `LES-9ADC37`) and `1` human-rejected overfitted lesson (`LES-REJ-001`), verified identical between `config/reflexion_playbook.json` and `data/auditguard.db` (`playbook_frozen = true`).

| Configuration (40 Unseen Held-Out Cases) | Accuracy | Replan Recovery | Avg Tool Calls | Avg Replans | Avg Latency |
|---|---:|---:|---:|---:|---:|
| **Single-Pass (`replanning=False`, Playbook OFF)** | 70.0% (28/40) | 50.0% | 12.30 | 0.00 | 524.5 ms |
| **Single-Pass (`replanning=False`, Frozen Playbook ON)** | **90.0%** (36/40, **+20.0 pp**) | **100.0%** | 12.50 | 0.00 | **423.0 ms** |
| **Full Multi-Pass (`replanning=True`, Playbook OFF)** | 90.0% (36/40) | 100.0% | 13.10 | 0.40 | 499.9 ms |
| **Full Multi-Pass (`replanning=True`, Frozen Playbook ON)** | **90.0%** (36/40) | **100.0%** | **12.60 (-0.50)** | **0.10 (-75%)** | **482.0 ms** |

---

## 6. Experiment E4 — Signature Replanning Ablation

| Split | Variant | Accuracy | Replan Recovery | Avg Tool Calls | Avg Replans | Avg Latency |
|---|---|---:|---:|---:|---:|---:|
| **Dev (20 cases)** | `c1_full_system` (Replanning ON + Verifier ON) | **90.0%** (18/20) | **100.0%** | 13.10 | 0.40 | 626.3 ms |
| **Dev (20 cases)** | `c1_no_replanning` (Replanning OFF) | 70.0% (14/20, **-20.0 pp**) | 50.0% | 12.30 | 0.00 | 434.7 ms |
| **Held-Out (40 cases)** | `c1_full_system` (Replanning ON + Verifier ON) | **90.0%** (36/40) | **100.0%** | 13.10 | 0.40 | 590.3 ms |
| **Held-Out (40 cases)** | `c1_no_replanning` (Replanning OFF) | 70.0% (28/40, **-20.0 pp**) | 50.0% | 12.30 | 0.00 | 413.3 ms |
