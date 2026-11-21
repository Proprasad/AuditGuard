# AuditGuard — Testing, Validation & Empirical Evaluation Report

**Execution Environment:** Windows (`win32`), Python `3.10.8`, SQLite Operational DB (`data/auditguard.db`)  
**Dataset:** 60-Case Synthetic Golden Dataset (`seed=42`: 20 dev in `data/synthetic/dev/`, 40 isolated held-out in `eval/held_out/`) + 32-Clause Indian AML Corpus + 35-Query Retrieval Benchmark + 32-Case Red-Team Suite.

---

## 1. Automated Unit, Integration & Milestone Test Suite (`pytest tests/ -v`)

**Result:** **26 / 26 Passed (100%)**

| Test Module | Count | Verified Capabilities & Milestones |
|-------------|-------|------------------------------------|
| [test_api.py](../tests/test_api.py) | 6 | Embedded Analyst UI (`/`), `/health`, `/metrics`, HS256 JWT issue & `401` forged-token rejection, `422` prompt-injection guardrail, `edit -> 403 stale hash -> 200 fresh hash -> 409 replay`, physical & DB held-out isolation, `DELETE /api/v1/memory/{id}` |
| [test_graph_engine.py](../tests/test_graph_engine.py) | 3 | **Milestone T1:** Staggered Day-11 recovery (`7d -> 14d`), exact `8.00%` (`INR 72,000.00`) Python `Decimal` conservation math, `POLICY_BOUNDS_EXCEEDED` on `max_hops=6` |
| [test_mcp_servers.py](../tests/test_mcp_servers.py) | 4 | **Milestone T2:** Happy-path & structured error contracts across `compliance-kb`, `graph-engine`, `bank-records`, and `case-actions` |
| [test_checkpoint_resume.py](../tests/test_checkpoint_resume.py) | 1 | **Milestone T3 (FR-6):** Simulated crash after `gather_evidence` node, SQLite checkpoint persistence verification, and exact crash recovery via `POST /api/v1/investigations/{thread_id}/resume` |
| [test_approval_invalidation.py](../tests/test_approval_invalidation.py) | 2 | **Milestone T4:** Editing 1 rupee invalidates HMAC/SHA-256 approval token; deterministic verifier blocks prohibited guilt declarations |
| [test_security_hooks.py](../tests/test_security_hooks.py) | 5 | **Milestone T5:** Memo prompt-injection block, PII scrubbing + `<untrusted_data>` wrapping, RBAC denial (`flow_tracer` -> `case-actions`), 15-call budget cap, output guilt-claim filter |
| [test_compliance_kb.py](../tests/test_compliance_kb.py) | 1 | **35-Query Hybrid RAG Benchmark:** Verifies `Recall@5 >= 90%` (`100.0%` achieved) |
| [test_red_team_suite.py](../tests/test_red_team_suite.py) | 1 | **32-Case Red-Team Suite:** Verifies `100.0%` attack block rate & `0.0%` false-block rate |
| [test_memory_policy.py](../tests/test_memory_policy.py) | 3 | Rolling 12-message context trimmer, human-approval-gated episode writes, `forget_customer()`, dev-only Reflexion & playbook freeze |

---

## 2. Experiment E1 — Architecture Value (`C0` vs. `C1` vs. `C2` on 20 Dev Cases)

| Architecture | Disposition Accuracy | Replan Recovery Rate | Avg Tool Calls | Avg Local Latency | Key Observation |
|--------------|----------------------|----------------------|----------------|-------------------|-----------------|
| **`c0_fixed`** (Fixed 7d/3-hop Baseline) | **30.0%** (6/20) | 50.0% | 5.0 | 83.7 ms | Misses staggered Day-11 & fee-skimming legs; misclassifies benign marketplaces/NGOs/payroll due to lack of commercial registry verification |
| **`c1_single`** (Single-Agent + Bounded Replan) | **100.0%** (20/20) | **100.0%** | 12.7 | 106.6 ms | Recovers staggered & fee-skimming networks via bounded replanning; accurately clears GST/80G/MCA/Chit benign look-alikes |
| **`c2_multi`** (Supervisor + 4 RBAC Specialists) | **100.0%** (20/20) | **100.0%** | 12.6 | **63.6 ms** | Matches C1 accuracy while enforcing strict per-specialist least-privilege RBAC and parallel specialist fan-out |

> Exceeds Blueprint Success Criterion #1 (`C1` & `C2` outperform `C0` by `+70.0` percentage points vs. `>= 20` pp target, and `100.0%` replan recovery vs. `>= 75%` target).

---

## 3. Experiment E2 — Security Defenses & 32-Case Red-Team Suite

| Configuration | Red-Team Cases | Blocked | Attack Block Rate | Attack Success Rate (ASR) | Clean Cases False-Block Rate (FBR) |
|---------------|----------------|---------|-------------------|---------------------------|------------------------------------|
| **Defenses OFF** | 32 | 0 | 0.0% | 100.0% | 0.0% |
| **Defenses ON** | 32 | **32** | **100.0%** | **0.0%** | **0.0%** (0/20) |

> Exceeds NFR-3 (`>= 90%` attack block rate, `<= 5%` false-block rate, `0` unauthorized write actions).

---

## 4. Experiment E4 — Signature Replanning Ablation

| Variant | Disposition Accuracy | Staggered / Fee-Skim Recovery | Finding |
|---------|----------------------|-------------------------------|---------|
| **`c1_full_system`** (Replanning ON + Verifier ON) | **100.0%** (20/20) | **100.0%** | Full bounded parameter reconfiguration (`7d/3h -> 15d/4h -> 30d/5h`) recovers delayed/skimmed legs |
| **`c1_no_replanning`** (Replanning OFF) | **80.0%** (16/20) | **50.0%** | Drops `-20.0` pp — fails all `staggered_timing` and `fee_skimming` cases outside initial 7-day window |

---

## 5. Known Limitations & Future Improvements

1. **Optional Live LLM Reasoning:** Out of the box, AuditGuard uses deterministic evidence-grounded reasoning locally when `OPENAI_API_KEY` is unset (`sk-placeholder`), ensuring zero API cost and 100% offline reproducibility. Supplying a valid OpenRouter/OpenAI key in `.env` with `pip install -e ".[llm]"` enables generative LLM narrative synthesis.
2. **Dense Vector Backend:** Locally, `compliance-kb` uses Okapi BM25 + Subword/Concept TF-IDF cosine vectors + RRF (`100%` Recall@5 on the 35-query benchmark) without requiring multi-gigabyte PyTorch downloads. Running via Docker Compose connects Qdrant + `BAAI/bge-m3` embeddings.
3. **Single Primary Typology Scope (Phase 1):** Covers scatter-gather networks and 5 benign look-alike categories; additional typologies (structuring, fan-in mule rings) plug into [typology_registry.py](../src/typology_registry.py) in Phase 2.
