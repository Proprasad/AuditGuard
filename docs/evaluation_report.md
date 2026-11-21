# AuditGuard — Testing, Validation & Empirical Evaluation Report

**Execution Environment:** Windows (`win32`), Python `3.10.8`, Node `v24.18.0`, SQLite Operational DB (`data/auditguard.db`)  
**Dataset:** 60-Case Synthetic Golden Dataset (`seed=42`: 20 dev in `data/synthetic/dev/`, 40 isolated held-out in `eval/held_out/`) + 32-Clause Indian AML Corpus + 35-Query Retrieval Benchmark + 32-Case Red-Team Suite.

---

## 1. Automated Unit, Integration, Frontend & Milestone Test Suite (`pytest tests/ -v`)

**Result:** **30 / 30 Passed (100%)**

| Test Module | Count | Verified Capabilities & Milestones |
|-------------|-------|------------------------------------|
| [test_api.py](../tests/test_api.py) | 6 | Embedded Analyst UI (`/`), `/health`, `/metrics`, HS256 JWT issue & `401` forged-token rejection, `422` prompt-injection guardrail, `edit -> 403 stale hash -> 200 fresh hash -> 409 replay`, physical & DB held-out isolation, `DELETE /api/v1/memory/{id}` |
| [test_frontend_integrity.py](../tests/test_frontend_integrity.py) | 4 | Static CSS/JS asset serving, workbench endpoints (`/cases`, `/customers`, `/regulations`, `/analytics`, `/config-info`), `Decimal` flow telemetry & topological roles, printable HTML/PDF compliance report export |
| [test_graph_engine.py](../tests/test_graph_engine.py) | 3 | **Milestone T1:** Staggered Day-11 recovery (`7d -> 14d`), exact `8.00%` (`INR 72,000.00`) Python `Decimal` conservation math, `POLICY_BOUNDS_EXCEEDED` on `max_hops=6` |
| [test_mcp_servers.py](../tests/test_mcp_servers.py) | 4 | **Milestone T2:** Happy-path & structured error contracts across `compliance-kb`, `graph-engine`, `bank-records`, and `case-actions` |
| [test_checkpoint_resume.py](../tests/test_checkpoint_resume.py) | 1 | **Milestone T3 (FR-6):** Simulated crash after `gather_evidence` node, SQLite checkpoint persistence verification, and exact crash recovery via `POST /api/v1/investigations/{thread_id}/resume` |
| [test_approval_invalidation.py](../tests/test_approval_invalidation.py) | 2 | **Milestone T4:** Editing 1 rupee invalidates HMAC/SHA-256 approval token; deterministic verifier blocks prohibited guilt declarations |
| [test_security_hooks.py](../tests/test_security_hooks.py) | 5 | **Milestone T5:** Memo prompt-injection block, PII scrubbing + `<untrusted_data>` wrapping, RBAC denial (`flow_tracer` -> `case-actions`), 15-call budget cap, output guilt-claim filter |
| [test_compliance_kb.py](../tests/test_compliance_kb.py) | 1 | **35-Query Hybrid RAG Benchmark:** Verifies `Recall@5 >= 90%` (`100.0%` achieved — 35/35) |
| [test_red_team_suite.py](../tests/test_red_team_suite.py) | 1 | **32-Case Red-Team Suite:** Verifies `100.0%` attack block rate & `0.0%` false-block rate |
| [test_memory_policy.py](../tests/test_memory_policy.py) | 3 | Rolling 12-message context trimmer, human-approval-gated episode writes, `forget_customer()`, dev-only Reflexion & playbook freeze |

---

## 2. Experiment E1 — Architecture Value (`C0` vs. `C1` vs. `C2` on Dev & Unseen Held-Out)

### 2A. 20-Case Dev Split (`data/synthetic/dev/`)

| Architecture | Disposition Accuracy | Replan Recovery Rate | Avg Tool Calls | Avg Local Latency | Key Observation |
|--------------|----------------------|----------------------|----------------|-------------------|-----------------|
| **`c0_fixed`** (Fixed 7d/3-hop Baseline) | **30.0%** (6/20) | 50.0% | 5.0 | 83.7 ms | Misses staggered Day-11 & fee-skimming legs; misclassifies benign marketplaces/NGOs/payroll due to lack of commercial registry verification |
| **`c1_single`** (Single-Agent + Bounded Replan) | **100.0%** (20/20) | **100.0%** | 12.7 | 106.6 ms | Recovers staggered & fee-skimming networks via bounded replanning; accurately clears GST/80G/MCA/Chit benign look-alikes |
| **`c2_multi`** (Supervisor + 4 RBAC Specialists) | **100.0%** (20/20) | **100.0%** | 12.6 | **63.6 ms** | Matches C1 accuracy while enforcing strict per-specialist least-privilege RBAC and parallel specialist fan-out (`asyncio.gather`) |

### 2B. 40-Case Unseen Held-Out Split (`eval/held_out/`)

| Architecture | Disposition Accuracy | Avg Tool Calls | Avg Local Latency |
|--------------|----------------------|----------------|-------------------|
| **`c0_fixed`** | **30.0%** (12/40) | 5.0 | 50.0 ms |
| **`c1_single`** | **100.0%** (40/40) | 12.7 | 114.9 ms |
| **`c2_multi`** | **100.0%** (40/40) | 12.6 | **40.7 ms** |

---

## 3. Experiment E2 — Security Defenses & 32-Case Red-Team Suite

| Configuration | Red-Team Cases | Blocked | Attack Block Rate | Attack Success Rate (ASR) | Clean Cases False-Block Rate (FBR) |
|---------------|----------------|---------|-------------------|---------------------------|------------------------------------|
| **Defenses OFF** | 32 | 0 | 0.0% | 100.0% | 0.0% |
| **Defenses ON** | 32 | **32** | **100.0%** | **0.0%** | **0.0%** (0/20) |

---

## 4. Experiment E3 — Frozen Reflexion Playbook Generalization on 40 Unseen Held-Out Cases

| Variant (Single-Pass Initial Scan) | Unseen Held-Out Accuracy (40 Cases) | Delta |
|------------------------------------|-------------------------------------|-------|
| **Frozen Playbook OFF** (`reflexion_enabled=False`, `replanning_enabled=False`) | **80.0%** (32/40) | Baseline |
| **Frozen Playbook ON** (`reflexion_enabled=True`, `replanning_enabled=False`) | **100.0%** (40/40) | **+20.0 pp** (+8 unseen delayed/fee-skimmed cases recovered on first pass) |

---

## 5. Experiment E4 — Signature Replanning Ablation

| Variant | Disposition Accuracy | Staggered / Fee-Skim Recovery | Finding |
|---------|----------------------|-------------------------------|---------|
| **`c1_full_system`** (Replanning ON + Verifier ON) | **100.0%** (20/20) | **100.0%** | Full bounded parameter reconfiguration (`7d/3h -> 15d/4h -> 30d/5h`) recovers delayed/skimmed legs |
| **`c1_no_replanning`** (Replanning OFF) | **80.0%** (16/20) | **50.0%** | Drops `-20.0` pp — fails all `staggered_timing` and `fee_skimming` cases outside initial 7-day window |
