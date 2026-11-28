# AuditGuard v3 — Reproducible Evaluation Report

> Generated automatically from computed JSON summaries by `eval/report.py` (`make replay` / `make report`). No metrics in this file are hand-typed.

## Artifact Provenance (Zero Hand-Typed Numbers)

Every quantitative value in this report was generated programmatically by `python -m eval.report` from the verified JSON artifacts listed below:

| Artifact | Path | SHA-256 (prefix) |
|---|---|---|
| E1 Deterministic Held-Out (120 + 30 challenge) | `eval/replay_bundle/e1_held_out_det_summary.json` | `88b7b1caadbe9451` |
| E1 Offline Replay Smoke (10 dev, all 4 modes) | `eval/replay_bundle/e1_smoke_summary.json` | `64fce40ffcf97a2e` |
| E2 Red-Team v2 Security Suite | `eval/replay_bundle/e2_security_summary.json` | `1abd2d9d9c514a5b` |
| Retrieval v2 Benchmark (110 queries) | `eval/replay_bundle/retrieval_v2_summary.json` | `8c03f05f23c58c52` |
| Phase 4 Judge Calibration Status | `eval/replay_bundle/calibration_status.json` | `300e12d909b14420` |

## AuditGuard Experiment `E1_HELD_OUT_DET` Report

- **Split:** `held_out` (`n=120` cases)
- **Configured LLM Repeats:** `1` (`llm_mode=offline`)
- **Run ID:** `replay_e1_held_out_det`

### 1. Headline Metrics (Mean ± 95% CI)

| Configuration | Type | Accuracy (95% CI) | Macro-F1 | Weighted Error Cost (95% CI) | False-Close Rate (95% CI) | Evidence Recall | Evidence Precision |
|---|---|---|---:|---|---|---:|---:|
| `c0_fixed` | `deterministic` | 42.5% [34.0%, 51.4%] | 0.368 | 3.2833 [1.6952, 5.1522] | 57.7% [44.2%, 70.1%] | 8.2% | 45.0% |
| `rule_engine` | `deterministic` | 66.7% [57.8%, 74.5%] | 0.640 | 0.6917 [0.4037, 1.0109] | 3.8% [1.1%, 13.0%] | 25.3% | 97.3% |

### 2. Replanning, Verification & Resource Percentiles (`p50` / `p95`)

| Configuration | Replan Recovery | Needless Replan | INR Math Err | Citation Valid | Cost USD (p50 / p95) | Latency s (p50 / p95) | Tool Calls (p50 / p95) | Tool Err Rate |
|---|---:|---:|---:|---:|---|---|---|---:|
| `c0_fixed` | 0.0% | 0.0% | 0.00% | 92.5% | \$0.0000 / \$0.0000 | 0.24s / 0.28s | 12.0 / 12.0 | 0.14% |
| `rule_engine` | 80.3% | 95.5% | 0.99% | 100.0% | \$0.0000 / \$0.0000 | 0.44s / 0.49s | 15.0 / 15.0 | 0.23% |

### 3. Paired Cluster-Bootstrap (10k) & Exact McNemar Comparisons

*Pre-registered rule: no configuration claims `outperforms` unless the paired 95% CI excludes `0`.*

| Pair (`A vs B`) | Acc Diff (95% CI) | Acc Verdict | McNemar p | Error-Cost Diff (95% CI) | Error-Cost Verdict | Cohen's d (Cost) |
|---|---|---|---:|---|---|---:|
| `c0_fixed vs rule_engine` | -0.2417 [-0.4685, -0.0094] | `b_outperforms_a` | 0.0001 | +2.5917 [+1.0797, +4.3158] | `b_outperforms_a` | +0.631 |

### 4. Anti-Shortcut Reference Baselines (`eval/shortcuts.py`)

| Shortcut Baseline | Dev Accuracy | Target Split Accuracy |
|---|---:|---:|
| `hand_features_logreg` | 70.0% | 40.8% |
| `memo_keyword_nb` | 60.0% | 44.2% |
| `root_kyc_tree` | 76.7% | 48.3% |

### 5. Per-Family Breakdown (`disposition_accuracy` / `weighted_error_cost`)

| Family | `c0_fixed` | `rule_engine` |
|---|---:|---:|
| `ambiguous` | 50.0% / 5.00 | 100.0% / 0.00 |
| `benign_lookalike` | 57.9% / 0.84 | 34.2% / 0.97 |
| `incomplete_data` | 91.7% / 0.83 | 100.0% / 0.00 |
| `layering` | 3.3% / 4.60 | 66.7% / 0.93 |
| `layering_benign_cover` | 0.0% / 9.00 | 68.8% / 1.12 |

### 6. Adversarial Challenge Slice (`30` Cases)

| Configuration | Accuracy (95% CI) | Weighted Error Cost (95% CI) | False-Close Rate |
|---|---|---|---|
| `c0_fixed` | 46.7% [30.2%, 63.9%] | 2.9333 [1.2258, 4.6858] | 53.8% |
| `rule_engine` | 70.0% [52.1%, 83.3%] | 0.5000 [0.2333, 0.8065] | 0.0% |
## AuditGuard Experiment `E1` Report

- **Split:** `v2_dev` (`n=10` cases)
- **Configured LLM Repeats:** `1` (`llm_mode=replay`)
- **Run ID:** `replay_e1_smoke`

### 1. Headline Metrics (Mean ± 95% CI)

| Configuration | Type | Accuracy (95% CI) | Macro-F1 | Weighted Error Cost (95% CI) | False-Close Rate (95% CI) | Evidence Recall | Evidence Precision |
|---|---|---|---:|---|---|---:|---:|
| `c0_fixed` | `deterministic` | 30.0% [10.8%, 60.3%] | 0.262 | 3.8000 [0.9091, 7.0000] | 60.0% [23.1%, 88.2%] | 8.9% | 45.0% |
| `c1_single` | `replay` | 30.0% [10.8%, 60.3%] | 0.154 | 1.4000 [0.7273, 2.0000] | 0.0% [0.0%, 43.4%] | 25.2% | 57.9% |
| `c2_multi` | `replay` | 30.0% [10.8%, 60.3%] | 0.232 | 1.4000 [0.7273, 2.0000] | 0.0% [0.0%, 43.4%] | 11.7% | 51.5% |
| `rule_engine` | `deterministic` | 80.0% [49.0%, 94.3%] | 0.785 | 0.4000 [0.0000, 1.0000] | 0.0% [0.0%, 43.4%] | 21.4% | 98.6% |

### 2. Replanning, Verification & Resource Percentiles (`p50` / `p95`)

| Configuration | Replan Recovery | Needless Replan | INR Math Err | Citation Valid | Cost USD (p50 / p95) | Latency s (p50 / p95) | Tool Calls (p50 / p95) | Tool Err Rate |
|---|---:|---:|---:|---:|---|---|---|---:|
| `c0_fixed` | 0.0% | 0.0% | 0.00% | 90.0% | \$0.0000 / \$0.0000 | 0.27s / 0.98s | 12.0 / 12.0 | 0.00% |
| `c1_single` | 20.0% | 0.0% | 2.90% | 40.0% | \$0.0259 / \$0.0407 | 0.33s / 0.38s | 15.0 / 15.0 | 13.77% |
| `c2_multi` | 20.0% | 100.0% | 0.00% | 100.0% | \$0.0464 / \$0.0517 | 0.59s / 0.67s | 14.5 / 15.0 | 31.47% |
| `rule_engine` | 80.0% | 80.0% | 0.00% | 100.0% | \$0.0000 / \$0.0000 | 0.45s / 0.46s | 15.0 / 15.0 | 0.00% |

### 3. Paired Cluster-Bootstrap (10k) & Exact McNemar Comparisons

*Pre-registered rule: no configuration claims `outperforms` unless the paired 95% CI excludes `0`.*

| Pair (`A vs B`) | Acc Diff (95% CI) | Acc Verdict | McNemar p | Error-Cost Diff (95% CI) | Error-Cost Verdict | Cohen's d (Cost) |
|---|---|---|---:|---|---|---:|
| `c0_fixed vs rule_engine` | -0.5000 [-0.8750, -0.1250] | `b_outperforms_a` | 0.0625 | +3.4000 [+0.4000, +6.7273] | `b_outperforms_a` | +0.735 |
| `c0_fixed vs c1_single` | +0.0000 [-0.3000, +0.3000] | `inconclusive_ci_includes_zero` | 1.0000 | +2.4000 [-0.4444, +5.2727] | `inconclusive_ci_includes_zero` | +0.545 |
| `c0_fixed vs c2_multi` | +0.0000 [-0.3000, +0.3000] | `inconclusive_ci_includes_zero` | 1.0000 | +2.4000 [-0.4444, +5.2727] | `inconclusive_ci_includes_zero` | +0.545 |
| `rule_engine vs c1_single` | +0.5000 [+0.1250, +0.8750] | `a_outperforms_b` | 0.0625 | -1.0000 [-1.7500, -0.2500] | `a_outperforms_b` | -0.949 |
| `rule_engine vs c2_multi` | +0.5000 [+0.1250, +0.8750] | `a_outperforms_b` | 0.0625 | -1.0000 [-1.7500, -0.2500] | `a_outperforms_b` | -0.949 |
| `c1_single vs c2_multi` | +0.0000 [+0.0000, +0.0000] | `inconclusive_ci_includes_zero` | 1.0000 | +0.0000 [+0.0000, +0.0000] | `inconclusive_ci_includes_zero` | +0.000 |

### 4. Anti-Shortcut Reference Baselines (`eval/shortcuts.py`)

| Shortcut Baseline | Dev Accuracy | Target Split Accuracy |
|---|---:|---:|
| `hand_features_logreg` | 70.0% | 80.0% |
| `memo_keyword_nb` | 60.0% | 60.0% |
| `root_kyc_tree` | 76.7% | 100.0% |

### 5. Per-Family Breakdown (`disposition_accuracy` / `weighted_error_cost`)

| Family | `c0_fixed` | `c1_single` | `c2_multi` | `rule_engine` |
|---|---:|---:|---:|---:|
| `ambiguous` | 66.7% / 3.33 | 100.0% / 0.00 | 100.0% / 0.00 | 100.0% / 0.00 |
| `benign_lookalike` | 33.3% / 1.33 | 0.0% / 2.00 | 0.0% / 2.00 | 66.7% / 0.67 |
| `layering` | 0.0% / 2.00 | 0.0% / 2.00 | 0.0% / 2.00 | 100.0% / 0.00 |
| `layering_benign_cover` | 0.0% / 7.33 | 0.0% / 2.00 | 0.0% / 2.00 | 66.7% / 0.67 |
## AuditGuard Experiment `E2` — Security Defenses Report

- **Split:** `held_out`
- **Red-Team Suite:** `v2`

### 1. Defenses OFF vs Defenses ON (Mean & Wilson 95% CI)

| Variant | Red-Team ASR (95% CI) | Block Rate | Benign False-Block Rate (95% CI) | Unauth Writes | PII Leaks | End-to-End Agent ASR |
|---|---|---|---|---:|---:|---|
| `defenses_off` | 87.9% [81.2%, 92.4%] | 12.1% (16/132) | 0.0% [0.0%, 1.2%] (0/320) | 4 | 10 | 100.0% |
| `defenses_on` | 2.3% [0.8%, 6.5%] | 97.7% (129/132) | 0.0% [0.0%, 1.2%] (0/320) | 0 | 0 | 0.0% |
## Retrieval v2 Benchmark (All 4 Pipelines)

- **Benchmark:** `eval/retrieval_bench_v2.jsonl` (`110` queries: `88` answerable, `22` unanswerable = `20.0%`)
- **Configured Default Pipeline:** `hybrid_rrf_rerank`
- **Empirical Best Pipeline:** `hybrid_rrf_rerank`
- **Default >= BM25 on Recall@1:** `True`

| Pipeline | Recall@1 | Recall@3 | Recall@5 | MRR | nDCG@5 | Abstain Prec | Abstain Rec | Abstain F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `bm25_only` | 0.852 | 0.786 | 0.875 | 0.891 | 0.838 | 0.833 | 0.909 | 0.870 |
| `dense_only` | 0.761 | 0.742 | 0.799 | 0.799 | 0.771 | 0.606 | 0.909 | 0.727 |
| `hybrid_rrf` | 0.898 | 0.881 | 0.915 | 0.934 | 0.887 | 1.000 | 0.909 | 0.952 |
| `hybrid_rrf_rerank` **(default)** | 0.909 | 0.856 | 0.915 | 0.938 | 0.888 | 1.000 | 0.909 | 0.952 |

## Cross-Family LLM Judge & Human Calibration Status

- **Calibration Status:** `awaiting_human_annotations`
- **Judge Model:** `google/gemini-3.1-flash-lite` (cross-family verified: `True`)
- **Stratified Blinded Packet:** `60` worksheets (`20` dev, `40` held-out)
- **Annotator Rows Completed:** annotator_1=`0`, annotator_2=`0`

## Limitations & Pending `[HUMAN]` Sign-Offs

1. **Synthetic Dataset (`golden_v2`):** All development, held-out, and challenge cases are parametrically synthesized to model Indian AML scatter-gather topologies and benign look-alikes. Metrics measure behavior on this synthetic benchmark rather than live bank production traffic.
2. **Pending Independent Human Annotations (`[HUMAN]`):** The 40-case dev adjudication templates (`eval/human_labels/cases_to_annotate_annotator_{1,2}.csv`) and the 60-worksheet judge calibration templates (`eval/human_labels/worksheets_to_score_annotator_{1,2}.csv`) are intentionally empty until completed independently by human compliance annotators; judge-human Cohen's kappa is NOT claimed until those templates are populated.
3. **Pending Statutory Numbering Sign-Off (`[HUMAN]`):** All regulatory passages in `data/regulatory_corpus/indian_aml_corpus.jsonl` carry `human_verified: false` pending verification against official Gazette of India / RBI / FIU-IND / FATF originals (`data/regulatory_corpus/HUMAN_VERIFICATION_CHECKLIST.md`).
4. **Keyless Replay Scope vs Full Live LLM Matrix:** `make replay` reproduces the recorded 10-case `v2_dev` E1 LLM cassette (`c0_fixed`, `rule_engine`, `c1_single`, `c2_multi`), the full 120-case `held_out` + 30-case `challenge` deterministic E1 baselines, the full E2 red-team v2 security suite, and the full 110-query Retrieval v2 benchmark without API keys. Running full 120-case x 3-repeat live LLM E1/E3/E4 sweeps requires a funded OpenRouter key.
5. **Dense Retriever Offline Backend:** In CI without multi-GB neural weights installed, `compliance-kb` uses L2-normalized float32 SVD semantic embeddings over word + character 3/4-gram + domain concept features; an optional BGE-M3 neural backend can be substituted when `sentence_transformers` is installed.
