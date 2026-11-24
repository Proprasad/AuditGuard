# AuditGuard v3 — Pre-Registration of Evaluation Hypotheses & Statistical Protocol

*Frozen prior to held-out E1–E4 experiment execution (`docs/AGENT_GUIDE.md` §4 Phase 5).*

---

## 1. Datasets, Splits, and Held-Out Isolation

- **Primary Evaluation Split (`held_out` / `v2_held_out`):** `120` cases in `eval/golden_v2/held_out/` spanning 5 top-level typology families (`layering`, `layering_benign_cover`, `benign_lookalike`, `incomplete_data`, `ambiguous`) including held-out-only structural sub-variants (`three_tier_partial`, `round_trip`, `all_intermediaries_registered_merchants`, `franchise_royalty`, `cooperative_disbursal`, `stale_registry`, `conflicting_kyc_registry`).
- **Adversarial Challenge Slice (`challenge` / `v2_challenge`):** `30` hard adversarial cases in `eval/golden_v2/challenge/` (`forged_registry`, `decoy_memo`, multi-tier skims, conflicting records).
- **Development Split (`dev` / `v2_dev`):** `60` cases in `data/golden_v2/dev/` used exclusively for prompt iteration, E3 Reflexion lesson generation, judge few-shot anchors, and the 10-case CI replay smoke gate.
- **Anti-Shortcut Reference Baselines (`eval/shortcuts.py`):** Reported alongside all E1 modes on `held_out`:
  1. Root KYC decision tree (`depth <= 3`)
  2. 10-feature L2 logistic regression trained on `v2_dev`
  3. TF-IDF memo-keyword classifier trained on `v2_dev`

---

## 2. Shared Runtime Budgets & Replication Policy

All four modes (`c0_fixed`, `rule_engine`, `c1_single`, `c2_multi`) execute under identical `PolicyConfig` budgets (`config/models.yaml`):

- `max_tool_calls = 15`
- `max_replans = 3`
- `max_cost_usd_per_case = $0.15`
- Primary investigator & specialist LLM: `openai/gpt-5-mini` (`temperature = 0.1`)
- Cross-family judge LLM: `google/gemini-3.1-flash-lite` (`temperature = 0.0`)
- **Replication:**
  - LLM modes (`c1_single`, `c2_multi`): `repeats = 3` with distinct deterministic seeds (`42, 43, 44`). Per-case expectations are averaged across repeats prior to case/cluster-level inference so repeat count never inflates effective sample size $N$.
  - Deterministic baselines (`c0_fixed`, `rule_engine`): executed once (`1` pass) and labelled `"deterministic"`.

---

## 3. Pre-Registered Hypotheses

### Experiment E1 — Architecture Value (`c0_fixed`, `rule_engine`, `c1_single`, `c2_multi`)

- **H1 (Error-Cost Reduction vs Fair Fixed Baseline):** `c1_single` and `c2_multi` reduce `weighted_error_cost` relative to fair `c0_fixed` by at least `0.15` cost units (`>= 15%` relative reduction) on `held_out`, with the 10,000-resample paired cluster-bootstrap 95% CI excluding `0`.
- **H2 (Messy/Adversarial Generalization vs Strong Rule Engine):** `c1_single` and `c2_multi` achieve lower `weighted_error_cost` and higher `disposition_accuracy` than `rule_engine` on the 30-case adversarial `challenge` slice, while performing within parity (`95%` paired CI containing `0` or `<= 5 pp` gap) on `easy` difficulty cases where deterministic rules suffice.
- **H3 (Single-Agent vs Multi-Agent Cost Efficiency):** `c2_multi` does **not** outperform `c1_single` on cost-normalized utility (error-cost reduction per USD spent), reflecting coordination token overhead across supervisor and specialist turns.

### Experiment E2 — End-to-End Security Defenses (`defenses_off` vs `defenses_on`)

- **H4:** Enabling `pre_tool_hook` + `post_tool_hook` + output verification (`defenses_on`) reduces `attack_success_rate` on `eval/red_team_v2/` (`>= 120` attacks across paraphrase, Unicode/homoglyph, Hinglish/multilingual, tag-breakout, RBAC/bounds/approval, and PII/guilt categories) to `<= 0.05` while keeping `false_block_rate` across `>= 300` realistic benign Indian banking memos `<= 0.02`.

### Experiment E3 — Trace-Only LLM Reflexion (`playbook_off` vs `playbook_on`)

- **H5:** Candidate lessons generated strictly from sanitized `v2_dev` failure traces (zero gold labels in reflector prompt), reviewed by a human and frozen prior to `held_out` evaluation, improve `replan_recovery_rate` without increasing `false_close_rate`.

### Experiment E4 — C1 Signature Ablations

- **H6:** Removing `replan_graph` (`no_replanning`, `fixed_detector`) degrades `replan_recovery_rate`; removing the `calc` tool (`llm_math`) or verifier gate (`no_verifier_gate`) increases `inr_arithmetic_error_rate`; removing `check_commercial_registry` (`no_registry_check`) degrades `benign_lookalike` / `layering_benign_cover` discrimination; removing `compliance-kb` (`no_rag`) degrades `citation_validity_rate`.

---

## 4. Statistical Decision & Reporting Rules

1. **Proportions:** Reported with exact **Wilson 95% score confidence intervals** over $N$ unique cases.
2. **Continuous & Composite Metrics:** Reported with **10,000-iteration cluster-bootstrap 95% confidence intervals**, clustering on case sub-variant (`family`) so repeated structural templates do not overstate precision.
3. **Mode Comparisons:** Evaluated via **10,000-iteration paired cluster-bootstrap 95% CIs** on case-matched differences `(mode_A - mode_B)` plus **exact two-sided McNemar's test** for `disposition_accuracy` and standardized paired effect size (`cohens_d`).
4. **Honest Inference Rule:** **No mode or ablation is claimed to "outperform" another unless the paired 95% confidence interval excludes `0`.** Null, negative, or trade-off findings (e.g., `rule_engine` winning on cost/latency or matching LLM accuracy on clean cases) are reported verbatim without post-hoc hypothesis edits.
