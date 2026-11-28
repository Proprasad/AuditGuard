# AuditGuard Progress

## 2026-11-28: Audit Wave 1 (critical security and state integrity)

Fixed AG-01, AG-02 and AG-03 (all three critical findings), plus AG-15 (partial), AG-16, AG-17, AG-30, AG-35 and AG-38.

- Tests: 191 → 208 passing.
- Every dev-eval, retrieval and E2 metric, graph export and tool hash is unchanged.

Details, decisions, adapted tests and residual items are in [audit/REMEDIATION_LOG.md](audit/REMEDIATION_LOG.md).

## 2026-11-28: AG-15 deny-by-default untrusted-data containment

Every tool result except `calc`/`finish` now reaches the LLM inside one XML-escaped `<untrusted_data>` envelope.

- E1 offline, E2 and retrieval are unchanged.
- Also fixed C2 running a different code path in replay than live. Re-recorded the smoke cassette ($0.0622) and regenerated the smoke baseline, replay bundle and evaluation report.
- 19 new tests; 227 passing; `make verify` passes. Details are in [audit/REMEDIATION_LOG.md](audit/REMEDIATION_LOG.md).

## 2026-11-28: Audit Wave 2 (resilience, targeted reviews, boundaries)

Fixed or added: AG-04/32, 05, 06, 07/08 (opt-in), 09, 10, 11, 12, 14, 18, 19/21, 20, 24, 25, 27, 28 and 33; Q5 deferred to ADR 0001.

- Also fixed 3 pre-existing defects found while running the real Compose stack.
- Tests: 227 → 290 passing; `make verify` and `make eval-gate` pass.
- E1 offline, E2 and retrieval are identical. Only the C2 smoke numbers moved (re-recorded C2 only, $0.07).

Details are in [audit/REMEDIATION_LOG.md](audit/REMEDIATION_LOG.md).
