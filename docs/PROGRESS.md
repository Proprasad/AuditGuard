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
