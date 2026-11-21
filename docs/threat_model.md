# AuditGuard 1-Page STRIDE Threat Model

| STRIDE Category | Specific Threat | Enforced Countermeasure |
|-----------------|-----------------|-------------------------|
| **Spoofing** | Forged analyst approval or unauthenticated API call | Server-side HMAC approval token bound to payload SHA-256 hash; JWT auth ready on API gateway |
| **Tampering** | Editing worksheet INR amounts or disposition after human sign-off | Canonical SHA-256 verification inside `case_actions.py`; any edit invalidates prior token (`token_invalidated_by_edit`) |
| **Repudiation** | Disputed audit trail for case closure or escalation | Append-only `audit_logs` table storing `thread_id`, evidence IDs, `payload_hash`, `actor`, and timestamp |
| **Information Disclosure** | Synthetic PII leaking into Langfuse traces or cross-case memory | `post_tool_hook` PII scrubber (`mask_pii`); namespace isolation in `LongTermMemoryStore` |
| **Denial of Service** | Infinite replanning loops or exponential graph path explosion | `max_replans=3`, `max_tool_calls=15`, `max_cost_usd=0.15`, `max_hops <= 5`, `time_window_days <= 30` |
| **Elevation of Privilege** | Indirect prompt injection in transaction memos (`Ignore previous instructions`) | `detect_injection` + `<untrusted_data>` tagging + per-agent RBAC allow-lists (`flow_tracer` cannot call `case-actions`) |
