# AuditGuard Memory Retention, Consent & Deletion Policy

## 1. Short-Term Memory
- **Mechanism:** LangGraph `InvestigationState` checkpointed per `thread_id` (PostgreSQL checkpointer in Docker/production).
- **Context Trimming:** `trim_messages_with_summary()` retains the most recent **12 messages** and folds older turns into a deterministic `rolling_summary`.

## 2. Long-Term Memory (`LongTermMemoryStore` — SQLite WAL / PostgreSQL)
- **What is saved:**
  1. `entity_profiles`: Synthetic customer prior alert metadata and human review summary.
  2. `case_episodes`: Closed case disposition, reviewer identity, and canonical SHA-256 payload hash.
  3. `reflexion_playbook`: Human-approved investigation heuristics with trigger preconditions.
- **When saved:** Case episodes and entity profiles are written **only after human approval** (`human_approved=True`). Reflexion lessons are promoted **only after human review** and frozen prior to held-out evaluation.
- **Who can read:** Investigation agents read `entity_profiles` and `reflexion_playbook` within case scope; only supervisors/evaluators modify the playbook.

## 3. Correction & Deletion (Right to be Forgotten)
- `DELETE /api/v1/memory/{customer_id}` (`senior_reviewer`+ JWT required) invokes `erase_customer()` to transactionally purge/redact entity profiles, case episodes, customer PII, registry records, transaction memos, worksheets, cases, checkpoints, events, audit logs, and LangGraph saver checkpoints.
