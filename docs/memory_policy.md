# AuditGuard Memory Retention, Consent & Deletion Policy

## 1. Short-Term Memory
- **Mechanism:** LangGraph `InvestigationState` checkpointed per `thread_id` (PostgreSQL checkpointer in Docker/production).
- **Context Trimming:** `trim_messages_with_summary()` retains the most recent **12 messages** and folds older turns into a deterministic `rolling_summary`.

## 2. Long-Term Memory (`LongTermMemoryStore` / `PostgresStore`)
- **What is saved:**
  1. `entity_profiles`: Synthetic customer prior alert count and verified commercial registration status.
  2. `case_episodes`: Closed case topology, final disposition, and key evidence IDs.
  3. `reflexion_playbook`: Human-approved investigation heuristics with trigger preconditions.
- **When saved:** Case episodes are written **only after human approval** (`human_approved=True`). Reflexion lessons are promoted **only after human review** and frozen prior to held-out evaluation.
- **Who can read:** Investigation agents read `entity_profiles` and `reflexion_playbook` within case scope; only supervisors/evaluators modify the playbook.

## 3. Correction & Deletion (Right to be Forgotten)
- `DELETE /api/v1/memory/{customer_id}` invokes `memory_store.forget_customer(customer_id)` to remove all stored entity profiles and case episodes on demand.
