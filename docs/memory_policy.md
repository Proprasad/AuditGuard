# AuditGuard Memory Retention, Consent & Deletion Policy

## 1. Short-Term Memory
- **Mechanism:** LangGraph `InvestigationState` checkpointed per `thread_id` (PostgreSQL checkpointer in Docker/production).
- **Context Trimming:**
  - **Checkpointed state:** `trim_messages_with_summary()` keeps the most recent **12 messages** (`memory.short_term_window_messages`) and folds older turns into a deterministic `rolling_summary`.
  - **Live LLM context:** before every C1 and C2-specialist `chat()` call, `trim_live_context()` trims the conversation once it exceeds `memory.live_context_window_messages` (**40**).
    - The system prompt and the alert message stay pinned.
    - Tool-call pairs are never split.
    - Evicted turns become one summary message wrapped as `<untrusted_data>`, because it quotes tool output.

## 2. Long-Term Memory (`LongTermMemoryStore` — SQLite WAL / PostgreSQL)
- **What is saved:**
  1. `entity_profiles`: Synthetic customer prior alert metadata and human review summary.
  2. `case_episodes`: Closed case disposition, reviewer identity, and canonical SHA-256 payload hash.
  3. `reflexion_playbook`: Human-approved investigation heuristics with trigger preconditions.
- **When saved:** Case episodes and entity profiles are written **only after human approval** (`human_approved=True`). Reflexion lessons are promoted **only after human review** and frozen prior to held-out evaluation.
- **Who reads what:**
  - **Subject history** (`src/memory/subject_history.py`): the C1 alert message and the C2 supervisor plan include up to 3 (`memory.subject_history_max_episodes`) prior **human-approved** case episodes. Rules:
    - The episodes must belong to the customer holding the alert's **root account**. Network counterparties are never included, and an earlier episode of the same alert is excluded, since it would hand the agent its own previous answer.
    - The block is labelled "may be stale … not evidence for this alert" and wrapped as `<untrusted_data source="memory:subject_history">`.
    - It is omitted entirely when `memory_enabled` is off or there is no history.
    - `entity_profiles` are written on commit but are not read by agents.
  - **Reflexion lessons** (`src/reflexion/retrieval.py`): an approved lesson is offered only when its trigger precondition shares at least `lesson_retrieval.min_overlap` (3) content words with a description of what the investigation has **observed**, capped at `lesson_retrieval.top_k` (2). In practice that is after the first graph scan: C1 gets one note after the tool turn, and the C2 supervisor sees them at the replan check.
  - **Playbook review:** only human reviewers change the playbook, via `auditguard lessons ...`. A frozen playbook carries `frozen_sha256` and is refused if edited afterwards.
- **Evaluation note:** episodes are written only by a human approval commit, which evaluation runs never perform. So E1/E3 "memory on" and "memory off" arms see the same (empty) subject history; the read path is exercised by tests and by live use.

## 3. Correction & Deletion (Right to be Forgotten)
- `DELETE /api/v1/memory/{customer_id}` (`senior_reviewer`+ JWT required) invokes `erase_customer()`. It purges or redacts entity profiles, case episodes, customer PII, registry records, transaction memos, worksheets, cases, checkpoints, events, audit logs and LangGraph saver checkpoints.
- **Order and failure handling:** the two stores cannot share one transaction, so the order is fixed and every failure is loud (audit AG-18):
  1. **LangGraph checkpoint saver first.** If this fails, nothing has changed.
  2. **Operational tables next, in one DB transaction.** If this fails, the checkpoint copy is already gone, and over-erasing the subject's own data is the safe direction.

  Either failure writes a `customer_erasure_failed` audit row (hashed customer id, stage, error type) and returns `503 ERASURE_INCOMPLETE`. Erasure is idempotent, so retrying completes it.
- **Not covered by erasure:**
  - LLM run transcripts under `runs/<run_id>/transcripts.jsonl` (local evaluation artefacts).
  - Log lines already shipped to Loki (PII-redacted at source by `src/observability/redaction.py`; removed by Loki retention, not by this API).
