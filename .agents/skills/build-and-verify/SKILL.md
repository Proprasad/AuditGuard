---
name: build-and-verify
description: Automatically implement, build, test, debug, and verify every requested feature or bugfix end-to-end. Use whenever modifying application code, implementing functionality, fixing defects, or changing existing behavior.
---

# Autonomous Build, Test, and Verification Workflow (`AuditGuard`)

Follow this mandatory four-step workflow for every feature implementation, bugfix, or behavior change in the AuditGuard repository. Consult `AGENTS.md` in the repository root for architectural invariants, coding standards, and autonomous execution rules.

**Non-negotiable rules:**
- Complete every step end-to-end without pausing for intermediate confirmation.
- Never modify files outside this workspace, and **never** run `git commit` or `git push`.
- Never disable tests, weaken lint/type rules, bypass deterministic safety guards, or claim an unexecuted check passed.

---

## Step 1: Implement

1. **Understand Requirements:** Clarify the exact behavior, acceptance criteria, and affected components from the user request.
2. **Inspect Source Code First:** Read all relevant source files, schemas (`src/models.py`), policies (`config/models.yaml`), and tests before making any edits. Source code is the single source of truth.
3. **Follow Existing Architecture & Standards:**
   - Preserve the deterministic safety core (`Decimal` arithmetic in `src/core/`, RBAC & hooks in `src/guardrails/`, fail-closed `verify_worksheet`, and single-use HMAC human approval gating).
   - Keep strict typing (`mypy src/ --strict`), Pydantic `StrictModel` validation, timezone-aware UTC timestamps, and structured MCP error propagation.
   - Maintain held-out isolation (`src/` and `data/` must never read `eval/golden_v2/held_out/`, `eval/golden_v2/challenge/`, or `eval/held_out/`).
   - Keep `src/ui/static/index.html` DOM IDs synchronized with `src/ui/static/js/app.js` when editing the Analyst Workbench.
4. **Implement Completely:** Handle edge cases, error paths, and security/redaction constraints without unnecessary refactoring of unrelated modules.
5. **Add or Update Automated Tests:** Add focused unit and/or integration tests under `tests/` using `tests/conftest.py` isolated DB fixtures and `tests/fakes.py` (`FakeLLM`) where appropriate. Never touch `data/auditguard.db` in tests.

---

## Step 2: Self-Heal and Test

Run all applicable repository verification commands from the project root.

### 1. Build / Package Check
AuditGuard is a Python package with static vanilla HTML/CSS/ES-Module frontend assets (no Node.js/npm/bundler build step).
- If `pyproject.toml` or packaging metadata changed, verify editable installation:
  ```bash
  python -m pip install --no-deps -e .
  ```
- Otherwise, confirm imports and package health via type-check and pytest below (report Build as `PASS` if verified or `NOT APPLICABLE` for non-packaging edits only if clearly explained; prefer running `python -m compileall -q src/ eval/` as a fast syntax/bytecode build check).

### 2. Type-Check
```bash
python -m mypy src/ --strict
```
*(Note: Frontend JavaScript in `src/ui/static/js/` is untyped vanilla ES Modules; no TypeScript checker exists in this repository.)*

### 3. Lint
```bash
python -m ruff check src/ eval/ data/generator_v2/ data/regulatory_corpus/ tests/ scripts/ --select E,F,B,S,DTZ,BLE,T20,C901
```
*(Note: No JavaScript/CSS linter is configured in this repository.)*

### 4. Unit & Integration Tests
Run targeted tests first while iterating, then run the full suite:
```bash
python -m pytest tests/ -q
```
For UI/DOM or SSE contract changes, ensure this passes:
```bash
python -m pytest tests/test_frontend_integrity.py -q
```

### 5. Offline CI Evaluation & Replay Gates (Integration / Regression)
Whenever agent logic, tools, graph math, retrieval, guardrails, prompts, verifier, or `eval/` code changes, run:
```bash
python -m eval.verify_gates
```
If dataset or operational DB code changed, also verify zero held-out leakage:
```bash
python scripts/purge_operational_db.py --check
```

### 6. End-to-End Tests (Where Applicable)
- **Live multi-process HTTP MCP + FastAPI + LLM E2E script:** `python scripts/verify_live_e2e.py`
  - Only run when `.env` contains valid seeded passwords and (for live LLM verification) a funded `OPENROUTER_API_KEY`.
  - If credentials or live external API access are unavailable, do **not** fake a pass — report the exact blocker (`BLOCKED` or `NOT AVAILABLE` with explanation).
- **Automated browser E2E test suite (Playwright/Cypress/Selenium):** Not installed in this repository.

### Self-Healing Loop
For **every** failure across any check above:
1. Read the complete relevant error output and stack trace.
2. Identify the root cause in source or test code.
3. Apply the proper engineering fix (never disable tests, add blanket `# type: ignore` / `# noqa` suppressions to hide real bugs, or weaken assertions).
4. Re-run the failing check and all impacted checks.
5. Repeat until every applicable check passes cleanly.

If a check cannot execute due to missing infrastructure, credentials, or external services, document the exact blocker accurately.

---

## Step 3: Browser and UI Verification

This step is **mandatory** whenever a change modifies `src/ui/`, `src/api/routes/ui.py`, API payloads consumed by the Analyst Workbench, SSE events, or any user-facing web behavior.

### Workflow
1. **Start the Local Server:**
   ```bash
   python -m src.cli serve --host 127.0.0.1 --port 8000
   ```
   Wait until `GET http://127.0.0.1:8000/health` returns HTTP `200` (`"status": "healthy"`).
   *(If modifying the optional Chainlit UI in `src/ui/app.py`, also launch `chainlit run src/ui/app.py --host 127.0.0.1 --port 8001`.)*
2. **Launch Browser Automation:** Use the available browser automation tool or browser subagent to open the running app.
3. **Open Affected Routes:**
   - Primary Analyst Workbench: `http://127.0.0.1:8000/` (sign in using local seeded dev credentials from `.env` when prompted by the JWT login modal)
   - OpenAPI Docs (when API schemas changed): `http://127.0.0.1:8000/api/docs`
   - Report Export route (when report HTML changed): `http://127.0.0.1:8000/api/v1/investigations/{thread_id}/export`
4. **Verify UI Components & User Journeys:**
   - Validate modified sidebar views (`investigation`, `alerts`, `cases`, `customers`, `graph_explorer`, `regulations`, `audit`, `analytics`, `settings`) and center workspace tabs (`graph`, `flow`, `hypotheses`, `evidence`, `agents`).
   - Exercise interactive controls: forms, dropdowns, buttons, modal dialogs, SSE live investigation stream, and approval/edit/reject controls as relevant to the change.
5. **Inspect Console & Network:**
   - Check browser console output for uncaught JavaScript errors or failed ES module imports.
   - Check network activity for unexpected `4xx`/`5xx` HTTP responses or dropped SSE streams.
6. **Capture Visual Evidence:** Take screenshots showing the verified routes and interactive states.
7. **Stop Temporary Servers (if appropriate):** Clean up any temporary test server started solely for verification unless the user asked to keep it running.

**Truthfulness Requirement:** If browser automation infrastructure (e.g., Chrome DevTools / browser subagent) is unavailable or blocked in the current environment, record `Browser verification: BLOCKED` with the exact reason — never claim browser verification passed.

---

## Step 4: Prepare Review

After all applicable checks succeed (or any external blockers are documented), produce a concise final **Walkthrough** artifact (or review-ready response section when artifacts are not used) containing all five sections below:

### A. Implementation Summary
- What was implemented or fixed.
- Key engineering decisions and how they align with AuditGuard's architecture.
- Any assumptions or known limitations.

### B. Changed Files
- Exact file paths (as clickable links).
- Brief summary of changes per file.
- Reason for each significant modification.

### C. Verification Results

Include an accurate table reflecting **only** checks that were actually executed:

| Check | Result |
|---|---|
| Build | PASS / FAIL / BLOCKED |
| Type-check | PASS / FAIL / NOT AVAILABLE |
| Lint | PASS / FAIL / NOT AVAILABLE |
| Unit tests | PASS / FAIL / NOT AVAILABLE |
| Integration tests | PASS / FAIL / NOT AVAILABLE |
| E2E tests | PASS / FAIL / NOT AVAILABLE / BLOCKED |
| Browser verification | PASS / FAIL / NOT APPLICABLE / BLOCKED |

### D. Visual Evidence
- Attach verification screenshots captured during Step 3 where applicable.
- Identify the exact routes, views, and interactions demonstrated.

### E. Remaining Issues
- Document any unresolved issues.
- Explain any environmental or credential blockers.
- List any checks that could not be completed.
- Confirm that no `git commit` or `git push` was performed and all changes remain ready for human review.
