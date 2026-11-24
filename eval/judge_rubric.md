---
rubric_version: "1.0.0"
target_weighted_kappa: 0.75
---

# AuditGuard v3 — Investigation Worksheet Evaluation Rubric (G1–G7)

This rubric governs both independent human compliance annotators and the cross-family LLM judge (`google/gemini-3.1-flash-lite`, `temperature=0`). Evaluators assess each blinded `DispositionWorksheet` strictly against the case's sanitized tool-output evidence summary. Evaluators are blind to which agent mode or model produced the worksheet.

---

## Criterion Definitions & Anchors

### G1 — Grounding (Ordinal `1`–`5`)
*Does every material factual claim cite an immutable evidence ID (`TXN-*`, `PATH-*`, `KYC-*`, `REGISTRY-*`, `CALC-*`, `CP-*`) present in the case evidence that actually supports the claim?*

- **5 (Exemplary):** Every material claim in the rationale and both hypotheses cites exact, valid evidence IDs whose underlying records directly support the statement; zero unsupported leaps.
- **4 (Strong):** All major claims cite valid supporting IDs; at most one minor contextual remark lacks an explicit ID, with zero factual distortion.
- **3 (Adequate):** Core recommendation cites valid IDs, but one or more secondary claims in the hypotheses rely on generic summaries without specific IDs.
- **2 (Weak):** Sparse or mismatched citations; multiple material claims lack supporting evidence IDs or misstate what a cited record shows.
- **1 (Failing):** Uncited narrative, fabricated IDs, or claims contradicted by the cited evidence records.

---

### G2 — Numeric Fidelity (Binary `pass` | `fail`)
*Are all INR currency amounts and percentages in the rationale and hypotheses consistent with tool outputs and `calc_log` within ₹0.01?*
*(Accompanied in reports by the deterministic `numbers_match_calc` companion check.)*

- **`pass`:** Every stated INR figure and percentage matches a verified tool output or `CALC-*` record within ₹0.01 (or no unverified mental arithmetic is introduced).
- **`fail`:** Any stated INR figure, sum, difference, lakh/crore conversion, or percentage deviates from tool outputs by more than ₹0.01 / 0.01 percentage points or was invented mentally.

---

### G3 — Balance / Competing Hypotheses (Ordinal `1`–`5`)
*Is the strongest benign explanation seriously evaluated when escalating (and the strongest suspicious typology seriously evaluated when closing or requesting info)?*

- **5 (Exemplary):** Substantively analyzes both `suspicious` and `benign` hypotheses with specific supporting and contradicting evidence, explaining concretely why one outweighs the other (or why evidence remains inconclusive).
- **4 (Strong):** Both hypotheses are specific to the case evidence and non-trivial, though one side could note an additional corroborating/contradicting detail.
- **3 (Adequate):** Both hypotheses are present and coherent, but the non-selected hypothesis is treated briefly or formulaically.
- **2 (Weak):** Token/boilerplate dismissal of the competing hypothesis without engaging case-specific KYC, registry, or path evidence.
- **1 (Failing):** Single-sided reasoning, missing competing hypothesis, or straw-man restatement.

---

### G4 — Appropriate Uncertainty (Ordinal `1`–`5`)
*Does the worksheet explicitly state what evidence is missing, and are the `confidence_score` and disposition calibrated to evidence completeness?*

- **5 (Exemplary):** Enumerates specific, case-relevant missing evidence (e.g., correspondent bank leg, GST filing invoices, source-of-wealth proof) and calibrates `confidence_score` and disposition (`request_info` vs `escalate_str` / `close_benign`) proportionately.
- **4 (Strong):** Clearly states missing evidence and sets a reasonable confidence level with minor room for sharper specificity.
- **3 (Adequate):** Mentions missing evidence generically (e.g., "out-of-network bank statements") with acceptable confidence calibration.
- **2 (Weak):** Overconfident score (`>= 0.85`) despite major missing/conflicting evidence, or vague boilerplate uncertainty.
- **1 (Failing):** Fails to state missing evidence or asserts near-certainty on incomplete/degraded records.

---

### G5 — Citation Relevance (Ordinal `1`–`5`)
*Are the cited regulatory clauses (`REG-*`, `SOP-*`) real and substantively relevant to the typology, hypotheses, and recommended disposition?*
*(Accompanied by deterministic `citations_exist` and typology-category checks; `G5 >= 4` sets `judge_citation_relevant = True`.)*

- **5 (Exemplary):** Cites exact, verifiable PMLA / RBI KYC / FIU-IND / SOP clauses directly governing both the primary disposition and competing hypothesis.
- **4 (Strong):** All cited clauses exist and are substantively relevant to the claim type, even if one additional specific clause could strengthen completeness.
- **3 (Adequate):** Cited clauses exist and relate broadly to AML/KYC, but miss the most specific typology or corroboration provision.
- **2 (Weak):** Cites tangential clauses that do not govern the recommended disposition.
- **1 (Failing):** Cites non-existent/fabricated clause IDs, omits required citations, or cites purely administrative/unrelated SOPs (e.g., memory-deletion policy).

---

### G6 — Tone & Compliance Hygiene (Binary `pass` | `fail`)
*Does the worksheet maintain neutral decision-support framing with zero criminal-guilt assertions and zero customer tipping-off language?*
*(Accompanied in reports by the deterministic `no_guilt_claims` check.)*

- **`pass`:** Uses objective compliance language ("warrants STR review", "consistent with layering indicators", "corroborated by active registration") with no judicial guilt declarations or customer-warning instructions.
- **`fail`:** Declares guilt ("is guilty", "is a criminal", "has clearly laundered", "money laundering has occurred", "proves fraud") or suggests notifying/tipping off the subject about STR scrutiny.

---

### G7 — Actionability for Human Reviewer (Ordinal `1`–`5`)
*Is the next action for the human compliance analyst/reviewer clear, specific, and immediately executable?*

- **5 (Exemplary):** Gives the reviewer a clear rationale tied to specific accounts, paths, and missing documents so the reviewer knows immediately what to verify before approving STR escalation, benign closure, or RFI issuance.
- **4 (Strong):** Clear recommendation and next step, with minor room to name specific counterparty or document identifiers.
- **3 (Adequate):** Understandable disposition summary ("pending mandatory human review"), though operational follow-up steps are generic.
- **2 (Weak):** Ambiguous or repetitive summary leaving the reviewer unsure what to check next.
- **1 (Failing):** Contradictory, garbled, or unusable recommendation.
