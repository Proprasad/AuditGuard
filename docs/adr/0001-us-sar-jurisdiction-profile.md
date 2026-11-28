# ADR 0001: US SAR jurisdiction profile

- **Status:** Proposed. Deferred from audit Wave 2 (finding AG-23, question Q5) by the project owner on 2026-11-28.
- **Decision needed from:** project owner, plus a compliance reviewer for the regulatory content.

## Context

AuditGuard investigates Indian scatter-gather alerts: PMLA 2002 / PML Rules 2005, the RBI KYC Master Direction and FIU-IND STR filing. A US profile was requested (filing a FinCEN SAR under the Bank Secrecy Act). Wave 2 found three structural blockers that make a "switch" a cross-cutting change, not configuration:

1. **Money is INR-typed in every public schema.** For example `Alert.total_amount_inr`, `FundFlowPath.total_outflow_inr`, MCP tool outputs (`amount_inr`), the DB columns (`amount_inr`, `declared_annual_income_inr`) and the workbench's `formatINR`. `Money` in `src/core/canonical.py` carries no currency. A US case would have to pretend USD is INR.
2. **The regulatory corpus is India-only.** `data/regulatory_corpus/indian_aml_corpus.jsonl` (165 passages) carries `human_verified: false` until checked against the Gazette, RBI and FIU-IND originals. There are no US passages, and US regulatory text must not be written from memory and presented as citable.
3. **India-specific rules are built into logic, prompts and tests.** These include the CTR threshold (`structuring.threshold_inr` = INR 10 lakh), the C1/C2 prompts ("Indian PMLA / RBI / FIU-IND"), citation-ID formats (`PMLA-2002-*`, `RBI-KYC-*`, `FIU-IND-RFI-*`) in the verifier, and the red-team and golden sets.

## Proposed design (for agreement before any code)

1. **A currency-aware money type.** `Money` gains a currency (or a `Amount{value: Decimal, currency: ISO-4217}` value object). Public fields become `amount` + `currency`; `*_inr` names stay as deprecated aliases for one release. This is a **breaking API/schema change** (API, MCP tool schemas, DB columns, UI, cassettes, golden sets) and needs its own migration plan.
2. **A jurisdiction profile in `config/models.yaml`:** `jurisdiction: IN | US`, default `IN`, so all current results are unchanged. Each profile defines:
   - report type and authority (STR / FIU-IND vs SAR / FinCEN);
   - filing deadlines;
   - reporting thresholds (structuring and CTR) with their currency;
   - the citation-ID grammar the verifier accepts;
   - the corpus file(s) retrieval may use;
   - prompt wording (versioned prompt YAML per profile, so `prompt_version` records it);
   - tipping-off wording (the guardrail already covers "SAR").
3. **A separate, human-verified US corpus** (for example `data/regulatory_corpus/us_bsa_corpus.jsonl`) with source URLs to eCFR and FinCEN. Retrieval filters by the active jurisdiction, so the Indian benchmark stays byte-identical.
4. **Separate evaluation sets.** A US synthetic golden set with its own dev / held-out split, and US red-team cases. US results are never mixed into the Indian E1–E4 numbers.

## US facts to verify before implementation ([HUMAN] check against eCFR / FinCEN; written from memory)

| Topic | Expected source | Content to confirm |
|---|---|---|
| Bank SAR obligation | 31 CFR 1020.320 | Dollar thresholds (with and without an identified suspect; insider abuse); "knows, suspects or has reason to suspect" standard |
| SAR filing deadline | 31 CFR 1020.320(b)(3) | 30 calendar days after initial detection; extended when no suspect is identified (to a 60-day maximum) |
| SAR confidentiality (tipping off) | 31 CFR 1020.320(e) | Prohibition on disclosing a SAR or its existence |
| Currency transaction report | 31 CFR 1010.311 | Cash transactions over USD 10,000 |
| Structuring | 31 U.S.C. 5324 | Prohibition on structuring to evade reporting |

## Consequences

- **Cost:** large, touching models, API, DB, MCP tools, UI, prompts, verifier, corpus, eval sets and every cassette. Realistically a wave of its own.
- **Risk if done as a terminology-only switch:** US-labelled output over INR-denominated data and unverified citations. That would look compliant without being so, so it is rejected.
- **Until then:** AuditGuard is documented as India-only (README "Limitations").
