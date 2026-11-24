"""
Category- and statute-specific compliance application guidance appended when enriching
passages into the 100-300 word chunk range (`data/regulatory_corpus/build_corpus_v2.py`).
"""

from __future__ import annotations

from typing import Any

CATEGORY_GUIDANCE: dict[str, str] = {
    "offence_definition": (
        "In operational alert triage, analysts map observed transaction indicators—such as rapid pass-through "
        "dispersion, unexplained intermediary hops, and disconnect from declared income—to statutory concealment "
        "risk without adjudicating criminal guilt. Objective documentation of transaction identifiers, decimal "
        "amounts, and missing external source-of-funds evidence supports Principal Officer review."
    ),
    "layering": (
        "Operational verification requires reconstructing candidate multi-hop paths across bounded lookback "
        "windows, checking exact decimal conservation between dispersed outflows and consolidated inflows, and "
        "testing whether intermediary accounts hold verified commercial registrations or recurring prior "
        "counterparty history before escalating an alert for Suspicious Transaction Report review."
    ),
    "structuring": (
        "Investigators examining suspected threshold evasion must aggregate linked cash or electronic legs "
        "across rolling monthly windows using exact decimal sums, inspect timing proximity across related "
        "accounts, and distinguish deliberate sub-INR 10,00,000 fragmentation from legitimate recurring "
        "commercial billing schedules backed by verifiable GST invoices."
    ),
    "fee_skimming": (
        "When intermediary accounts retain a consistent 5 to 12 percent slice prior to onward remittance, "
        "analysts must compute exact net differences and retention percentages deterministically, check "
        "whether intermediaries possess GSTIN or MCA business registrations, and verify if historical "
        "counterparty logs corroborate bona fide brokerage or point to compensated money-mule activity."
    ),
    "two_tier_layering": (
        "Detecting secondary shell hops requires expanding graph search depth to four or five hops when "
        "initial short-hop scans reveal unexplained outbound dispersal without immediate consolidation. "
        "Analysts document all intermediate nodes, check KYC profiles for shared addresses or dormant "
        "account flags, and preserve full path identifiers for Principal Officer escalation."
    ),
    "dormant_reactivation": (
        "Compliance review of newly opened or reactivated dormant accounts focuses on comparing recent "
        "high-velocity IMPS, NEFT, and RTGS bursts against historical balance dormancy, verifying whether "
        "fresh OVD and PAN re-KYC was completed, and confirming whether incoming credits align with the "
        "holder's declared occupation and annual income before ruling out mule exploitation."
    ),
    "shell_entities": (
        "Distinguishing genuine commercial traders from shell conduits requires corroborating corporate "
        "registration records (MCA CIN, active GSTIN filings, proprietorship licences) alongside multi-month "
        "counterparty history and beneficial ownership disclosures. Contradictions between claimed trade "
        "narrations and authoritative registry lookups prohibit automatic benign closure."
    ),
    "edd": (
        "Applying Enhanced Due Diligence requires verifying source of funds, source of wealth, beneficial "
        "ownership, and economic rationale whenever observed turnover diverges materially from declared "
        "annual income or occupation. Analysts record every verified KYC identifier, highlight unresolved "
        "income-to-volume discrepancies, and document enhanced ongoing monitoring recommendations."
    ),
    "risk_categorization": (
        "Risk categorization guides monitoring intensity and periodic KYC refresh intervals (two years for "
        "High risk, eight years for Medium risk, ten years for Low risk) without serving as a standalone "
        "verdict. Investigators weigh risk tier alongside reconstructed fund-flow paths, commercial "
        "corroboration, and counterparty cadence when recommending disposition."
    ),
    "pep": (
        "Reviews involving Politically Exposed Persons or their close relatives and associates require "
        "verifying senior management approval on file, independently checking documented source of wealth "
        "against observed transfer volumes, and maintaining heightened continuous transaction monitoring "
        "over all linked domestic and cross-border accounts."
    ),
    "periodic_updation": (
        "Where an account participating in high-value inter-bank flows exhibits expired KYC records, "
        "minimal or small-account tiers, or missing PAN verification, analysts must surface the compliance "
        "gap in missing evidence and recommend requesting fresh OVD and PAN documentation rather than "
        "closing the alert as benign."
    ),
    "commercial_verification": (
        "Corroborating a benign commercial hypothesis requires independent confirmation of active statutory "
        "registration (GSTIN, MCA CIN, or relevant sector licence) paired with recurring multi-month "
        "counterparty settlement history and alignment between observed payment ticket sizes and declared "
        "business turnover; a single registry flag alone is insufficient."
    ),
    "ngo_monitoring": (
        "Non-Profit Organisation and charitable trust alerts require verifying NITI Aayog DARPAN portal "
        "registration, Section 80G or 12A status, trustee beneficial ownership, and transparent alignment "
        "between donor inflows and verified charitable relief disbursements, while ensuring Rule 3(1)(BA) "
        "reporting thresholds above INR 10,00,000 are monitored."
    ),
    "wire_transfers": (
        "Wire transfer compliance across RTGS, NEFT, IMPS, and cross-border channels mandates retaining "
        "accurate originator and beneficiary account identifiers, unique transaction references, and "
        "batch reconciliation records so end-to-end fund flows remain fully traceable and any cross-border "
        "transfers exceeding INR 5,00,000 satisfy statutory reporting."
    ),
    "wire_traceability": (
        "Maintaining unbroken payment-chain transparency across ordering, intermediary, and beneficiary "
        "institutions prevents stripping of originator metadata. When an intermediary leg lacks complete "
        "party identification or exits into an external correspondent bank, analysts document the gap "
        "explicitly and apply risk-based follow-up or information requests."
    ),
    "marketplace_escrow": (
        "Evaluating purported e-commerce marketplace or payment aggregator settlements requires confirming "
        "authorized escrow/nodal operations, active commercial registration for both aggregator and seller "
        "recipients, regular T+1/T+2 payout cadence, and absence of circular reconsolidation or "
        "undocumented fee skimming to personal accounts."
    ),
    "record_keeping": (
        "Reconstructable five-year record retention encompasses transaction ledgers, exact decimal amounts, "
        "KYC identity documents, beneficial ownership filings, business correspondence, and written "
        "investigation analysis so the reporting entity can respond swiftly and accurately to supervisory "
        "audits or Section 12A requests from FIU-IND."
    ),
    "confidentiality": (
        "Strict anti-tipping-off controls bar disclosing STR consideration, internal alert triggers, or "
        "FIU-IND correspondence to customers or unauthorized third parties. Any necessary customer document "
        "requests must be framed neutrally as standard KYC or routine account verification without hinting "
        "at suspicion of money laundering."
    ),
    "str_obligation": (
        "Suspicious transaction obligations cover executed and attempted transactions, cash and non-cash "
        "electronic rails alike, with zero minimum monetary threshold whenever objective anomalies create "
        "reasonable grounds of suspicion or demonstrate unusual complexity lacking apparent economic "
        "rationale or bona fide lawful purpose."
    ),
    "principal_officer": (
        "Statutory reporting authority rests exclusively with the designated Principal Officer notified to "
        "FIU-IND. Investigation worksheets prepared by analysts or AI decision-support agents must package "
        "both competing hypotheses, exact evidence IDs, and verified citations to enable timely Principal "
        "Officer review and formal approval."
    ),
    "filing_timeline": (
        "Timely triage protects statutory compliance with PMLR Rule 8 deadlines: periodic CTR, NTR, and "
        "CBWTR filings by the 15th day of the succeeding month, and Suspicious Transaction Reports "
        "furnished promptly and not later than seven working days after the Principal Officer is satisfied "
        "that reasonable grounds of suspicion exist."
    ),
    "chit_fund": (
        "Lawful chit fund pools require prior State Government sanction and active registration with the "
        "State Registrar of Chits under Section 4 of the Chit Funds Act, 1982, alongside regular monthly "
        "subscriber installment schedules. Unregistered informal pooling schemes claiming chit operations "
        "lack statutory oversight and must be escalated."
    ),
    "str_standard": (
        "Reasonable-grounds reporting balances preventing false-negative misses of genuine layering against "
        "avoiding defensive over-reporting of verified commercial look-alikes. Analysts present neutral, "
        "evidence-backed findings without ever asserting criminal guilt or declaring that a predicate "
        "offence has been judicially proven."
    ),
    "replanning": (
        "Bounded investigative replanning ensures static default scan windows do not overlook delayed or "
        "deeper-hop layering. Every parameter expansion remains strictly clamped within policy minimums "
        "and maximums, consumes an explicit replan budget slot, and records comparative graph outputs for "
        "full audit reproducibility."
    ),
    "incomplete_data": (
        "Whenever critical external-bank legs, counterparty KYC files, or degraded tool responses prevent "
        "complete verification, fail-closed compliance rules forbid speculative extrapolation or premature "
        "benign closure. Analysts explicitly enumerate missing items and recommend requesting supplementary "
        "inter-bank logs or KYC records."
    ),
    "benign_lookalikes": (
        "Commercial pooling mechanisms—such as marketplace escrow payouts, corporate payroll runs, "
        "registered NGO relief grants, verified hospitality event payments, and State-registered chit "
        "funds—require multi-signal corroboration across registry status, counterparty cadence, and "
        "income alignment before closing an alert as benign."
    ),
    "payroll_verification": (
        "Employer salary runs must be verified against active corporate registry records (MCA, GST, or "
        "EPFO), consistent monthly disbursement intervals, alignment with recipient employee KYC profiles, "
        "and absence of suspicious onward consolidation back into an employer-linked beneficiary account."
    ),
    "wedding_social": (
        "Family and social event expenditure claims require corroborating Low-risk verified customer KYC, "
        "alignment with personal or family savings capacity, direct remittance to GST-registered banquet, "
        "hotel, or catering vendors, and absence of circular pass-through routing to unrelated individuals."
    ),
    "decimal_math": (
        "Every monetary total, outflow-to-inflow variance, fee retention percentage, and structuring "
        "threshold comparison must originate from deterministic Python Decimal computation rather than LLM "
        "estimation, maintaining exact INR 0.01 grounding across structured schedules and narrative text. "
        "Whenever a prose figure deviates by more than one paisa from calc logs or ledger outputs, "
        "deterministic verification blocks submission for repair."
    ),
    "prompt_injection": (
        "Isolating customer-supplied text fields inside untrusted delimiters and enforcing output and PII "
        "redaction guardrails ensures hostile transaction memos or KYC notes cannot manipulate tool "
        "selection, alter disposition decisions, or expose sensitive Aadhaar, PAN, phone, or credential data."
    ),
    "memory_policy": (
        "Strict governance over episodic memory and trace-only Reflexion lessons protects data-subject "
        "erasure rights and held-out evaluation integrity by permitting persistence only after explicit "
        "human approval and forbidding runtime access to held-out gold labels. Every deletion or "
        "reflexion approval event is recorded in the compliance audit log for regulatory inspection."
    ),
    "governance": (
        "End-to-end compliance governance combines deterministic safety verification, dual-hypothesis "
        "reporting, explicit missing-evidence disclosure, and cryptographic SHA-256 human analyst approval "
        "so every committed disposition remains transparent, auditable, and strictly under human control. "
        "Automated systems never file regulatory reports autonomously and always preserve immutable "
        "evidence references for Principal Officer and supervisory audit review."
    ),
}


def ensure_chunk_word_range(rec: dict[str, Any], min_words: int = 100, max_words: int = 300) -> dict[str, Any]:
    """Enrich passages under `min_words` with category-specific application guidance, staying <= `max_words`."""
    text = " ".join(str(rec["text"]).split())
    words = text.split()
    if len(words) < min_words:
        cat = str(rec.get("category", "governance"))
        suffix = CATEGORY_GUIDANCE.get(cat, CATEGORY_GUIDANCE["governance"])
        text = f"{text} {suffix}"
        words = text.split()
    if len(words) > max_words:
        text = " ".join(words[:max_words])
    return {**rec, "text": text}
