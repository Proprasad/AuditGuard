# ruff: noqa: E501
"""
Deterministic Retrieval Benchmark v2 Builder (`eval/build_retrieval_bench_v2.py`).

Generates `eval/retrieval_bench_v2.jsonl` with 110 blind analyst-phrased queries:
  - 63 natural-language paraphrases across PMLA 2002, PMLR 2005, RBI KYC Master Direction,
    FIU-IND Red Flag Indicators, FATF Recommendations, RBI PA Guidelines, Chit Funds Act, and SOPs.
  - 25 multi-clause compound queries requiring 2-3 distinct passages.
  - 22 unanswerable out-of-scope queries (exact 20.0%) expecting empty retrieval (`expected_ids: []`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CORPUS_PATH = Path("data/regulatory_corpus/indian_aml_corpus.jsonl")
BENCH_V2_PATH = Path("eval/retrieval_bench_v2.jsonl")


def _q(qid: str, query: str, qtype: str, expected_ids: list[str]) -> dict[str, Any]:
    return {
        "query_id": qid,
        "query": query,
        "query_type": qtype,
        "expected_ids": expected_ids,
        "unanswerable": len(expected_ids) == 0,
    }


def _paraphrase_queries() -> list[dict[str, Any]]:
    """63 blind analyst-phrased single-topic paraphrase queries."""
    specs: list[tuple[str, list[str]]] = [
        # PMLA 2002
        ("What defines the legal crime of concealing dirty money and presenting it as clean assets in India?", ["PMLA-2002-S3-P01", "PMLA-2002-S3-P02"]),
        ("Does enjoying tainted funds weeks after the initial transfer still count as a continuing offence under Indian AML law?", ["PMLA-2002-S3-P02"]),
        ("How does Indian money laundering statute treat someone who knowingly lets their account be used as a pass-through conduit?", ["PMLA-2002-S3-P04", "PMLA-2002-S3-P03"]),
        ("Do bank compliance officers have to prove an underlying predicate crime before escalating suspicious activity?", ["PMLA-2002-S3-P06", "FATF-R20-P01"]),
        ("What statutory clause requires Indian banks to keep records capable of reconstructing each individual payment?", ["PMLA-2002-S12-P01"]),
        ("Are attempted suspicious transactions that were aborted before execution still reportable to FIU-IND?", ["PMLA-2002-S12-P02", "PMLR-2005-R2-P04"]),
        ("How many years must a bank retain transaction records and client KYC files after an account closes?", ["PMLA-2002-S12-P05", "FATF-R11-P01"]),
        ("Which section of PMLA lets the Director of FIU-IND demand additional records from a bank?", ["PMLA-2002-S12A-P01", "PMLA-2002-S12A-P02"]),
        ("Can a bank invoke banker-customer secrecy to refuse a statutory data request from FIU-IND?", ["PMLA-2002-S12A-P02"]),
        ("When must a reporting entity conduct enhanced due diligence to verify source of funds and client financial position before a specified transaction?", ["PMLA-2002-S12AA-P01", "PMLA-2002-S12AA-P04"]),
        ("What must a bank do if a client fails to satisfy statutory enhanced due diligence requirements prior to a specified transaction?", ["PMLA-2002-S12AA-P02"]),
        ("How long must records gathered during PMLA enhanced due diligence be preserved?", ["PMLA-2002-S12AA-P03"]),
        ("Which provision prohibits notifying a customer that their records were kept or furnished confidentially under PMLA?", ["PMLA-2002-S12-P04", "RBI-KYC-2016-P70-P01"]),
        # PMLR 2005
        ("Is there a minimum rupee threshold before an unusually complex transfer qualifies as a suspicious transaction?", ["PMLR-2005-R2-P01", "FATF-R20-P02"]),
        ("What is the cash transaction reporting limit and monthly aggregation rule for linked deposits below ten lakh?", ["PMLR-2005-R3-P01", "PMLR-2005-R3-P05"]),
        ("At what rupee amount must a bank record donations received by a charitable non-profit organisation?", ["PMLR-2005-R3-P02", "PMLR-2005-R3-P08"]),
        ("Do purely electronic IMPS or RTGS layering transfers without physical cash require suspicious transaction record keeping?", ["PMLR-2005-R3-P03", "PMLR-2005-R3-P06"]),
        ("What value triggers mandatory cross-border wire transfer recording and immovable property transaction records under PML Rules?", ["PMLR-2005-R3-P04", "PMLR-2005-R3-P07"]),
        ("Which mandatory fields such as currency, date, amount, and parties must every transaction record preserve?", ["PMLR-2005-R4-P01", "PMLR-2005-R4-P03"]),
        ("Who inside a bank must be officially notified to FIU-IND as responsible for furnishing suspicious transaction reports?", ["PMLR-2005-R7-P01", "PMLR-2005-R7-P03"]),
        ("By which day of the following month must monthly CTR and CBWTR reports be submitted to FIU-IND?", ["PMLR-2005-R8-P01"]),
        ("How many working days does the Principal Officer have to submit an STR after concluding a transaction is suspicious?", ["PMLR-2005-R8-P02"]),
        ("What ownership percentage identifies a natural person beneficial owner in an Indian company or partnership firm after the 2023 amendment?", ["PMLR-2005-R9-P02", "RBI-KYC-2016-P13-P02"]),
        ("Who must be identified as beneficial owners when the bank's customer is a trust?", ["PMLR-2005-R9-P03"]),
        ("Which government portal must banks register Non-Profit Organisation clients on under the amended PML Rules?", ["PMLR-2005-R9-P04", "RBI-KYC-2016-P56-P01"]),
        ("What rule mandates ongoing monitoring to verify client transactions align with business profile and source of funds?", ["PMLR-2005-R9-P05"]),
        ("Where must banks upload KYC records under PML Rules for centralized registry verification?", ["PMLR-2005-R9-P06"]),
        ("How should compliance staff handle document forgery or mismatched GSTIN/CIN credentials discovered during review?", ["PMLR-2005-R3-P09", "FIU-IND-RFI-BA-07"]),
        # RBI KYC Master Direction
        ("What are the four core elements required inside a bank's Board-approved KYC policy?", ["RBI-KYC-2016-P04-P01"]),
        ("When is a bank forbidden from opening an account under Customer Acceptance Policy rules?", ["RBI-KYC-2016-P10-P01"]),
        ("At what occasional walk-in transaction amount must a bank perform Customer Due Diligence?", ["RBI-KYC-2016-P13-P01", "PMLR-2005-R9-P01"]),
        ("Which Officially Valid Documents and PAN checks are required for individual customer onboarding?", ["RBI-KYC-2016-P16-P01"]),
        ("What proofs are needed to verify a sole proprietorship or company during commercial entity onboarding?", ["RBI-KYC-2016-P16-P02", "PMLR-2005-R9-P07"]),
        ("How does Video-based Customer Identification Process V-CIP mitigate risks of digital non-face-to-face account opening?", ["RBI-KYC-2016-P18-P01", "RBI-KYC-2016-P18-P02"]),
        ("When a customer's transfer volume far exceeds their declared annual salary and occupation, what RBI KYC control applies?", ["RBI-KYC-2016-P35-P01", "FIU-IND-RFI-BA-08"]),
        ("How are bank customers segmented into Low, Medium, and High risk buckets and how often is risk reviewed?", ["RBI-KYC-2016-P38-P01", "RBI-KYC-2016-P38-P02"]),
        ("Can an investigator decide a case solely from the customer's Low or High KYC risk category?", ["RBI-KYC-2016-P38-P03"]),
        ("What approval and wealth verification steps are mandatory for accounts of senior politicians or foreign public officials?", ["RBI-KYC-2016-P41-P01", "RBI-KYC-2016-P41-P02", "FATF-R12-P01"]),
        ("Do Politically Exposed Person enhanced safeguards also cover close family members and associates?", ["RBI-KYC-2016-P41-P03", "FATF-R12-P01"]),
        ("How often must banks refresh KYC records for High, Medium, and Low risk customers?", ["RBI-KYC-2016-P46-P01"]),
        ("What compliance action is required when an account with expired or minimal KYC shows high-value inter-bank transfers?", ["RBI-KYC-2016-P46-P02", "PMLR-2005-R9-P10"]),
        ("What originator details must accompany domestic RTGS, NEFT, and IMPS wire transfers of INR 50,000 or more?", ["RBI-KYC-2016-P64-P01"]),
        ("How are bundled batch wire transfers handled for originator traceability under RBI KYC directions?", ["RBI-KYC-2016-P64-P02", "RBI-KYC-2016-P64-P05"]),
        ("Should a bank automatically freeze a customer's account merely because an STR has been submitted to FIU-IND?", ["RBI-KYC-2016-P70-P02"]),
        # FIU-IND Red Flag Indicators
        ("What red flag describes dispersing funds into unrelated accounts and reconsolidating them 14 to 30 days later?", ["FIU-IND-RFI-BA-02", "FIU-IND-RFI-BA-01"]),
        ("What indicator covers intermediaries skimming a 5 to 12 percent commission before forwarding funds to a single recipient?", ["FIU-IND-RFI-BA-04", "RBI-KYC-2016-P10-P02"]),
        ("How do multi-tier layering schemes use four to five hops through secondary shells to defeat standard 3-hop detection?", ["FIU-IND-RFI-BA-05"]),
        ("What red flag applies when an inactive dormant savings account suddenly explodes with rapid outward IMPS transfers?", ["FIU-IND-RFI-BA-06", "RBI-KYC-2016-P46-P03"]),
        ("What red flag applies to a trading firm lacking MCA CIN, active GSTIN filings, and prior supplier history?", ["FIU-IND-RFI-BA-07", "FIU-IND-RFI-BA-19"]),
        ("What indicator flags funds looping through intermediaries and returning substantially intact to the original sender?", ["FIU-IND-RFI-BA-10"]),
        ("Can investigators take transaction memo descriptions like trade advance or consultancy at face value?", ["FIU-IND-RFI-BA-12", "SOP-SEC-001"]),
        # FATF, RBI PA, Chit Funds Act
        ("How do RBI Payment Aggregator guidelines treat pooled buyer escrow payouts to GST-verified e-commerce sellers?", ["RBI-PA-2020-C08-P01", "RBI-PA-2020-C08-P02"]),
        ("Are unlicensed payment pools deducting opaque commissions and co-mingling funds allowed under RBI PA rules?", ["RBI-PA-2020-C08-P04"]),
        ("What statutory sanction and registration is required before operating a rotating subscriber chit fund in India?", ["CHIT-1982-S04-P01", "CHIT-1982-S04-P02"]),
        ("How should analysts treat an informal rotating chit pool that has no State Registrar registration?", ["CHIT-1982-S04-P03", "FIU-IND-RFI-BA-15"]),
        ("What international FATF standard requires intermediary institutions to preserve wire originator metadata down the chain?", ["FATF-R16-P01", "FATF-R16-P02"]),
        ("What FATF recommendation grants legal safe harbour for good-faith STR reporting while banning tipping off?", ["FATF-R21-P01"]),
        # Internal AuditGuard SOPs
        ("When initial 7-day 3-hop graph scanning finds outbound legs without consolidation, what replanning parameters should the agent try?", ["SOP-SG-001"]),
        ("How should an investigator respond when an intermediate leg exits to an external bank missing from internal logs?", ["SOP-SG-002", "RBI-KYC-2016-P64-P03", "FATF-R16-P03"]),
        ("What verification checks distinguish legitimate monthly corporate salary payroll runs from illicit fan-out?", ["SOP-SG-004", "RBI-KYC-2016-P16-P03"]),
        ("When are pooled family wedding payments to hotels and caterers considered benign expenditure?", ["SOP-SG-005", "RBI-KYC-2016-P16-P04"]),
        ("Why does AuditGuard forbid LLM mental INR math and require Python Decimal calculation tools?", ["SOP-NUM-001", "SOP-NUM-002"]),
        ("When can case episodes be saved to long-term memory and how is customer data forgotten or erased?", ["SOP-MEM-001"]),
    ]
    return [_q(f"Q-P{i:03d}", text, "paraphrase", ids) for i, (text, ids) in enumerate(specs, start=1)]


def _multi_clause_queries() -> list[dict[str, Any]]:
    """25 multi-clause compound queries expecting 2-3 distinct passages."""
    specs: list[tuple[str, list[str]]] = [
        (
            "Staggered 14 to 30 day scatter-gather consolidation and expanding graph replanning window bounds",
            ["FIU-IND-RFI-BA-02", "SOP-SG-001"],
        ),
        (
            "Mule accounts retaining 8 percent commission without GST registration and STR filing deadline of seven working days",
            ["FIU-IND-RFI-BA-04", "PMLR-2005-R8-P02"],
        ),
        (
            "External correspondent bank visibility gap in wire transfer chain and requesting inter-bank logs instead of speculating",
            ["RBI-KYC-2016-P64-P03", "FATF-R16-P03", "SOP-SG-002"],
        ),
        (
            "Charitable trust receiving over ten lakh donations and verifying DARPAN portal and Section 80G alignment",
            ["PMLR-2005-R3-P02", "PMLR-2005-R9-P04", "RBI-KYC-2016-P56-P01"],
        ),
        (
            "Structuring cash deposits just below ten lakh rupees within a month to evade CTR reporting",
            ["PMLR-2005-R3-P01", "PMLR-2005-R3-P05", "FIU-IND-RFI-BA-03"],
        ),
        (
            "Authorized e-commerce marketplace escrow settlement cadence and commercial registration corroboration before benign closure",
            ["RBI-PA-2020-C08-P01", "SOP-SG-003", "RBI-KYC-2016-P35-P04"],
        ),
        (
            "Politically Exposed Person senior management approval, source of wealth check, and high-value multi-hop red flag",
            ["RBI-KYC-2016-P41-P02", "FATF-R12-P01", "FIU-IND-RFI-BA-16"],
        ),
        (
            "Prohibition on declaring criminal guilt in STR worksheets and cryptographic SHA-256 human analyst approval",
            ["FATF-R20-P03", "SOP-HUM-001", "SOP-HUM-002"],
        ),
        (
            "Hostile prompt injection inside untrusted transaction memos and automatic redaction of Aadhaar, PAN, and +91 phone PII",
            ["SOP-SEC-001", "SOP-SEC-002"],
        ),
        (
            "Expired minimal KYC tier on an account conducting high-value inter-bank transfers and fresh OVD PAN remediation",
            ["RBI-KYC-2016-P46-P02", "PMLR-2005-R9-P10", "RBI-KYC-2016-P16-P01"],
        ),
        (
            "Unregistered informal chit fund pool versus State Registrar sanctioned chit subscriber disbursements",
            ["CHIT-1982-S04-P01", "CHIT-1982-S04-P03", "FIU-IND-RFI-BA-15"],
        ),
        (
            "Anti-tipping-off confidentiality during routine customer document inquiries and PMLA Section 12(2) secrecy",
            ["PMLA-2002-S12-P04", "RBI-KYC-2016-P70-P01", "PMLR-2005-R7-P05"],
        ),
        (
            "Corporate salary payroll disbursement verification with MCA/EPFO employer registry and monthly counterparty cadence",
            ["SOP-SG-004", "RBI-KYC-2016-P16-P03", "SOP-SG-009"],
        ),
        (
            "Shell company with forged or uncorroborated registration flag and zero prior counterparty history in scatter-gather flow",
            ["SOP-SG-006", "FIU-IND-RFI-BA-07", "PMLR-2005-R9-P08"],
        ),
        (
            "Multi-tier four to five hop shell routing and deterministic Decimal flow conservation calculation",
            ["FIU-IND-RFI-BA-05", "SOP-NUM-002", "SOP-SG-001"],
        ),
        (
            "Cross-border wire transfer exceeding INR 5 lakhs originator metadata preservation and monthly 15th filing schedule",
            ["PMLR-2005-R3-P04", "PMLR-2005-R8-P01", "RBI-KYC-2016-P64-P02"],
        ),
        (
            "Reactivated dormant savings account sudden IMPS velocity spike and fresh re-KYC verification",
            ["FIU-IND-RFI-BA-06", "RBI-KYC-2016-P46-P03"],
        ),
        (
            "Five-year record keeping of transaction reconstruction trails and FIU-IND Director access to information",
            ["PMLA-2002-S12-P05", "PMLA-2002-S12A-P01", "FATF-R11-P01"],
        ),
        (
            "Evaluating both competing suspicious and benign hypotheses and fail-closed verifier repair downgrade to request_info",
            ["SOP-SG-007", "SOP-HUM-004"],
        ),
        (
            "Beneficial ownership 10 percent company threshold and uncovering undisclosed common owners in layered shell networks",
            ["PMLR-2005-R9-P02", "RBI-KYC-2016-P13-P02"],
        ),
        (
            "Transaction turnover vastly exceeding declared annual income and statutory PMLA Section 12AA enhanced due diligence",
            ["RBI-KYC-2016-P35-P01", "PMLA-2002-S12AA-P01", "FIU-IND-RFI-BA-08"],
        ),
        (
            "Principal Officer review handoff and seven working day STR furnishing timeline upon satisfaction of suspicion",
            ["PMLR-2005-R7-P01", "PMLR-2005-R8-P02", "SOP-HUM-003"],
        ),
        (
            "Trace-only Reflexion lesson approval without held-out leakage and post-approval episodic memory erasure",
            ["SOP-MEM-001", "SOP-MEM-002"],
        ),
        (
            "Degraded MCP tool failure handling and avoiding speculative benign closure when evidence is missing",
            ["SOP-SG-010", "SOP-SG-002"],
        ),
        (
            "Case-specific regulatory search formulation covering typology, benign hypothesis, and missing evidence obligations",
            ["SOP-SG-008", "SOP-SG-007"],
        ),
    ]
    return [_q(f"Q-M{i:03d}", text, "multi_clause", ids) for i, (text, ids) in enumerate(specs, start=1)]


def _unanswerable_queries() -> list[dict[str, Any]]:
    """22 realistic out-of-scope queries (20.0% of 110) expecting abstention (`expected_ids: []`)."""
    texts = [
        "What is the SEBI insider trading penalty multiplier for unpublished price sensitive information violations?",
        "Under EU GDPR Article 17, what administrative fine cap applies when a SaaS processor refuses data erasure?",
        "How is GST input tax credit reversal calculated for depreciated manufacturing capital goods under Rule 43?",
        "What is the maximum Income Tax Section 80C deduction limit for PPF and ELSS investments in India?",
        "What elements must a plaintiff prove in a US SEC Rule 10b-5 private securities fraud lawsuit?",
        "What Liquidity Coverage Ratio haircut percentage applies to Level 2B corporate bonds under Basel III?",
        "How is RERA builder delay compensation interest rate calculated for delayed residential possession in Maharashtra?",
        "What is the statutory timeline for granting compulsory pharmaceutical licensing under the Indian Patents Act?",
        "What is the Motor Vehicles Act third-party bodily injury liability compensation cap for commercial trucks?",
        "What percentage of adjusted net bank credit must scheduled banks allocate to agricultural Priority Sector Lending?",
        "What TCS tax rate applies under FEMA Liberalised Remittance Scheme for overseas undergraduate tuition fees?",
        "What minimum default threshold triggers corporate insolvency resolution under Section 7 of the Insolvency and Bankruptcy Code?",
        "What is the Indian Customs Act duty-free gold jewellery baggage allowance for returning non-resident travellers?",
        "How is monthly EPS-95 pension calculated for private sector employees contributing to EPFO?",
        "What maximum waiting period may IRDAI health insurers impose on pre-existing medical conditions?",
        "How many days notice must a payee serve after cheque dishonour under Section 138 of the Negotiable Instruments Act?",
        "Which Indian companies must spend two percent of average net profits on CSR under Companies Act Section 135?",
        "What Merchant Discount Rate cap applies to RuPay debit card and BHIM UPI retail point-of-sale transactions?",
        "What voting quorum is required for the RBI Monetary Policy Committee to change the benchmark repo rate?",
        "What is the SEBI Total Expense Ratio slab limit for open-ended equity mutual fund schemes above fifty thousand crores?",
        "What US IRS FATCA Form W-8BEN withholding tax rate applies to equity dividends paid to non-resident aliens?",
        "Does the Indian Copyright Act fair dealing exception cover reverse engineering proprietary database drivers?",
    ]
    return [_q(f"Q-U{i:03d}", text, "unanswerable", []) for i, text in enumerate(texts, start=1)]


def build_retrieval_bench_v2() -> dict[str, Any]:
    """Validate and write `eval/retrieval_bench_v2.jsonl`, returning summary counts."""
    corpus_ids = {
        str(json.loads(ln)["passage_id"])
        for ln in CORPUS_PATH.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    }
    queries = [*_paraphrase_queries(), *_multi_clause_queries(), *_unanswerable_queries()]

    seen_q: set[str] = set()
    for q in queries:
        qt = q["query"].strip().lower()
        if qt in seen_q:
            raise ValueError(f"Duplicate benchmark query: {q['query_id']}")
        seen_q.add(qt)
        missing = [eid for eid in q["expected_ids"] if eid not in corpus_ids]
        if missing:
            raise ValueError(f"{q['query_id']} references unknown corpus IDs: {missing}")

    n_unans = sum(1 for q in queries if q["unanswerable"])
    unans_ratio = n_unans / len(queries)
    if len(queries) < 100 or abs(unans_ratio - 0.20) > 0.01:
        raise ValueError(f"Benchmark shape invalid: total={len(queries)}, unanswerable_ratio={unans_ratio:.3f}")

    BENCH_V2_PATH.write_text(
        "\n".join(json.dumps(q, ensure_ascii=False) for q in queries) + "\n",
        encoding="utf-8",
    )
    return {
        "total_queries": len(queries),
        "paraphrase": sum(1 for q in queries if q["query_type"] == "paraphrase"),
        "multi_clause": sum(1 for q in queries if q["query_type"] == "multi_clause"),
        "unanswerable": n_unans,
        "unanswerable_ratio": round(unans_ratio, 4),
        "bench_path": str(BENCH_V2_PATH),
    }


if __name__ == "__main__":
    print(json.dumps(build_retrieval_bench_v2(), indent=2))
