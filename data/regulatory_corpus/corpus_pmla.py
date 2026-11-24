"""
Regulatory Corpus v2 — Statutory Sources Part 1:
  - Prevention of Money-Laundering Act, 2002 (PMLA 2002: Sections 3, 12, 12A, 12AA)
  - Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 (Rules 2, 3, 4, 5, 7, 8, 9)

Each passage is 100-300 words with exact section/rule references, official source URL,
retrieval date, category, and `human_verified=False` pending `[HUMAN]` check against
official Gazette of India / India Code / FIU-IND originals.
"""

from __future__ import annotations

from typing import Any

RETRIEVAL_DATE = "2026-11-24"
PMLA_URL = "https://www.indiacode.nic.in/handle/123456789/2036"
PMLR_URL = "https://fiuindia.gov.in/files/Act_and_Rules/PML_Rules_2005.pdf"


def _reg(
    passage_id: str,
    doc_title: str,
    clause_number: str,
    effective_date: str,
    source_url: str,
    category: str,
    text: str,
) -> dict[str, Any]:
    return {
        "passage_id": passage_id,
        "source_type": "regulatory",
        "doc_title": doc_title,
        "clause_number": clause_number,
        "effective_date": effective_date,
        "retrieval_date": RETRIEVAL_DATE,
        "source_url": source_url,
        "category": category,
        "human_verified": False,
        "text": " ".join(text.split()),
    }


def _pmla(cid: str, sec: str, eff: str, cat: str, text: str) -> dict[str, Any]:
    return _reg(cid, "Prevention of Money-Laundering Act, 2002", sec, eff, PMLA_URL, cat, text)


def _pmlr(cid: str, rule: str, eff: str, cat: str, text: str) -> dict[str, Any]:
    return _reg(
        cid,
        "Prevention of Money-Laundering (Maintenance of Records) Rules, 2005",
        rule,
        eff,
        PMLR_URL,
        cat,
        text,
    )


def build_pmla_and_pmlr_passages() -> list[dict[str, Any]]:
    """Return 58 statutory passages (100-300 words each) covering PMLA 2002 and PMLR 2005."""
    items: list[dict[str, Any]] = [
        # ---- PMLA 2002 Section 3 (Offence of Money-Laundering) ----
        _pmla(
            "PMLA-2002-S3-P01",
            "Section 3",
            "2005-07-01",
            "offence_definition",
            """Section 3 of the Prevention of Money-Laundering Act, 2002 defines the statutory offence of
            money-laundering. Under this provision, whosoever directly or indirectly attempts to indulge,
            or knowingly assists, or knowingly is a party, or is actually involved in any process or
            activity connected with the proceeds of crime—including its concealment, possession,
            acquisition, or use—and projecting or claiming it as untainted property commits the offence
            of money-laundering. For banking compliance investigators, Section 3 establishes why
            multi-hop transfer networks that obscure the origin of funds trigger reporting obligations.
            Compliance analysts and automated decision-support systems do not adjudicate criminal guilt
            under Section 3; rather, they document objective transaction indicators that create reasonable
            grounds to suspect involvement with proceeds of crime for Principal Officer review.""",
        ),
        _pmla(
            "PMLA-2002-S3-P02",
            "Section 3 Explanation (i)-(ii)",
            "2019-08-01",
            "offence_definition",
            """The Explanation inserted into Section 3 of the Prevention of Money-Laundering Act, 2002
            clarifies two vital evidentiary principles for financial intelligence reviews. First, a person
            falls within the statutory scope if directly or indirectly involved in any process or activity
            connected with proceeds of crime across concealment, possession, acquisition, use, projecting as
            untainted property, or claiming as untainted property in any manner whatsoever, even when each
            act stands independently. Second, the process or activity connected with proceeds of crime is
            a continuing activity and continues until such time a person is directly or indirectly enjoying
            the proceeds of crime by concealment, possession, acquisition, use, or projection. Staggered
            transfers executed weeks after initial receipt therefore remain relevant to an active review.""",
        ),
        _pmla(
            "PMLA-2002-S3-P03",
            "Section 3 & Section 2(1)(u)",
            "2005-07-01",
            "layering",
            """Read alongside Section 2(1)(u) of the Prevention of Money-Laundering Act, 2002, proceeds of
            crime encompass any property derived or obtained, directly or indirectly, by any person as a
            result of criminal activity relating to a scheduled offence, or the value of any such property.
            When funds are dispersed from a seed account into multiple intermediary accounts and later
            consolidated into a common beneficiary account, the layering sequence obscures the audit trail
            linking source and destination. Under Section 3, knowingly assisting such concealment or
            pass-through movement through mule accounts implicates the layering stage of money-laundering.
            Investigators evaluating scatter-gather topologies should assess whether intermediary hops lack
            commercial substance, verified invoices, or genuine economic justification before recommending
            escalation to the Principal Officer.""",
        ),
        _pmla(
            "PMLA-2002-S3-P04",
            "Section 3 (Attempted & Indirect Assistance)",
            "2005-07-01",
            "offence_definition",
            """Section 3 of the Prevention of Money-Laundering Act, 2002 expressly extends beyond completed
            laundering schemes to cover direct or indirect attempts and knowing assistance. In banking
            operations, an entity or individual who permits an account to be operated as a conduit or mule
            pass-through account—receiving dispersed credits and forwarding near-identical balances onward
            while retaining a percentage commission—may provide knowing assistance in concealing proceeds.
            Because bank compliance units lack judicial authority to verify underlying predicate offences,
            investigators must record observable financial anomalies such as fee skimming, rapid velocity,
            and uncorroborated commercial claims while explicitly noting missing external evidence and
            refraining from making definitive criminal guilt assertions in investigation worksheets.""",
        ),
        # ---- PMLA 2002 Section 12 (Reporting Entity Record Keeping) ----
        _pmla(
            "PMLA-2002-S12-P01",
            "Section 12(1)(a)",
            "2013-02-15",
            "record_keeping",
            """Section 12(1)(a) of the Prevention of Money-Laundering Act, 2002 mandates that every reporting
            entity—including banking companies, financial institutions, and financial intermediaries—shall
            maintain a record of all transactions, including information relating to transactions covered
            under clause (b), in such manner as to enable it to reconstruct individual transactions.
            Transaction reconstructability is the statutory cornerstone of AML fund-flow tracing. When
            reconstructing scatter-gather paths across RTGS, NEFT, IMPS, and internal transfers, banks must
            preserve exact timestamps, sender and receiver account identifiers, exact INR decimal amounts,
            and payment references so an independent auditor or FIU-IND examiner can trace every leg
            without ambiguity or rounding distortion.""",
        ),
        _pmla(
            "PMLA-2002-S12-P02",
            "Section 12(1)(b)",
            "2013-02-15",
            "str_obligation",
            """Under Section 12(1)(b) of the Prevention of Money-Laundering Act, 2002, every reporting
            entity is legally obligated to furnish to the Director of the Financial Intelligence Unit -
            India (FIU-IND), within such time as may be prescribed under the Maintenance of Records Rules,
            information relating to prescribed transactions, whether attempted or executed, the nature and
            value of which may be prescribed. This statutory duty encompasses Cash Transaction Reports,
            Cross-Border Wire Transfer Reports, Counterfeit Currency Reports, Non-Profit Organisation
            Transaction Reports, and Suspicious Transaction Reports. Attempted suspicious transactions that
            are aborted or partially blocked before settlement still require full documentation and
            assessment for statutory reporting under Section 12(1)(b).""",
        ),
        _pmla(
            "PMLA-2002-S12-P03",
            "Section 12(1)(c)-(e)",
            "2013-02-15",
            "record_keeping",
            """Clauses (c), (d), and (e) of Section 12(1) of the Prevention of Money-Laundering Act, 2002
            require every reporting entity to maintain records of documents evidencing the identity of its
            clients and beneficial owners, as well as account files and business correspondence relating to
            its clients. In complex investigations involving multi-entity scatter-gather flows, preserving
            verified KYC records, beneficial ownership declarations, commercial registry checks, and
            historical counterparty correspondence allows analysts to test benign explanations against
            suspicious layering hypotheses. Incomplete account files, missing KYC records, or unverified
            corporate signatories constitute material evidentiary gaps that must be surfaced in the
            investigation worksheet rather than overlooked during disposition review.""",
        ),
        _pmla(
            "PMLA-2002-S12-P04",
            "Section 12(2) (Confidentiality)",
            "2013-02-15",
            "confidentiality",
            """Section 12(2) of the Prevention of Money-Laundering Act, 2002 mandates that every information
            maintained, furnished, or verified—save as otherwise provided under any law for the time being
            in force—shall be kept confidential. Reporting entities, compliance analysts, and technology
            systems supporting AML alert triage must safeguard investigation worksheets, STR drafts,
            escalation rationales, and FIU-IND correspondence against unauthorized disclosure. In
            particular, customers under active alert investigation must never be alerted or tipped off that
            their transactions are undergoing suspicious activity scrutiny or that a Suspicious Transaction
            Report is being prepared for submission to the Director, FIU-IND, as disclosure compromises
            statutory intelligence gathering.""",
        ),
        _pmla(
            "PMLA-2002-S12-P05",
            "Section 12(3)-(4) (Five-Year Retention)",
            "2013-02-15",
            "record_keeping",
            """Sub-sections (3) and (4) of Section 12 of the Prevention of Money-Laundering Act, 2002
            prescribe mandatory five-year retention periods for AML compliance records. Transaction records
            maintained under Section 12(1)(a) must be preserved for a period of five years from the date of
            the transaction between a client and the reporting entity. Identity documents, beneficial
            ownership records, account files, and business correspondence maintained under Section 12(1)(e)
            must be preserved for five years after the business relationship between a client and the
            reporting entity has ended or the account has been closed, whichever is later. Retention
            ensures historical counterparty patterns remain verifiable during multi-year inquiries.""",
        ),
        # ---- PMLA 2002 Section 12A (Access to Information) ----
        _pmla(
            "PMLA-2002-S12A-P01",
            "Section 12A(1)",
            "2013-02-15",
            "record_keeping",
            """Section 12A(1) of the Prevention of Money-Laundering Act, 2002 empowers the Director of the
            Financial Intelligence Unit - India (FIU-IND) to call for from any reporting entity any of the
            records referred to in Section 11A, Section 12(1), or Section 12AA(1), as well as any
            additional information considered necessary for the purposes of the Act. This statutory access
            authority means that every alert disposition—whether escalated as an STR, placed on request for
            additional information, or closed as benign—must retain complete supporting transaction logs,
            deterministic calculation traces, KYC records, and registry checks in an immutable audit trail
            capable of prompt production upon regulatory demand from FIU-IND.""",
        ),
        _pmla(
            "PMLA-2002-S12A-P02",
            "Section 12A(2)-(3)",
            "2013-02-15",
            "record_keeping",
            """Sub-sections (2) and (3) of Section 12A of the Prevention of Money-Laundering Act, 2002
            obligate every reporting entity to furnish to the Director, FIU-IND any information called for
            under Section 12A(1) within such time and in such manner as specified, while mandating that
            information sought under this section shall be kept strictly confidential. Banks cannot invoke
            general banker-customer secrecy to refuse statutory information calls from FIU-IND. Conversely,
            reporting entities must protect the confidentiality of FIU-IND information requests internally
            and never notify the affected customer that records or supplementary transaction logs were
            called for under Section 12A.""",
        ),
        # ---- PMLA 2002 Section 12AA (Enhanced Due Diligence) ----
        _pmla(
            "PMLA-2002-S12AA-P01",
            "Section 12AA(1)(a)-(b)",
            "2019-08-01",
            "edd",
            """Section 12AA(1) of the Prevention of Money-Laundering Act, 2002 requires every reporting
            entity, prior to the commencement of each specified transaction, to perform Enhanced Due
            Diligence (EDD). Under clauses (a) and (b), the reporting entity must verify the identity of
            clients undertaking specified transactions using prescribed authentication methods and take
            additional steps to examine the ownership and financial position, including sources of funds,
            of the client. When an account exhibits high-value scatter-gather volume sharply exceeding its
            declared annual income or business scale, Section 12AA mandates substantive verification of
            ownership structure and source of funds before treating the activity as economically legitimate.""",
        ),
        _pmla(
            "PMLA-2002-S12AA-P02",
            "Section 12AA(1)(c) & 12AA(2)",
            "2019-08-01",
            "edd",
            """Under Section 12AA(1)(c) of the Prevention of Money-Laundering Act, 2002, a reporting entity
            must take additional steps as prescribed to record the purpose behind conducting a specified
            transaction and the intended nature of the relationship between the transaction parties. Under
            Section 12AA(2), where the client fails to fulfill the Enhanced Due Diligence conditions laid
            down in sub-section (1), the reporting entity shall not allow the specified transaction to be
            carried out. In alert triage, when commercial purpose or counterparty relationships cannot be
            corroborated from existing KYC and registry records, analysts must not close the case as benign
            and must instead escalate or formally request corroborating documentation.""",
        ),
        _pmla(
            "PMLA-2002-S12AA-P03",
            "Section 12AA(3)-(4)",
            "2019-08-01",
            "edd",
            """Section 12AA(3) of the Prevention of Money-Laundering Act, 2002 mandates that where any
            specified transaction or series of specified transactions undertaken by a client is considered
            suspicious or likely to involve proceeds of crime, the reporting entity shall increase the
            future monitoring of the business relationship with the client, including greater scrutiny of
            transactions in such manner as may be prescribed. Section 12AA(4) further requires that
            information obtained while applying Enhanced Due Diligence measures under Section 12AA shall be
            maintained for a period of five years from the date of the transaction, ensuring full
            traceability for subsequent FIU-IND reviews and supervisory inspections.""",
        ),
        # ---- PMLR 2005 Rule 2(1)(g) (Suspicious Transaction Definition) ----
        _pmlr(
            "PMLR-2005-R2-P01",
            "Rule 2(1)(g)(i)-(ii)",
            "2005-07-01",
            "str_obligation",
            """Rule 2(1)(g) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            defines a 'suspicious transaction' as a transaction referred to in clause (h), including an
            attempted transaction, whether or not made in cash, which to a person acting in good faith
            gives rise to a reasonable ground of suspicion that it may involve proceeds of an offence
            specified in the Schedule to the Act, regardless of the value involved, or appears to be made
            in circumstances of unusual or unjustified complexity. Crucially, the definition carries zero
            minimum monetary threshold: even modest-value multi-hop layering or attempted pass-through
            transfers qualify for STR evaluation when complexity lacks legitimate economic basis.""",
        ),
        _pmlr(
            "PMLR-2005-R2-P02",
            "Rule 2(1)(g)(iii)-(iv)",
            "2005-07-01",
            "str_obligation",
            """Under sub-clauses (iii) and (iv) of Rule 2(1)(g) of the Prevention of Money-Laundering
            (Maintenance of Records) Rules, 2005, a transaction also constitutes a suspicious transaction
            if, to a person acting in good faith, it appears to have no economic rationale or bona fide
            purpose, or gives rise to a reasonable ground of suspicion that it may involve financing of
            activities relating to terrorism. In scatter-gather alert reviews, demonstrating the absence of
            economic rationale requires examining both suspicious topology (dispersion, intermediary
            skimming, rapid or staggered reconsolidation) and benign commercial hypotheses (registered
            marketplace escrow, corporate payroll, licensed chit pools, or verifiable charity relief) before
            concluding whether reasonable grounds of suspicion exist.""",
        ),
        _pmlr(
            "PMLR-2005-R2-P03",
            "Rule 2(1)(fa) & 2(1)(h)",
            "2013-08-27",
            "record_keeping",
            """Rule 2(1)(h) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            broadly defines a 'transaction' to include a purchase, sale, loan, pledge, gift, transfer,
            delivery, or the arrangement thereof, encompassing deposits, withdrawals, exchanges, credits,
            debits, electronic fund transfers, and opening of accounts. Rule 2(1)(fa) defines 'Non-Profit
            Organisation' for AML monitoring as any entity or organisation constituted for religious or
            charitable purposes referred to in Section 2(15) of the Income-tax Act, 1961 and registered as
            a trust, society, or Section 8 company. Understanding both definitions ensures electronic IMPS,
            NEFT, RTGS, and charitable trust pools fall squarely within reconstructable record obligations.""",
        ),
        # ---- PMLR 2005 Rule 3 (Maintenance of Records of Transactions) ----
        _pmlr(
            "PMLR-2005-R3-P01",
            "Rule 3(1)(A)-(B)",
            "2005-07-01",
            "structuring",
            """Rule 3(1)(A) and Rule 3(1)(B) of the Prevention of Money-Laundering (Maintenance of Records)
            Rules, 2005 require every reporting entity to maintain records of all cash transactions of the
            value of more than rupees ten lakhs (INR 10,00,000) or its equivalent in foreign currency, as
            well as all series of cash transactions integrally connected to each other which have been
            individually valued below rupees ten lakhs or its equivalent in foreign currency where such
            series of transactions have taken place within a month and the monthly aggregate exceeds ten
            lakh rupees. Splitting deposits or transfers into multiple tranches just below INR 10,00,000
            within a rolling monthly window is classic structuring requiring aggregation and review.""",
        ),
        _pmlr(
            "PMLR-2005-R3-P02",
            "Rule 3(1)(BA)",
            "2009-11-12",
            "ngo_monitoring",
            """Rule 3(1)(BA) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            requires reporting entities to maintain dedicated records of all transactions involving receipts
            by non-profit organisations of value more than rupees ten lakhs (INR 10,00,000), or its
            equivalent in foreign currency. When an alert involves a charitable trust, society, or NGO
            receiving pooled donations exceeding ten lakh rupees and disbursing funds to multiple regional
            accounts, investigators must verify active DARPAN portal registration, Section 80G status, and
            alignment with charitable relief activities while ensuring NPO Transaction Report (NTR) record
            obligations under Rule 3(1)(BA) are respected.""",
        ),
        _pmlr(
            "PMLR-2005-R3-P03",
            "Rule 3(1)(C)-(D)",
            "2005-07-01",
            "str_obligation",
            """Rule 3(1)(C) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            covers all cash transactions where forged or counterfeit currency notes or bank notes have been
            used as genuine or where any forgery of a valuable security or document has taken place. Rule
            3(1)(D) mandates record maintenance for all suspicious transactions—whether or not made in
            cash—and by way of deposits, credits, withdrawals, electronic transfers, remittances, or
            settlements, regardless of the transaction value. Consequently, non-cash electronic layering
            via NEFT, RTGS, or IMPS triggers Rule 3(1)(D) preservation and STR assessment even when zero
            physical cash enters the transaction network.""",
        ),
        _pmlr(
            "PMLR-2005-R3-P04",
            "Rule 3(1)(E)-(F)",
            "2013-08-27",
            "wire_transfers",
            """Rule 3(1)(E) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            mandates that reporting entities maintain records of all cross-border wire transfers of the
            value of more than five lakh rupees (INR 5,00,000) or its equivalent in foreign currency where
            either the origin or destination of the fund is in India. Rule 3(1)(F) extends mandatory record
            keeping to all purchase and sale by any person of immovable property valued at fifty lakh
            rupees (INR 50,00,000) or more that is registered by the reporting entity. Cross-border wire
            legs exceeding INR 5,00,000 must preserve complete originator and beneficiary identification to
            support both CBWTR filing and cross-bank fund-flow reconstruction.""",
        ),
        # ---- PMLR 2005 Rules 4 & 5 (Particulars & Maintenance Procedure) ----
        _pmlr(
            "PMLR-2005-R4-P01",
            "Rule 4",
            "2005-07-01",
            "record_keeping",
            """Rule 4 of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 specifies
            the mandatory particulars that every transaction record maintained under Rule 3 must contain:
            (a) the nature of the transactions, (b) the amount of the transaction and the currency in which
            it was denominated, (c) the date on which the transaction was conducted, and (d) the parties to
            the transaction. When reconstructing candidate fund-flow paths during an AML investigation,
            preserving exact Rule 4 fields—including exact INR Decimal amounts, payment channel, timestamps,
            and counterparty account identifiers—ensures every finding can be deterministically audited
            against core banking records without approximation.""",
        ),
        _pmlr(
            "PMLR-2005-R5-P01",
            "Rule 5",
            "2005-07-01",
            "record_keeping",
            """Rule 5 of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 directs
            that every reporting entity shall maintain information in respect of transactions with its
            client referred to in Rule 3 in accordance with the procedure and manner specified by its
            regulator, such as the Reserve Bank of India, from time to time. It further requires reporting
            entities to evolve an internal mechanism for maintaining such information in such form and at
            such intervals as specified, enabling rapid retrieval for internal audits, Principal Officer
            escalations, and regulatory calls by FIU-IND. Structured evidence registries with immutable IDs
            directly operationalize Rule 5 traceability.""",
        ),
        # ---- PMLR 2005 Rule 7 (Principal Officer & Procedure for Furnishing Info) ----
        _pmlr(
            "PMLR-2005-R7-P01",
            "Rule 7(1)-(2)",
            "2005-07-01",
            "principal_officer",
            """Rule 7(1) and Rule 7(2) of the Prevention of Money-Laundering (Maintenance of Records) Rules,
            2005 require every reporting entity to communicate to the Director, FIU-IND the name,
            designation, and address of its Principal Officer and Designated Director. The Principal Officer
            is statutorily designated to furnish the information referred to in Rule 3 to the Director,
            FIU-IND on the basis of information available with the reporting entity. Automated alert
            engines and AI investigation agents cannot independently submit STRs to FIU-IND; they function
            strictly as decision-support systems preparing evidence-grounded worksheets for review and
            formal sign-off by the compliance analyst and Principal Officer.""",
        ),
        _pmlr(
            "PMLR-2005-R7-P02",
            "Rule 7(3)-(4)",
            "2013-08-27",
            "principal_officer",
            """Rule 7(3) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 mandates
            that every reporting entity shall evolve an internal mechanism having regard to any guidelines
            issued by the Director, FIU-IND in consultation with its sectoral regulator, for detecting
            transactions referred to in Rule 3 and for furnishing information about such transactions in
            such form as may be directed. Rule 7(4) imposes a duty on every reporting entity, its
            Designated Director, officers, and employees to observe the procedure and manner of furnishing
            information specified by the Director. Documented alert triage protocols, dual-hypothesis
            analysis, and human approval gates fulfill Rule 7(3) governance expectations.""",
        ),
        # ---- PMLR 2005 Rule 8 (Timelines for Furnishing Information) ----
        _pmlr(
            "PMLR-2005-R8-P01",
            "Rule 8(1)",
            "2013-08-27",
            "filing_timeline",
            """Rule 8(1) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 sets the
            statutory reporting schedule for periodic threshold-based disclosures to FIU-IND. The Principal
            Officer of a reporting entity shall furnish the information in respect of transactions referred
            to in clauses (A), (B), (BA), (C), and (E) of sub-rule (1) of Rule 3—covering Cash Transaction
            Reports above INR 10 lakhs, integrally connected cash series, NPO receipts above INR 10 lakhs,
            counterfeit currency transactions, and Cross-Border Wire Transfers above INR 5 lakhs—every
            month to the Director, FIU-IND by the 15th day of the succeeding month.""",
        ),
        _pmlr(
            "PMLR-2005-R8-P02",
            "Rule 8(2) (Seven Working Days STR Timeline)",
            "2013-08-27",
            "filing_timeline",
            """Rule 8(2) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 governs
            the statutory deadline for filing Suspicious Transaction Reports (STRs). The Principal Officer
            of a reporting entity shall furnish the information referred to in clause (D) of sub-rule (1)
            of Rule 3 promptly in writing, or by fax or electronic mail, to the Director, FIU-IND not later
            than seven working days on being satisfied that the transaction is suspicious. The seven
            working-day clock begins upon the Principal Officer's satisfaction of reasonable grounds of
            suspicion following investigation, making timely alert triage, bounded replanning, and clear
            evidentiary packaging essential for statutory compliance.""",
        ),
        _pmlr(
            "PMLR-2005-R8-P03",
            "Rule 8(3)-(5) (Immovable Property & Prompt Furnishing)",
            "2013-08-27",
            "filing_timeline",
            """Sub-rules (3) through (5) of Rule 8 of the Prevention of Money-Laundering (Maintenance of
            Records) Rules, 2005 specify that immovable property transaction records under Rule 3(1)(F)
            must be furnished quarterly by the 15th day of the month succeeding the quarter, and reinforce
            that delayed internal investigation workflows cannot justify missing the seven working-day STR
            deadline once suspicion is established. Where an analyst lacks external inter-bank logs needed
            to resolve ambiguity, issuing a structured request for information prevents premature closure
            while preserving audit documentation of when sufficient evidence was assembled for the
            Principal Officer's satisfaction under Rule 8(2).""",
        ),
        # ---- PMLR 2005 Rule 9 (Client Due Diligence & Beneficial Ownership) ----
        _pmlr(
            "PMLR-2005-R9-P01",
            "Rule 9(1) & 9(1A) (CDD at Commencement & Ongoing)",
            "2013-08-27",
            "edd",
            """Rule 9(1) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 requires
            every reporting entity, at the commencement of an account-based relationship, to identify its
            clients, verify their identity, obtain information on the purpose and intended nature of the
            business relationship, and determine whether a client is acting on behalf of a beneficial
            owner. Reporting entities must also conduct Client Due Diligence for occasional transactions
            equal to or exceeding INR 50,000, international money transfers, or whenever there is a
            suspicion of money-laundering or doubts about the veracity or adequacy of previously obtained
            customer identification data.""",
        ),
        _pmlr(
            "PMLR-2005-R9-P02",
            "Rule 9(3)(a)-(b) (Beneficial Owner — Company & Partnership)",
            "2023-03-07",
            "shell_entities",
            """Rule 9(3) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005, as
            amended in March 2023, establishes the statutory thresholds for identifying the natural person
            Beneficial Owner (BO) behind legal entities. Where the client is a company, the beneficial
            owner is the natural person(s) who, acting alone or together or through one or more juridical
            persons, has a controlling ownership interest of more than 10 percent of the shares, capital,
            or profits of the company, or exercises control through other means. For partnership firms, the
            threshold is ownership of or entitlement to more than 10 percent of capital or profits (revised
            down from 15 percent in 2023). Identifying opaque corporate BOs is critical when assessing
            suspected shell entities.""",
        ),
        _pmlr(
            "PMLR-2005-R9-P03",
            "Rule 9(3)(c)-(f) (Beneficial Owner — Trusts & Senior Managing Official)",
            "2023-03-07",
            "ngo_monitoring",
            """Under Rule 9(3)(e) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            (as amended in 2023), where the client is a trust, identification of beneficial owners shall
            include identification of the author of the trust, the trustee, the beneficiaries with 10
            percent or more interest in the trust, and any other natural person exercising ultimate
            effective control over the trust through a chain of control or ownership. Where no natural
            person is identified through ownership thresholds, Rule 9(3)(d) directs reporting entities to
            identify the relevant natural person who holds the position of senior managing official. Trust
            and NGO accounts handling pooled relief disbursements require complete trustee and beneficiary
            verification.""",
        ),
        _pmlr(
            "PMLR-2005-R9-P04",
            "Rule 9(9A) (NPO DARPAN Portal Registration)",
            "2023-03-07",
            "ngo_monitoring",
            """Rule 9(9A) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005,
            introduced by the 2023 amendment, requires every banking company or financial institution to
            register the details of a client, in case of a client being a Non-Profit Organisation (NPO), on
            the DARPAN Portal of NITI Aayog, if not already registered, and maintain such registration
            records for a period of five years after the business relationship has ended or the account has
            been closed. During AML investigations of charitable trusts or NGOs exhibiting scatter-gather
            disbursements, verifying DARPAN and Section 80G credentials is a mandatory documentary step
            before assessing whether charitable payouts are benign.""",
        ),
        _pmlr(
            "PMLR-2005-R9-P05",
            "Rule 9(12) (Ongoing Due Diligence & Transaction Alignment)",
            "2013-08-27",
            "edd",
            """Rule 9(12) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            mandates that every reporting entity shall exercise ongoing due diligence with respect to the
            business relationship with every client and closely examine the transactions in order to ensure
            that they are consistent with their knowledge of the client, his business and risk profile, and
            where necessary, the source of funds. Ongoing due diligence requires comparing observed account
            credits and debits against declared annual income, occupation, commercial registration status,
            and historical counterparty cadence. Sharp deviations—such as a low-income individual routing
            multi-lakh business-like pass-through flows—trigger escalated review under Rule 9(12).""",
        ),
        _pmlr(
            "PMLR-2005-R9-P06",
            "Rule 9(14) & 9(15) (CKYCR & Risk-Based KYC Policy)",
            "2015-07-07",
            "risk_categorization",
            """Sub-rules (14) and (15) of Rule 9 of the Prevention of Money-Laundering (Maintenance of
            Records) Rules, 2005 require reporting entities to adopt regulator-prescribed KYC policies,
            upload KYC records to the Central KYC Records Registry (CKYCR), and apply risk-based
            verification proportionate to client risk categorization. Enhanced monitoring applies whenever
            a client's risk category is high, corporate ownership is layered, or transactions diverge from
            expected profile. Maintaining synchronized CKYCR and internal KYC records enables investigators
            to verify whether an account's KYC tier is current or requires immediate remediation via fresh
            Customer Due Diligence.""",
        ),
        # Additional focused PMLA / PMLR passages to ensure rich, distinct coverage across sub-topics
        _pmla(
            "PMLA-2002-S3-P05",
            "Section 3 (Layering vs Integration Stages)",
            "2005-07-01",
            "layering",
            """In operational AML typologies mapped to Section 3 of the Prevention of Money-Laundering Act,
            2002, concealment of proceeds of crime commonly unfolds through placement, layering, and
            integration. Scatter-gather networks exemplify the layering stage: a root account fragments a
            principal sum across several unrelated mule or intermediary accounts, sometimes across multiple
            tiers of four to five hops or staggered across fourteen to thirty days, before reconsolidating
            funds into a single beneficiary. Separating the financial origin from the ultimate recipient is
            a hallmark of concealment under Section 3, provided investigators first rule out legitimate
            commercial pooling or settlement mechanisms.""",
        ),
        _pmla(
            "PMLA-2002-S3-P06",
            "Section 3 & Scheduled Offences Predicate Boundary",
            "2005-07-01",
            "str_standard",
            """Although criminal prosecution under Section 3 of the Prevention of Money-Laundering Act, 2002
            ultimately depends on proceeds connected to a scheduled offence listed in the Schedule to the
            Act, reporting entities and bank compliance investigators are neither equipped nor expected to
            prove a predicate crime before escalating a Suspicious Transaction Report. Instead, bank
            investigations examine financial indicators—such as unexplained pass-through velocity,
            structured tranches below reporting thresholds, unverified shell counterparties, and commission
            skimming—and refer reasonable grounds of suspicion to FIU-IND so statutory enforcement agencies
            can investigate potential predicate links.""",
        ),
        _pmla(
            "PMLA-2002-S12-P06",
            "Section 12 (Multi-Channel Transaction Reconstruction)",
            "2013-02-15",
            "wire_transfers",
            """To satisfy the transaction reconstruction mandate of Section 12(1)(a) of the Prevention of
            Money-Laundering Act, 2002, banks must maintain linked records across all domestic and
            international payment rails, including RTGS, NEFT, IMPS, UPI, cheque clearing, and SWIFT wire
            transfers. When a transaction chain exits the reporting bank to an external correspondent bank
            and later re-enters or terminates off-book, internal transaction records cannot reconstruct the
            missing external leg. Under Section 12 reconstructability principles, investigators must flag
            external-bank visibility gaps explicitly as missing evidence and request inter-bank logs rather
            than extrapolating unobserved transfers.""",
        ),
        _pmla(
            "PMLA-2002-S12-P07",
            "Section 12 (Client & Beneficial Owner Audit Trail)",
            "2013-02-15",
            "commercial_verification",
            """Section 12(1)(e) of the Prevention of Money-Laundering Act, 2002 requires banks to retain
            verified identity records, business correspondence, and account files for all clients and
            beneficial owners. When evaluating whether a high-value scatter-gather flow represents
            legitimate commercial settlement—such as e-commerce seller payouts, wholesale trade settlements,
            or corporate payroll runs—investigators rely on retained corporate registration records (MCA
            CIN, GSTIN filings, PAN, board resolutions) and historical account correspondence. Absence of
            verifiable commercial registration records undermines a benign commercial hypothesis and
            prevents automatic closure of the alert.""",
        ),
        _pmla(
            "PMLA-2002-S12A-P03",
            "Section 12A (Evidentiary Readiness & Audit Defensibility)",
            "2013-02-15",
            "governance",
            """Because Section 12A of the Prevention of Money-Laundering Act, 2002 authorizes the Director,
            FIU-IND to demand underlying transaction logs, KYC files, EDD records, and supplementary
            analysis from any reporting entity, every disposition worksheet must be self-contained and
            audit-defensible. Each material assertion in an investigation report should cite immutable
            internal evidence identifiers (transaction IDs, KYC record IDs, commercial registry checks,
            reconstructed path IDs, and deterministic calculation IDs) together with the specific statutory
            provisions applied, ensuring seamless response to any subsequent Section 12A inquiry.""",
        ),
        _pmla(
            "PMLA-2002-S12AA-P04",
            "Section 12AA (Disproportionate Volume & Source of Funds)",
            "2019-08-01",
            "edd",
            """Enhanced Due Diligence under Section 12AA of the Prevention of Money-Laundering Act, 2002 is
            triggered whenever transaction patterns exhibit unusual complexity or value disproportionate to
            the client's verified financial position. For example, if a savings account holder with modest
            declared annual income suddenly orchestrates multi-lakh outbound transfers across unrelated
            counterparties without corresponding business registration or documented source of funds,
            Section 12AA requires examining the underlying financial position and source of wealth. Failing
            to corroborate source of funds bars benign clearance and supports escalation or formal
            information request.""",
        ),
        _pmla(
            "PMLA-2002-S12AA-P05",
            "Section 12AA (Ongoing Enhanced Monitoring After Alerts)",
            "2019-08-01",
            "edd",
            """Under Section 12AA(3) of the Prevention of Money-Laundering Act, 2002, when a client's
            specified transactions are assessed as suspicious or likely to involve proceeds of crime,
            reporting entities must intensify ongoing monitoring of the entire business relationship.
            Heightened monitoring includes lowering alert thresholds for future velocity spikes, reviewing
            new counterparties and beneficial owners, and periodically re-evaluating the client's risk
            categorization. Documenting recommended enhanced monitoring steps alongside an STR escalation
            or request-for-information disposition strengthens institutional compliance with Section 12AA(3).""",
        ),
        _pmlr(
            "PMLR-2005-R2-P04",
            "Rule 2(1)(g) (Good Faith Standard & Attempted Transactions)",
            "2005-07-01",
            "str_standard",
            """Rule 2(1)(g) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            anchors suspicious transaction determination in the objective standard of 'a person acting in
            good faith' forming a 'reasonable ground of suspicion.' Good-faith assessment requires weighing
            both inculpatory anomalies and exculpatory commercial evidence impartially without confirmation
            bias. Moreover, Rule 2(1)(g) explicitly captures attempted transactions: even if a customer
            aborts a suspicious layered transfer after being asked for supporting invoices or source-of-funds
            documentation, the attempted transaction remains reportable as an STR to FIU-IND.""",
        ),
        _pmlr(
            "PMLR-2005-R3-P05",
            "Rule 3(1)(B) (Integrally Connected Cash Structuring)",
            "2005-07-01",
            "structuring",
            """Under Rule 3(1)(B) of the Prevention of Money-Laundering (Maintenance of Records) Rules,
            2005, reporting entities must aggregate cash transactions that are integrally connected and
            individually placed below INR 10,00,000 whenever their monthly aggregate crosses the ten-lakh
            threshold. Common structuring indicators include multiple cash deposits of INR 9,00,000 to
            INR 9,90,000 across consecutive days, coordinated deposits into multiple related accounts, or
            split cash withdrawals immediately converted into electronic transfers. Deliberate evasion of
            the Rule 3(1)(A) CTR threshold also independently triggers Rule 3(1)(D) STR scrutiny.""",
        ),
        _pmlr(
            "PMLR-2005-R3-P06",
            "Rule 3(1)(D) (Non-Cash Electronic Layering & Mule Accounts)",
            "2005-07-01",
            "layering",
            """Rule 3(1)(D) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 makes
            clear that suspicious transaction record-keeping and reporting apply equally whether or not the
            transactions are conducted in cash. Digital payment networks—such as rapid IMPS fan-out from a
            seed account into multiple personal savings accounts followed by RTGS or NEFT consolidation into
            a single beneficiary—fall squarely within Rule 3(1)(D). Because electronic pass-through schemes
            avoid cash-counter detection, graph-based path reconstruction and decimal conservation checks
            are vital for identifying suspicious non-cash layering.""",
        ),
        _pmlr(
            "PMLR-2005-R3-P07",
            "Rule 3(1)(E) (Cross-Border Wire Transfer Threshold)",
            "2013-08-27",
            "wire_transfers",
            """Rule 3(1)(E) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            requires reporting entities to record and report all cross-border wire transfers exceeding
            INR 5,00,000 (or foreign currency equivalent) where either origin or destination lies in India.
            When domestic scatter-gather consolidation feeds directly into an outward cross-border wire or
            originates from an inward foreign remittance above INR 5,00,000, analysts must verify complete
            originator, intermediary, and beneficiary details, check for trade invoice corroboration, and
            flag any missing correspondent leg information as an evidentiary deficiency.""",
        ),
        _pmlr(
            "PMLR-2005-R3-P08",
            "Rule 3(1)(BA) & (F) (High-Value NPO & Property Flows)",
            "2013-08-27",
            "ngo_monitoring",
            """Rule 3(1)(BA) and Rule 3(1)(F) of the Prevention of Money-Laundering (Maintenance of Records)
            Rules, 2005 target two sectors vulnerable to value layering: Non-Profit Organisation receipts
            above INR 10,00,000 and registered immovable property transactions of INR 50,00,000 or more.
            In AML alert investigations, rapid pass-through of pooled donations through an unregistered
            charitable trust or sudden multi-party consolidation purportedly for real-estate purchase
            without matching sale deeds or registered counterparties warrants Enhanced Due Diligence rather
            than routine benign closure.""",
        ),
        _pmlr(
            "PMLR-2005-R4-P02",
            "Rule 4 (Exact Decimal Amount & Counterparty Fidelity)",
            "2005-07-01",
            "decimal_math",
            """Rule 4 of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 mandates
            accurate recording of transaction amount, currency, date, nature, and transacting parties.
            Because regulatory reports and Principal Officer STR filings rely on exact INR figures,
            calculating cumulative outflows, consolidated inflows, fee retention differences, and retention
            percentages must be performed with exact decimal precision rather than floating-point
            approximations or mental estimates. Any discrepancy exceeding one paisa (INR 0.01) between
            narrative summaries and deterministic transaction totals undermines Rule 4 record fidelity.""",
        ),
        _pmlr(
            "PMLR-2005-R5-P02",
            "Rule 5 (Internal Mechanism & Reconstructable Audit Logs)",
            "2005-07-01",
            "governance",
            """Rule 5 of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 requires
            reporting entities to maintain internal mechanisms that preserve transaction information in
            prescribed regulator-approved formats. In modern AML investigation platforms, this entails
            immutable storage of alert payloads, read-only database query traces, deterministic graph
            calculation logs, verification results, and cryptographic human approval hashes. Separating
            untrusted external memo fields from trusted core ledger fields protects the integrity of Rule 5
            records against adversarial tampering or data poisoning.""",
        ),
        _pmlr(
            "PMLR-2005-R7-P03",
            "Rule 7 (Role of Principal Officer in Escalation Review)",
            "2013-08-27",
            "principal_officer",
            """Under Rule 7 of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005, the
            Principal Officer serves as the statutory decision-maker accountable for reviewing escalated
            alerts and submitting verified STRs to FIU-IND. To enable efficient Principal Officer review
            within the seven working-day window, analyst worksheets must present balanced competing
            hypotheses (suspicious vs benign), list exact supporting and contradicting evidence IDs, cite
            applicable PMLA/PMLR/RBI/FIU-IND provisions, and explicitly identify missing out-of-bank
            evidence that could alter the risk assessment.""",
        ),
        _pmlr(
            "PMLR-2005-R7-P04",
            "Rule 7(3) (Alignment with FIU-IND & Sectoral Guidelines)",
            "2013-08-27",
            "principal_officer",
            """Rule 7(3) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 directs
            every reporting entity to calibrate its internal transaction-monitoring and alert-detection
            mechanisms in accordance with guidelines issued by FIU-IND and sectoral regulators such as the
            Reserve Bank of India. Static, inflexible detection windows—for instance, scanning only a narrow
            seven-day window—can miss staggered layering schemes explicitly highlighted in FIU-IND red flag
            guidance. Bounded investigative replanning that expands time windows and hop depth when initial
            dispersal legs lack consolidation aligns internal detection mechanisms with Rule 7(3).""",
        ),
        _pmlr(
            "PMLR-2005-R8-P04",
            "Rule 8(2) (Distinguishing Escalation vs Request Info)",
            "2013-08-27",
            "incomplete_data",
            """Under Rule 8(2) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005,
            the seven working-day STR submission deadline is triggered once the Principal Officer is
            satisfied that a transaction is suspicious. When material evidentiary gaps exist—such as
            missing correspondent bank legs, expired KYC records, or unverified counterparty business
            relationships—analysts must promptly recommend requesting additional information rather than
            speculating or closing the alert prematurely. Once supplementary records arrive, the case is
            re-evaluated promptly so any confirmed suspicion is filed within seven working days.""",
        ),
        _pmlr(
            "PMLR-2005-R9-P07",
            "Rule 9(1) & 9(14) (Commercial Entity Identity Verification)",
            "2013-08-27",
            "commercial_verification",
            """Rule 9 of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 specifies
            distinct identity verification documents for legal entities—companies, partnership firms,
            trusts, and proprietorships—including Certificate of Incorporation, Memorandum and Articles of
            Association, PAN, GST registration, and board resolutions identifying authorized signatories.
            When an alert involves a purported commercial aggregator, payroll employer, or wholesale trader
            executing scatter-gather payments, confirming active statutory registration and corroborating
            recurring counterparty settlement history under Rule 9 is essential before concluding benign
            commercial activity.""",
        ),
        _pmlr(
            "PMLR-2005-R9-P08",
            "Rule 9 (Enhanced Checks for High-Risk & Shell Counterparties)",
            "2023-03-07",
            "shell_entities",
            """Under Rule 9 of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005,
            reporting entities must verify not only formal registration documents but also the substantive
            nature of the client's business and beneficial ownership. A newly incorporated or unregistered
            entity claiming wholesale trade or agency brokerage without active GST filings, valid MCA CIN,
            or historical supplier-buyer relationships displays classic shell-entity characteristics.
            Because forged or dormant registrations can be misused to mask mule networks, registration
            status must be corroborated against counterparty history length and transaction cadence.""",
        ),
        _pmlr(
            "PMLR-2005-R9-P09",
            "Rule 9 (PEP Identification & Enhanced Scrutiny)",
            "2013-08-27",
            "pep",
            """Rule 9 of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005, read with
            RBI KYC Master Directions, requires reporting entities to maintain risk management systems to
            determine whether a client or beneficial owner is a Politically Exposed Person (PEP). Where a
            PEP or close relative/associate is involved in high-value multi-hop transfers, reporting
            entities must obtain senior management approval for continuing the relationship, take
            reasonable measures to establish source of wealth and source of funds, and subject the account
            to heightened ongoing transaction monitoring.""",
        ),
        _pmlr(
            "PMLR-2005-R9-P10",
            "Rule 9 (Periodic KYC Refresh & Expired Credentials)",
            "2013-08-27",
            "periodic_updation",
            """Rule 9 of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005 mandates
            ongoing due diligence and periodic KYC updation to keep client identification and risk profiles
            accurate over time. Accounts carrying expired KYC documentation, minimal or small-account KYC
            tiers, or missing PAN verification that suddenly receive or disperse high-value inter-bank
            transfers represent a direct compliance breach. Investigators encountering expired or absent
            KYC records on key accounts in a fund-flow network must record the deficiency and require fresh
            Customer Due Diligence before any benign clearance.""",
        ),
        _pmlr(
            "PMLR-2005-R7-P05",
            "Rule 7 & Rule 8 (No Tipping Off During Information Requests)",
            "2013-08-27",
            "confidentiality",
            """When an investigation recommends requesting additional information—such as invoices, GST
            filings, commercial contracts, or source-of-funds explanations—compliance teams operating under
            Rules 7 and 8 of the PML (Maintenance of Records) Rules, 2005 and Section 12(2) of PMLA 2002
            must frame customer outreach strictly as routine KYC or transaction-monitoring verification.
            Staff must never reveal that an AML alert was triggered, that scatter-gather layering is
            suspected, or that an STR is under consideration for FIU-IND submission, preserving strict
            anti-tipping-off confidentiality throughout the inquiry.""",
        ),
        _pmlr(
            "PMLR-2005-R8-P05",
            "Rule 8 (Record of Non-Filing Decisions & Benign Closure)",
            "2013-08-27",
            "governance",
            """Although Rule 8 of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            requires furnishing STRs to FIU-IND within seven working days upon satisfaction of suspicion,
            supervisory best practice equally requires documenting the objective rationale whenever an
            escalated alert is closed as benign without filing an STR. A defensible benign closure record
            documents the active commercial registration verified, recurring counterparty settlement history,
            alignment with declared income and business profile, and the specific regulatory provisions
            supporting the non-suspicious determination.""",
        ),
        _pmlr(
            "PMLR-2005-R3-P09",
            "Rule 3 (Counterfeit & Document Forgery Indicators)",
            "2005-07-01",
            "shell_entities",
            """Rule 3(1)(C) of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            highlights forgery of valuable securities or documents alongside counterfeit currency as
            mandatory reportable events. In commercial AML investigations, discrepancies between a
            customer's claimed commercial registration (such as a mismatched GSTIN, invalid MCA CIN, or
            inconsistent trade name) and authoritative commercial registry lookup records raise acute
            concern of fabricated documentation. Such contradictions must never be dismissed as benign
            look-alikes and warrant immediate escalation or rigorous EDD verification.""",
        ),
        _pmlr(
            "PMLR-2005-R4-P03",
            "Rule 4 & Rule 5 (Inter-Bank Wire Metadata Preservation)",
            "2005-07-01",
            "wire_traceability",
            """Rules 4 and 5 of the Prevention of Money-Laundering (Maintenance of Records) Rules, 2005
            require preserving complete party identifiers, dates, amounts, and transaction nature across
            every electronic transfer record. When funds route across multiple Indian banks via RTGS, NEFT,
            or IMPS, retaining accurate remitter and beneficiary account numbers, IFSC codes, and unique
            transaction reference (UTR) numbers allows analysts to link outbound legs to inbound credits
            and promptly diagnose when an intermediate hop disappears into an external correspondent bank
            outside internal visibility.""",
        ),
    ]
    return items
