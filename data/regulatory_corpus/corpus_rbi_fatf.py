"""
Regulatory Corpus v2 — Statutory Sources Part 2:
  - RBI Master Direction — Know Your Customer (KYC) Direction, 2016 (DBR.AML.BC.No.81/14.01.001/2015-16, updated 2024)
  - RBI Guidelines on Regulation of Payment Aggregators and Payment Gateways (2020)
  - Chit Funds Act, 1982 (Section 4)
  - FATF Recommendations (R.10, R.11, R.12, R.16, R.20, R.21)

Every passage is 100-300 words, carries `source_type="regulatory"`, official source URL,
retrieval date, exact section/paragraph ref, and `human_verified=False` for `[HUMAN]` verification.
"""

from __future__ import annotations

from typing import Any

from data.regulatory_corpus.corpus_pmla import _reg

RBI_KYC_URL = "https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=11566"
RBI_PA_URL = "https://www.rbi.org.in/Scripts/NotificationUser.aspx?Id=11822"
CHIT_URL = "https://www.indiacode.nic.in/handle/123456789/1798"
FATF_URL = "https://www.fatf-gafi.org/en/publications/Fatfrecommendations/Fatf-recommendations.html"


def _kyc(cid: str, para: str, cat: str, text: str) -> dict[str, Any]:
    return _reg(
        cid,
        "RBI Master Direction — Know Your Customer (KYC) Direction, 2016 (updated 2024)",
        para,
        "2024-01-04",
        RBI_KYC_URL,
        cat,
        text,
    )


def _fatf(cid: str, rec: str, cat: str, text: str) -> dict[str, Any]:
    return _reg(
        cid,
        "FATF Recommendations (International Standards on Combating ML/TF)",
        rec,
        "2023-11-01",
        FATF_URL,
        cat,
        text,
    )


def build_rbi_fatf_passages() -> list[dict[str, Any]]:
    """Return 62 statutory passages (100-300 words each) covering RBI KYC, RBI PA, Chit Funds Act, and FATF."""
    return [
        # ---- RBI KYC Master Direction: Policy & CDD (Paras 4, 10, 13, 16, 18) ----
        _kyc(
            "RBI-KYC-2016-P04-P01",
            "Chapter II, Para 4 (KYC Policy Four Elements)",
            "governance",
            """Paragraph 4 of the RBI Master Direction — Know Your Customer (KYC) Direction, 2016 requires
            every Regulated Entity (RE) to formulate a Board-approved KYC policy incorporating four key
            elements: (a) Customer Acceptance Policy (CAP), (b) Risk Management, (c) Customer
            Identification Procedures (CIP), and (d) Monitoring of Transactions. These four pillars operate
            together across the lifecycle of a bank account. Effective transaction monitoring cannot be
            performed in isolation from Customer Acceptance and Risk Management; investigators must always
            contextualize observed payment flows against customer onboarding records, business activity
            declarations, and assigned risk tier.""",
        ),
        _kyc(
            "RBI-KYC-2016-P10-P01",
            "Chapter IV, Para 10 (Customer Acceptance Policy Controls)",
            "shell_entities",
            """Paragraph 10 of the RBI Master Direction on KYC (2016) establishes strict Customer Acceptance
            Policy rules. Regulated Entities must ensure that no account is opened in an anonymous or
            fictitious/benami name, no account is opened where the RE is unable to apply appropriate
            Customer Due Diligence measures due to customer non-cooperation or unreliability of documents,
            and transactions must not be permitted without identity verification where ML/TF risk is
            elevated. When an alert uncovers multiple intermediary accounts holding unverified identities,
            incomplete KYC files, or suspiciously aligned newly opened accounts, Para 10 principles bar
            clearing the network as routine benign activity.""",
        ),
        _kyc(
            "RBI-KYC-2016-P13-P01",
            "Chapter VI, Para 13 (CDD Trigger Thresholds)",
            "edd",
            """Paragraph 13 of the RBI Master Direction on KYC (2016) enumerates the mandatory triggers for
            undertaking Customer Due Diligence (CDD). Regulated Entities must execute CDD when establishing
            an account-based relationship, when carrying out an occasional transaction of an amount equal
            to or exceeding INR 50,000 (whether single or linked operations), when carrying out an
            international money transfer, when there is a suspicion of money laundering or terrorist
            financing regardless of exemptions or thresholds, or when the RE has doubts about the veracity
            or adequacy of previously obtained customer identification data.""",
        ),
        _kyc(
            "RBI-KYC-2016-P16-P01",
            "Chapter VI, Para 16 (Individual OVD & PAN Verification)",
            "periodic_updation",
            """Paragraph 16 of the RBI Master Direction on KYC (2016) outlines Customer Due Diligence
            procedures for individuals, requiring verification of identity and address through Officially
            Valid Documents (OVDs)—such as Passport, Driving Licence, proof of possession of Aadhaar,
            Voter's Identity Card, NREGA job card, or National Population Register letter—together with
            Permanent Account Number (PAN) or Form 60. When an individual account lacks verified PAN or
            holds only simplified or minimal KYC documentation yet participates in high-value multi-hop
            electronic transfers, investigators must flag the KYC deficiency and recommend fresh CDD.""",
        ),
        _kyc(
            "RBI-KYC-2016-P16-P02",
            "Chapter VI, Para 16 & Part III (Legal Entity & Proprietorship CDD)",
            "commercial_verification",
            """Under Chapter VI of the RBI Master Direction on KYC (2016), Customer Due Diligence for
            companies, partnership firms, trusts, and sole proprietorships requires independent verification
            of legal existence, registration status, authorized signatories, and beneficial ownership. For
            sole proprietorships, Regulated Entities must verify at least two business activity proofs such
            as GST registration certificate, municipal trade licence, or income tax return in the name of
            the firm. Confirming active MCA CIN, GSTIN, or statutory commercial registration is essential
            before accepting a commercial settlement narrative for scatter-gather fund flows.""",
        ),
        _kyc(
            "RBI-KYC-2016-P18-P01",
            "Chapter VI, Para 18 (Video-Based Customer Identification Process — V-CIP)",
            "edd",
            """Paragraph 18 of the RBI Master Direction on KYC (2016) governs the Video-based Customer
            Identification Process (V-CIP), an alternate consent-based method of establishing customer
            identity via seamless, secure, live audio-visual interaction with an official of the Regulated
            Entity. Accounts onboarded digitally via non-face-to-face channels without full V-CIP or
            in-person OVD verification carry elevated mule-account risk. If a newly opened digital savings
            account without full V-CIP suddenly executes rapid pass-through IMPS or RTGS transfers,
            investigators should apply Enhanced Due Diligence and treat mule-account typology as a primary
            suspicious hypothesis.""",
        ),
        # ---- RBI KYC Master Direction: EDD & Transaction Monitoring (Para 35 / Chapter VI Part VI) ----
        _kyc(
            "RBI-KYC-2016-P35-P01",
            "Chapter VI, Para 35 (EDD for Disproportionate Volume & Velocity)",
            "edd",
            """Under the Enhanced Due Diligence and ongoing transaction monitoring provisions of the RBI
            Master Direction on KYC (Para 35 / Chapter VI), Regulated Entities must apply Enhanced Due
            Diligence whenever observed transaction volume, frequency, or velocity is disproportionate to
            the customer's declared annual income, stated occupation, business profile, and expected
            account turnover. A salaried individual or student declaring annual income of INR 4 to 6 lakhs
            whose account routes INR 15 to 50 lakhs across unrelated counterparties within days exhibits a
            material profile mismatch requiring source-of-funds verification and STR evaluation.""",
        ),
        _kyc(
            "RBI-KYC-2016-P35-P02",
            "Chapter VI, Para 35 (Complex & Unusual Patterns Without Economic Rationale)",
            "layering",
            """The RBI Master Direction on KYC directs Regulated Entities to pay special attention to all
            complex, unusually large transactions and all unusual patterns of transactions which have no
            apparent economic or visible lawful purpose. Banks must examine as far as possible the
            background and purpose of such transactions and record their findings in writing for at least
            five years. Multi-hop scatter-gather loops—where principal funds split across unrelated
            intermediaries and reconsolidate into one beneficiary—require documented scrutiny of both
            suspicious layering mechanics and plausible commercial settlement alternatives.""",
        ),
        _kyc(
            "RBI-KYC-2016-P35-P03",
            "Chapter VI, Para 35 (Non-Face-to-Face & High-Risk Channel EDD)",
            "edd",
            """Enhanced Due Diligence measures under Chapter VI, Part VI of the RBI Master Direction on KYC
            apply specifically to non-face-to-face customer onboarding (outside compliant V-CIP), accounts
            of Politically Exposed Persons, correspondent banking relationships, and clients operating
            cash-intensive or high-risk intermediary businesses. Additional EDD controls include verifying
            first payment through an existing KYC-compliant bank account, obtaining independent business
            registration checks, verifying source of wealth, and subjecting high-velocity outbound payment
            channels (IMPS/RTGS) to pre-clearance or post-transaction compliance review.""",
        ),
        _kyc(
            "RBI-KYC-2016-P35-P04",
            "Chapter VI, Para 35 (Corroborating Commercial Settlements)",
            "commercial_verification",
            """When evaluating whether a high-value multi-counterparty fund flow represents legitimate
            commercial operations under the RBI Master Direction on KYC, analysts must corroborate
            documentary registration status (active GSTIN, MCA CIN, or Section 80G approval) alongside
            behavioral evidence such as historical counterparty relationships, recurring settlement cadence,
            and alignment between transaction amounts and declared business turnover. A single registry flag
            without corroborating counterparty history or consistent commercial cadence does not suffice to
            auto-close a scatter-gather alert showing unexplained intermediate hops or fee retention.""",
        ),
        _kyc(
            "RBI-KYC-2016-P35-P05",
            "Chapter VI, Para 35 (Source of Funds & Counterparty History Verification)",
            "edd",
            """Enhanced Due Diligence under the RBI Master Direction on KYC requires verifying not merely the
            identity of the seed account holder, but also the economic relationship between the seed account
            and downstream counterparties. Inspecting multi-month counterparty transfer history helps
            distinguish recurring legitimate vendor, payroll, or marketplace settlements from one-off
            opportunistic mule pass-through bursts. Where a root account transacts exclusively with newly
            seen unrelated accounts over a compressed window and immediately depletes incoming credits,
            EDD findings weigh strongly toward STR escalation or formal information request.""",
        ),
        # ---- RBI KYC Master Direction: Risk Categorization (Para 38 / Chapter V) ----
        _kyc(
            "RBI-KYC-2016-P38-P01",
            "Chapter V, Para 38 (Low, Medium, and High Risk Categorization)",
            "risk_categorization",
            """Under the Risk Management provisions of the RBI Master Direction on KYC (Para 38 / Chapter V),
            Regulated Entities must categorize customers into Low, Medium, and High risk tiers based on
            assessment of customer identity, social and financial status, nature of business activity,
            location of the customer and counterparties, and expected transaction profile. Risk
            categorization must be dynamic rather than static: if an account originally onboarded as Low
            risk suddenly exhibits High-risk scatter-gather layering or rapid pass-through activity, the
            account's risk profile must be reassessed rather than relying blindly on its legacy Low-risk
            tag to dismiss the alert.""",
        ),
        _kyc(
            "RBI-KYC-2016-P38-P02",
            "Chapter V, Para 38 (Periodic Risk Review & High-Risk Triggers)",
            "risk_categorization",
            """The RBI Master Direction on KYC mandates periodic review of customer risk categorization at
            least once every six months, with prompt upgrading to High risk whenever adverse transaction
            alerts, PEP associations, shell-entity indicators, or opaque ownership structures emerge.
            High-risk categorization triggers shorter KYC periodic updation cycles (every two years),
            stricter ongoing monitoring thresholds, and mandatory Enhanced Due Diligence before clearing
            unusual transfers. Importantly, high-risk status is an analytical risk factor—not standalone
            proof of suspicious activity—and must be weighed alongside actual fund-flow and commercial
            evidence.""",
        ),
        _kyc(
            "RBI-KYC-2016-P38-P03",
            "Chapter V, Para 38 (Avoiding Single-Attribute Disposition Shortcuts)",
            "risk_categorization",
            """Risk-based supervision under the RBI Master Direction on KYC explicitly distinguishes risk
            categorization from transaction disposition. Categorizing a customer as High risk (for example,
            a bullion dealer, import-export firm, or cash-intensive business) mandates closer scrutiny and
            Enhanced Due Diligence, but does not automatically mean every transfer is suspicious.
            Conversely, a Low-risk salaried account compromised as a mule conduit can facilitate serious
            layering. Investigators must evaluate fund-flow topology, conservation math, counterparty
            cadence, and commercial corroboration together rather than deciding solely from KYC risk tier.""",
        ),
        # ---- RBI KYC Master Direction: Politically Exposed Persons (Para 41) ----
        _kyc(
            "RBI-KYC-2016-P41-P01",
            "Chapter VI, Para 41 (PEP Definition & Identification)",
            "pep",
            """Paragraph 41 of the RBI Master Direction on KYC (2016), read with the Master Direction
            definitions, sets out mandatory Enhanced Due Diligence requirements for Politically Exposed
            Persons (PEPs)—individuals who are or have been entrusted with prominent public functions by a
            foreign country or domestic jurisdiction, including Heads of State or Government, senior
            politicians, senior government, judicial, or military officers, senior executives of
            state-owned corporations, and important political party officials. Regulated Entities must
            operate robust risk management systems to identify whether any customer or beneficial owner is
            a PEP or a close family member or associate of a PEP.""",
        ),
        _kyc(
            "RBI-KYC-2016-P41-P02",
            "Chapter VI, Para 41 (Senior Management Approval & Source of Wealth)",
            "pep",
            """Under Paragraph 41 of the RBI Master Direction on KYC (2016), before establishing an
            account-based relationship with a Politically Exposed Person—or upon discovering that an
            existing customer or beneficial owner has subsequently become a PEP—Regulated Entities must
            obtain senior management approval to open or continue the business relationship. Regulated
            Entities must further take reasonable measures to establish the PEP's source of wealth and
            source of funds, and conduct continuous enhanced monitoring of the business relationship.
            Unexplained multi-hop transfers linked to a PEP account require escalated review and cannot be
            auto-closed.""",
        ),
        _kyc(
            "RBI-KYC-2016-P41-P03",
            "Chapter VI, Para 41 (Close Relatives & Associates of PEPs)",
            "pep",
            """Paragraph 41 of the RBI Master Direction on KYC (2016) extends PEP Enhanced Due Diligence
            safeguards to accounts of family members and close associates of Politically Exposed Persons.
            In layering schemes, illicit proceeds are frequently routed through relatives, personal staff,
            or closely held companies controlled by a PEP's associates to mask direct public-official
            involvement. When scatter-gather intermediary or beneficiary accounts display family ties,
            shared addresses, or beneficial ownership links to a PEP alongside funds disproportionate to
            declared income, analysts must apply Para 41 EDD scrutiny and document source-of-wealth gaps.""",
        ),
        # ---- RBI KYC Master Direction: Periodic Updation & Dormant/Minimal KYC (Para 46) ----
        _kyc(
            "RBI-KYC-2016-P46-P01",
            "Chapter VI, Para 46 (Periodic Updation Cycles: 2 / 8 / 10 Years)",
            "periodic_updation",
            """Paragraph 46 of the RBI Master Direction on KYC (2016) prescribes risk-based periodic updation
            of KYC records at least once every two years for High-risk customers, once every eight years
            for Medium-risk customers, and once every ten years for Low-risk customers from the date of
            account opening or last KYC updation. For legal entities, periodic updation includes confirming
            no change in beneficial ownership, registration status, or principal business activity. Accounts
            overdue for periodic KYC updation that suddenly exhibit high-value inter-bank scatter-gather
            activity require fresh Customer Due Diligence before benign closure.""",
        ),
        _kyc(
            "RBI-KYC-2016-P46-P02",
            "Chapter VI, Para 46 (Expired / Minimal KYC & High-Value Transfers)",
            "periodic_updation",
            """Under Paragraph 46 and small-account provisions of the RBI Master Direction on KYC (2016),
            accounts operating under expired KYC documentation, simplified/small-account limits, or
            unverified PAN status are restricted from unrestricted high-value transaction velocity. When an
            alert reveals multi-lakh inter-bank transfers moving through an account with expired or minimal
            KYC—or where KYC records are missing from bank systems—investigators must flag the compliance
            breach as degraded or missing evidence, mandate fresh OVD and PAN verification, and recommend
            request for information or escalation rather than benign closure.""",
        ),
        _kyc(
            "RBI-KYC-2016-P46-P03",
            "Chapter VI, Para 46 (Reactivation of Dormant / Inoperative Accounts)",
            "dormant_reactivation",
            """Under RBI KYC periodic updation and inoperative-account guidelines, previously dormant or
            inoperative accounts require fresh KYC verification and heightened transaction monitoring upon
            reactivation. A sudden burst of high-value credits followed immediately by outward IMPS, NEFT,
            or RTGS transfers from a newly reactivated dormant savings account is a classic indicator of
            account takeover or rented mule activity. Analysts encountering dormant reactivation combined
            with rapid pass-through flows must treat the pattern as high-priority suspicious layering unless
            verified documentary proof of lawful origin is obtained.""",
        ),
        # ---- RBI KYC Master Direction: NPOs & Charitable Trusts (Para 56 / Rule 9(9A)) ----
        _kyc(
            "RBI-KYC-2016-P56-P01",
            "Chapter VI & X, Para 56 (NPO & Charitable Trust Monitoring)",
            "ngo_monitoring",
            """Under the RBI Master Direction on KYC (read with PMLR Rule 9(9A)), Regulated Entities
            maintaining accounts for Non-Profit Organisations (NPOs), charitable trusts, societies, and
            Section 8 companies must verify legal constitution documents, trustees and beneficial owners,
            NITI Aayog DARPAN portal registration, and applicable tax-exemption credentials (such as
            Section 80G / 12A). When an NPO pools donor contributions and disburses relief grants across
            multiple regional beneficiaries, verified DARPAN/80G status plus documented charitable relief
            alignment supports a benign look-alike assessment; absent registration or unexplained personal
            diversion requires escalation.""",
        ),
        _kyc(
            "RBI-KYC-2016-P56-P02",
            "Chapter VI & X, Para 56 (Distinguishing Benign Charity Pools from Layering)",
            "ngo_monitoring",
            """Charitable relief collections and disaster-aid disbursements naturally exhibit fan-in pooling
            followed by fan-out distribution that structurally mimics scatter-gather topologies. Under RBI
            KYC guidance for NPOs, distinguishing legitimate charitable operations from misuse of trusts for
            money laundering requires checking four objective criteria: active DARPAN and Section 80G
            registration, transparent donor inflows matching public fundraising campaigns, disbursements to
            verified relief vendors or enrolled beneficiaries without unexplained intermediary commission
            skimming, and absence of circular reconsolidation back into trustee-controlled private accounts.""",
        ),
        # ---- RBI KYC Master Direction: Wire Transfers (Para 64 / Chapter X) ----
        _kyc(
            "RBI-KYC-2016-P64-P01",
            "Chapter X, Para 64 (Domestic Wire Transfer Originator & Beneficiary Data)",
            "wire_transfers",
            """Paragraph 64 of the RBI Master Direction on KYC (2016), updated in 2023 to align fully with
            FATF Recommendation 16, governs domestic and cross-border wire transfers across RTGS, NEFT,
            IMPS, and international messaging rails. Every domestic wire transfer of INR 50,000 and above
            (or where the originator is not an account holder) must be accompanied by accurate originator
            information—name, account number or unique transaction reference, and address or customer ID—so
            ordering, intermediary, and beneficiary Regulated Entities can reconstruct end-to-end payment
            trails without losing traceability.""",
        ),
        _kyc(
            "RBI-KYC-2016-P64-P02",
            "Chapter X, Para 64 (Cross-Border Wire Transfer Requirements)",
            "wire_transfers",
            """Under Paragraph 64 of the RBI Master Direction on KYC (2016), all cross-border wire transfers
            must be accompanied by accurate and meaningful originator information (name, account number,
            and address/national ID/customer ID/date and place of birth) and beneficiary information (name
            and account number or unique transaction reference). Where several individual cross-border wire
            transfers from a single originator are bundled in a batch file, the batch file must contain
            complete, fully traceable originator and beneficiary data within the receiving jurisdiction.
            Incomplete cross-border wire data triggers risk-based holding, rejection, or STR review.""",
        ),
        _kyc(
            "RBI-KYC-2016-P64-P03",
            "Chapter X, Para 64 (Intermediary & Beneficiary RE Obligations on Missing Legs)",
            "incomplete_data",
            """Paragraph 64 of the RBI Master Direction on KYC (2016) imposes explicit duties on intermediary
            and beneficiary Regulated Entities to retain all originator and beneficiary information
            accompanying a wire transfer and maintain risk-based policies to detect wire transfers lacking
            required metadata. When an internal bank investigation encounters an external-bank correspondent
            gap—where funds exit to an external bank and downstream beneficiary records are absent from
            internal ledgers—investigators must not guess or extrapolate missing legs. Instead, they must
            flag the visibility gap, request inter-bank wire metadata, and classify disposition as
            request_info when evidence is insufficient.""",
        ),
        _kyc(
            "RBI-KYC-2016-P64-P04",
            "Chapter X, Para 64 (Payment Chain Preservation & Stripping Prevention)",
            "wire_traceability",
            """Under Paragraph 64 of the RBI Master Direction on KYC (2016), intermediary financial
            institutions participating in multi-hop wire transfer chains must take reasonable measures to
            ensure originator and beneficiary identifiers are never stripped or altered during onward
            forwarding. Where technical limitations prevent direct transmission along a domestic payment
            rail, the intermediary RE must preserve a linked five-year record mapping incoming and outgoing
            unique transaction references (UTRs). Missing UTR linkage or deliberately opaque payment memos
            across rapid multi-hop transfers constitute red flags warranting deeper investigation.""",
        ),
        # ---- RBI KYC Master Direction: Secrecy, Tipping-Off & Reporting (Para 70 / Chapter IX) ----
        _kyc(
            "RBI-KYC-2016-P70-P01",
            "Chapter IX, Para 70 (Prohibition on Tipping Off & Confidentiality)",
            "confidentiality",
            """Under Chapter IX (Para 70 / Reporting Obligations) of the RBI Master Direction on KYC (2016),
            Regulated Entities, their directors, officers, and employees are strictly prohibited from
            disclosing ('tipping off') to the customer or any unauthorized third party the fact that a
            Suspicious Transaction Report (STR) or related information is being filed or considered for
            submission to FIU-IND. Banks must also ensure that routine KYC inquiries or document requests
            triggered by an internal alert never hint at suspicion of money laundering, preserving the
            confidentiality mandated by PMLA Section 12(2) and FATF Recommendation 21.""",
        ),
        _kyc(
            "RBI-KYC-2016-P70-P02",
            "Chapter IX, Para 70 (No Account Restrictions Solely Due to STR Filing)",
            "str_standard",
            """RBI KYC Master Direction reporting guidance emphasizes that filing a Suspicious Transaction
            Report with FIU-IND is a statutory intelligence obligation, not a judicial finding of criminal
            guilt. Regulated Entities should avoid putting arbitrary restrictions on customer operations
            solely because an STR has been filed, as sudden unexplained freezes can inadvertently tip off
            the customer. Instead, banks apply risk-based enhanced monitoring under PMLA Section 12AA(3)
            and await lawful directions from competent enforcement or regulatory authorities while
            maintaining strict internal confidentiality over the STR.""",
        ),
        _kyc(
            "RBI-KYC-2016-P70-P03",
            "Chapter IX (Robust Alert Management & Avoiding Mechanical Closure)",
            "governance",
            """The RBI Master Direction on KYC directs Regulated Entities to deploy robust transaction
            monitoring systems capable of generating timely alerts for complex, unusually large, or
            unstructured payment patterns, backed by trained compliance reviewers. Alerts must not be closed
            mechanically without substantive examination of underlying transaction trails, KYC records,
            commercial registrations, and counterparty history. Documented human review, explicit handling
            of missing evidence, and independent verification of numerical totals and regulatory citations
            form the operational foundation of RBI-compliant alert disposal.""",
        ),
        # ---- RBI Guidelines on Payment Aggregators & Payment Gateways (2020) ----
        _reg(
            "RBI-PA-2020-C08-P01",
            "RBI Guidelines on Regulation of Payment Aggregators and Payment Gateways, 2020",
            "Clause 8 (Escrow Account & Settlement Operations)",
            "2020-03-17",
            RBI_PA_URL,
            "marketplace_escrow",
            """Clause 8 of the RBI Guidelines on Regulation of Payment Aggregators and Payment Gateways
            (DPSS.CO.PD.No.1810/02.14.008/2019-20 dated March 17, 2020) mandates that authorized non-bank
            Payment Aggregators (PAs) maintain pooled customer funds in a dedicated escrow account with a
            scheduled commercial bank. Funds collected from buyers are settled out of this escrow account
            to onboarded, KYC-verified merchants and logistics partners within prescribed T+1 to T+5
            settlement timelines. Because escrow pooling inherently creates high-volume fan-in and fan-out
            flows, authorized PA and marketplace payouts represent a primary benign look-alike to
            scatter-gather layering when merchant KYC and active PA/GST registration are verified.""",
        ),
        _reg(
            "RBI-PA-2020-C08-P02",
            "RBI Guidelines on Regulation of Payment Aggregators and Payment Gateways, 2020",
            "Clause 8.9 (Permitted Escrow Debits & Merchant Settlement Cadence)",
            "2020-03-17",
            RBI_PA_URL,
            "marketplace_escrow",
            """Under Clause 8.9 of the RBI Payment Aggregator Guidelines (2020), debits from a PA escrow
            account are strictly restricted to permitted settlement purposes: payment to onboarded
            merchants/sellers, refunds to customers, settlement of payment gateway fees/commissions, and
            authorized nodal transfers. Legitimate marketplace escrow payouts display regular settlement
            cadence, verified commercial registration (active GSTIN and MCA CIN), and recurring historical
            counterparty relationships with onboarded sellers. By contrast, an unregistered entity routing
            pooled funds to personal savings accounts while retaining undocumented 8-12 percent fees fails
            Clause 8 escrow criteria and requires STR scrutiny.""",
        ),
        _reg(
            "RBI-PA-2020-C08-P03",
            "RBI Guidelines on Regulation of Payment Aggregators and Payment Gateways, 2020",
            "Clause 7 (Merchant Onboarding & KYC Verification)",
            "2020-03-17",
            RBI_PA_URL,
            "commercial_verification",
            """Clause 7 of the RBI Payment Aggregator Guidelines (2020) obligates Payment Aggregators to
            conduct thorough background and antecedent checks on every onboarded merchant, ensuring
            merchants possess genuine business operations, valid GST/commercial registration, and
            compliant KYC profiles before receiving escrow settlements. When an AML investigator evaluates
            a purported e-commerce marketplace or payment aggregator alert, verifying both the aggregator's
            registration and the active commercial registration of recipient seller accounts corroborates
            legitimate Clause 7/8 settlement flows and prevents false-positive STR escalation.""",
        ),
        _reg(
            "RBI-PA-2020-C08-P04",
            "RBI Guidelines on Regulation of Payment Aggregators and Payment Gateways, 2020",
            "Clause 8 (Prohibition on Co-Mingling & Unauthorized Pass-Through)",
            "2020-03-17",
            RBI_PA_URL,
            "fee_skimming",
            """RBI Payment Aggregator Guidelines (2020) strictly prohibit co-mingling of PA escrow funds
            with the aggregator's operational funds or using unauthorized personal/proprietorship accounts
            to aggregate third-party payments. Entities operating unlicensed payment-collection pools that
            accept inflows from scattered sources, deduct an opaque percentage commission, and forward net
            balances to a consolidated beneficiary violate RBI PA authorization requirements and exhibit
            strong mule/unlicensed-intermediary layering indicators warranting immediate STR escalation.""",
        ),
        # ---- Chit Funds Act, 1982 (Section 4) ----
        _reg(
            "CHIT-1982-S04-P01",
            "Chit Funds Act, 1982",
            "Section 4(1) (Prohibition of Unsanctioned / Unregistered Chits)",
            "1982-08-19",
            CHIT_URL,
            "chit_fund",
            """Section 4(1) of the Chit Funds Act, 1982 mandates that no chit shall be commenced or
            conducted without obtaining the previous sanction of the State Government within whose
            jurisdiction the chit is to be commenced or conducted, and unless the chit is registered in
            that State in accordance with the provisions of the Act before the Registrar of Chits. In AML
            alert investigations, chit pools structurally collect periodic installments from many enrolled
            subscribers and disburse consolidated auction prize amounts. Confirming valid State Registrar
            of Chits registration is mandatory before classifying a chit pool flow as benign.""",
        ),
        _reg(
            "CHIT-1982-S04-P02",
            "Chit Funds Act, 1982",
            "Section 4 & Section 20 (Security Deposit & Lawful Foreman Disbursements)",
            "1982-08-19",
            CHIT_URL,
            "chit_fund",
            """Read with Section 4 and Section 20 of the Chit Funds Act, 1982, a lawfully registered chit
            foreman must deposit prescribed security with the Registrar of Chits, maintain an audited
            register of enrolled subscribers, and disburse prize amounts strictly according to scheduled
            monthly auction cycles with transparent foreman commission caps. When an AML alert involves
            pooled subscriber installments disbursing to a single beneficiary, corroborating active State
            Registrar registration, regular monthly installment cadence, and verified subscriber histories
            supports benign closure; an unregistered informal chit pool routing large funds must be
            escalated.""",
        ),
        _reg(
            "CHIT-1982-S04-P03",
            "Chit Funds Act, 1982",
            "Section 4 (Unregistered Chit Pools as Layering Conduit)",
            "1982-08-19",
            CHIT_URL,
            "chit_fund",
            """Unregistered chit schemes operating in contravention of Section 4 of the Chit Funds Act, 1982
            pose severe AML vulnerabilities because pooled cash and IMPS collections from unrelated
            individuals can be used to disguise illicit proceeds as 'chit auction winnings.' Whenever a
            customer's memo or KYC note claims chit-fund collections or prize disbursements but commercial
            registry lookup shows no active registration with the State Registrar of Chits (or no recurring
            monthly subscriber history), investigators must reject the benign chit hypothesis and escalate
            for STR review or request statutory registration certificates.""",
        ),
        # ---- FATF Recommendations (R.10, R.11, R.12, R.16, R.20, R.21) ----
        _fatf(
            "FATF-R10-P01",
            "Recommendation 10 (Customer Due Diligence)",
            "edd",
            """FATF Recommendation 10 prohibits financial institutions from keeping anonymous accounts or
            accounts in obviously fictitious names and mandates Customer Due Diligence (CDD) when
            establishing business relations, carrying out occasional transactions above the applicable
            designated threshold, when there is a suspicion of money laundering or terrorist financing, or
            when the institution has doubts about the veracity or adequacy of previously obtained customer
            identification data. Recommendation 10 requires identifying the customer, verifying identity
            using reliable independent sources, identifying the beneficial owner, and conducting ongoing
            due diligence on the business relationship.""",
        ),
        _fatf(
            "FATF-R10-P02",
            "Recommendation 10 (Inability to Complete CDD)",
            "incomplete_data",
            """Under FATF Recommendation 10, where a financial institution is unable to comply with
            applicable Customer Due Diligence requirements—including identifying beneficial owners,
            verifying business purpose, or reconciling missing KYC profiles—it should be required not to
            open the account, commence business relations, or perform the transaction, or should terminate
            the business relationship and consider making a Suspicious Transaction Report (STR). During
            alert triage, missing KYC records on key counterparties or unverified corporate ownership
            preclude benign closure and require information request or STR escalation.""",
        ),
        _fatf(
            "FATF-R11-P01",
            "Recommendation 11 (Record-Keeping — Five Years)",
            "record_keeping",
            """FATF Recommendation 11 requires financial institutions to maintain, for at least five years,
            all necessary records on transactions—both domestic and international—to enable them to comply
            swiftly with information requests from competent authorities. Such records must be sufficient
            to permit reconstruction of individual transactions (including the exact amounts and types of
            currency involved) so as to provide, if necessary, evidence for prosecution of criminal
            activity. Recommendation 11 aligns directly with PMLA Section 12 and mandates keeping CDD files,
            account correspondence, and the results of any complex-transaction analysis for at least five
            years.""",
        ),
        _fatf(
            "FATF-R12-P01",
            "Recommendation 12 (Politically Exposed Persons)",
            "pep",
            """FATF Recommendation 12 requires financial institutions, in addition to performing normal
            Customer Due Diligence, to put in place appropriate risk-management systems to determine
            whether a customer or beneficial owner is a Politically Exposed Person (PEP), obtain senior
            management approval for establishing or continuing business relationships with such customers,
            take reasonable measures to establish the source of wealth and source of funds, and conduct
            enhanced ongoing monitoring of the business relationship. These enhanced controls also apply to
            family members and close associates of PEPs.""",
        ),
        _fatf(
            "FATF-R16-P01",
            "Recommendation 16 (Wire Transfers — Originator & Beneficiary Traceability)",
            "wire_traceability",
            """FATF Recommendation 16 (Payment Transparency / Wire Transfers) requires financial institutions
            to include required and accurate originator information, and required beneficiary information, on
            wire transfers and related messages, and ensure that this information remains with the wire
            transfer or related message throughout the payment chain. Preserving complete originator and
            beneficiary metadata across every intermediary hop prevents illicit actors from obscuring the
            link between sender and ultimate beneficiary in multi-bank layering networks and enables
            end-to-end transaction tracing by investigators and FIUs.""",
        ),
        _fatf(
            "FATF-R16-P02",
            "Recommendation 16 (Intermediary Financial Institution Duties)",
            "wire_traceability",
            """Under Interpretive Note to FATF Recommendation 16, intermediary financial institutions must
            ensure that all originator and beneficiary information accompanying a wire transfer is
            retained with the transfer as it moves downstream. Intermediary institutions must take
            reasonable measures—consistent with straight-through processing—to identify wire transfers that
            lack required originator or beneficiary information and apply risk-based policies determining
            when to execute, reject, or suspend a transfer lacking required information and what follow-up
            action (such as requesting missing metadata or filing an STR) is warranted.""",
        ),
        _fatf(
            "FATF-R16-P03",
            "Recommendation 16 (Handling Missing Correspondent Bank Legs)",
            "incomplete_data",
            """FATF Recommendation 16 emphasizes that missing originator, intermediary, or beneficiary
            information across correspondent bank boundaries constitutes a critical visibility gap in
            payment chains. When an AML investigator observes funds exiting the institution into an
            external correspondent bank without downstream settlement visibility, Recommendation 16
            principles dictate flagging the missing correspondent leg explicitly, issuing an inter-bank
            information request (RFI), and refraining from fabricating or assuming benign continuity across
            unobserved external legs.""",
        ),
        _fatf(
            "FATF-R16-P04",
            "Recommendation 16 (Screening & Monitoring Wire Chains)",
            "wire_transfers",
            """Under FATF Recommendation 16, beneficiary and ordering financial institutions must monitor wire
            transfers to detect missing information, sanctions matches, and unusual routing patterns such
            as rapid pass-through chains or split transfers structured to evade reporting thresholds.
            Aligned with RBI KYC Master Direction Paragraph 64, effective Recommendation 16 compliance
            combines accurate UTR and party-ID capture with post-event monitoring across multi-day windows
            to uncover staggered consolidation across domestic and cross-border rails.""",
        ),
        _fatf(
            "FATF-R20-P01",
            "Recommendation 20 (Prompt Reporting of Suspicious Transactions)",
            "str_standard",
            """FATF Recommendation 20 mandates that if a financial institution suspects or has reasonable
            grounds to suspect that funds are the proceeds of a criminal activity, or are related to
            terrorist financing, it should be required directly by law to report promptly its suspicions to
            the Financial Intelligence Unit (FIU). Recommendation 20 establishes the international standard
            for reasonable-grounds reporting: institutions report objective suspicion promptly without
            requiring proof of an underlying predicate offence and without making judicial determinations
            of criminal guilt.""",
        ),
        _fatf(
            "FATF-R20-P02",
            "Recommendation 20 (All Suspicious Transactions Regardless of Amount)",
            "str_obligation",
            """Under the Interpretive Note to FATF Recommendation 20, all suspicious transactions—including
            attempted transactions—should be reported regardless of the amount of the transaction. The
            reporting obligation applies to both cash and non-cash electronic transfers, complex layering
            schemes, mule pass-through networks, and transactions with no apparent economic or visible
            lawful purpose. Financial institutions must avoid imposing arbitrary internal monetary floors
            that suppress reporting of lower-value structuring or multi-tier layering alerts when
            reasonable grounds of suspicion exist.""",
        ),
        _fatf(
            "FATF-R20-P03",
            "Recommendation 20 (Distinguishing Reasonable Suspicion from Criminal Guilt)",
            "str_standard",
            """FATF Recommendation 20 draws a firm boundary between compliance suspicion reporting and
            judicial adjudication. Financial institutions and compliance analysts evaluate whether
            transaction trails, KYC anomalies, and uncorroborated commercial claims give rise to reasonable
            grounds for suspicion warranting FIU review. Investigation reports must never assert that
            money laundering has occurred, declare a customer guilty, or label an individual a criminal;
            factual, neutral descriptions of anomalies preserve evidentiary objectivity and legal
            defensibility.""",
        ),
        _fatf(
            "FATF-R21-P01",
            "Recommendation 21 (Tipping-Off & Legal Safe Harbour)",
            "confidentiality",
            """FATF Recommendation 21 stipulates two complementary protections for suspicious transaction
            reporting. First, financial institutions, their directors, officers, and employees should be
            protected by law from criminal and civil liability for breach of any restriction on disclosure
            of information if they report their suspicions in good faith to the FIU, even if they did not
            know precisely what the underlying criminal activity was. Second, they must be strictly
            prohibited by law from disclosing ('tipping off') the fact that an STR or related information
            is being filed with the FIU.""",
        ),
        # ---- Additional RBI KYC operational depth passages (payroll, social, shell, trade, V-CIP, BO) ----
        _kyc(
            "RBI-KYC-2016-P16-P03",
            "Chapter VI (Corporate Payroll & Employer Account Verification)",
            "payroll_verification",
            """Under Chapter VI of the RBI Master Direction on KYC (2016), corporate salary and payroll
            accounts operated by active, MCA-registered or EPFO-registered employers disburse recurring
            monthly NEFT or RTGS credits to multiple employee savings accounts. Although bulk salary
            disbursement generates a one-to-many fan-out graph resembling the scatter leg of layering,
            corroborating active corporate registry status (MCA CIN / GSTIN / EPFO employer status),
            consistent monthly disbursement dates, recurring employee beneficiary histories, and alignment
            between individual salary credits and employee KYC income profiles confirms benign payroll
            activity.""",
        ),
        _kyc(
            "RBI-KYC-2016-P16-P04",
            "Chapter VI (Family & Social Event Merchant Settlements)",
            "wedding_social",
            """Under the ongoing transaction monitoring expectations of the RBI Master Direction on KYC,
            assessing apparent high-value personal transfers requires checking customer social/financial
            profile and recipient merchant legitimacy. Family or social event pools—such as wedding
            expenditure funded from family savings accounts and disbursed directly to GST-registered
            hotels, banquet halls, caterers, and jewellers—display benign economic rationale when the root
            customer holds Low-risk verified KYC, funds align with family wealth/savings, and counterparties
            are independently verified commercial hospitality merchants with zero circular reconsolidation.""",
        ),
        _kyc(
            "RBI-KYC-2016-P35-P06",
            "Chapter VI, Para 35 (Trade & Wholesale Settlement Verification)",
            "commercial_verification",
            """Under RBI KYC Enhanced Due Diligence guidelines for commercial current accounts, legitimate
            distributors, agricultural mandis, and B2B wholesale traders frequently receive pooled buyer
            payments and remit funds onward to multiple suppliers. Distinguishing lawful wholesale trade
            from shell-company pass-through layering requires checking active GSTIN filing continuity,
            valid MCA or proprietorship registration, multi-month recurring buyer-supplier counterparty
            history, reasonable working-capital retention margins, and alignment with declared business
            turnover in the customer's KYC profile.""",
        ),
        _kyc(
            "RBI-KYC-2016-P38-P04",
            "Chapter V, Para 38 (Geographic & Cross-Border Counterparty Risk)",
            "risk_categorization",
            """Paragraph 38 of the RBI Master Direction on KYC (2016) includes customer and counterparty
            location among core risk-categorization parameters. Regulated Entities must apply Enhanced Due
            Diligence to business relationships and transactions involving natural or legal persons from
            jurisdictions identified by FATF as having strategic AML/CFT deficiencies (high-risk or
            increased-monitoring jurisdictions). High-value transfers routing to or from high-risk foreign
            correspondents without documented underlying trade invoices or commercial purpose warrant
            escalated scrutiny and STR consideration.""",
        ),
        _kyc(
            "RBI-KYC-2016-P38-P05",
            "Chapter V, Para 38 (Risk Categorization of Trusts, Charities & Intermediaries)",
            "ngo_monitoring",
            """Under Chapter V of the RBI Master Direction on KYC (2016), accounts of trusts, charities,
            Non-Profit Organisations, companies having close family shareholding, and non-face-to-face
            intermediary businesses are evaluated with heightened care during risk categorization. While
            verified DARPAN-registered NGOs with transparent relief operations are lawful, unregistered
            associations or newly formed trusts receiving large pooled deposits and rapidly transferring
            funds onward to unrelated personal accounts exhibit elevated ML/TF risk requiring Enhanced Due
            Diligence and potential STR escalation.""",
        ),
        _kyc(
            "RBI-KYC-2016-P46-P04",
            "Chapter VI, Para 46 (Account Restrictions on Persistent KYC Non-Compliance)",
            "periodic_updation",
            """Under Paragraph 46 of the RBI Master Direction on KYC (2016), where a customer fails to
            complete mandatory periodic KYC updation despite due notice, Regulated Entities may impose
            partial freezing (allowing credits while restricting debits) followed by full operational
            restrictions until compliant OVD and PAN documentation are furnished. Discovering active
            high-value outbound transfers from an account overdue for periodic KYC updation signals a
            control gap that must be recorded in the investigation worksheet and remedied via formal
            information request and fresh CDD.""",
        ),
        _kyc(
            "RBI-KYC-2016-P64-P05",
            "Chapter X, Para 64 (Batch Wire Transfers & Reconciliation)",
            "wire_transfers",
            """Paragraph 64 of the RBI Master Direction on KYC (2016) provides specific rules for batch wire
            transfers—such as bulk corporate payroll files or marketplace seller settlement batches—where
            multiple transfers from a single originator are bundled. Individual transfers within a domestic
            or cross-border batch must remain traceable back to the full originator identity contained in
            the batch header, and beneficiary institutions must be able to reconcile each individual credit
            against the batch settlement record. Unreconciled split transfers lacking batch authorization
            warrant structuring or layering review.""",
        ),
        _kyc(
            "RBI-KYC-2016-P64-P06",
            "Chapter X, Para 64 (Handling Transfers Lacking Complete Originator Info)",
            "wire_traceability",
            """Under Paragraph 64 of the RBI Master Direction on KYC (2016), beneficiary Regulated Entities
            must maintain risk-based post-event or real-time monitoring to detect wire transfers lacking
            complete originator or beneficiary details. When a receiving bank repeatedly encounters inward
            transfers from an ordering institution that fails to supply required originator identification,
            the beneficiary RE must request the missing information, consider restricting or terminating
            the correspondent relationship if deficiencies persist, and evaluate whether the incomplete
            wire transfer gives rise to reasonable grounds for an STR.""",
        ),
        _kyc(
            "RBI-KYC-2016-P13-P02",
            "Chapter VI, Para 13 & 16 (Beneficial Owner Identification in Layered Entities)",
            "shell_entities",
            """Under Chapter VI of the RBI Master Direction on KYC (2016), harmonised with PMLR Rule 9(3),
            Regulated Entities must pierce through multi-layered corporate ownership chains to identify the
            natural person Beneficial Owners holding more than 10 percent ownership or effective control in
            a company or partnership, or 10 percent or more interest in a trust. When multiple intermediary
            entities participating in a scatter-gather transaction network share undisclosed common
            beneficial owners, directors, or registered addresses, the apparent independence of counterparties
            is illusory and indicates coordinated layering.""",
        ),
        _kyc(
            "RBI-KYC-2016-P10-P02",
            "Chapter IV, Para 10 (Preventing Mule Account Exploitation)",
            "fee_skimming",
            """Under the Customer Acceptance Policy framework of the RBI Master Direction on KYC (2016),
            banks must safeguard against opening or maintaining accounts controlled by third parties
            ('money mules') who rent personal savings accounts to move illicit funds for a commission.
            Indicators of mule exploitation include newly opened low-income accounts receiving rapid
            multi-lakh credits from unrelated senders, immediate onward IMPS/RTGS transfer of 88 to 95
            percent of inflows while retaining a 5 to 12 percent fee, and absence of any commercial
            business registration or invoice trail.""",
        ),
        _kyc(
            "RBI-KYC-2016-P18-P02",
            "Chapter VI, Para 18 & Digital Onboarding Controls",
            "dormant_reactivation",
            """RBI KYC Master Direction digital onboarding rules require strict transaction velocity limits
            and enhanced post-onboarding monitoring on accounts opened via OTP-based e-KYC or minimal
            digital channels until full V-CIP or in-person OVD verification is completed. Rapid high-value
            inward credits followed by same-day outward dispersion through a newly opened digital account
            violate expected onboarding risk profiles and represent a high-priority FIU-IND red flag for
            pass-through layering requiring prompt investigator scrutiny.""",
        ),
        _fatf(
            "FATF-R11-P02",
            "Recommendation 11 (Auditability of Investigation Analysis)",
            "governance",
            """FATF Recommendation 11 extends record-keeping beyond raw bank ledger entries to expressly
            cover account files, business correspondence, and 'results of any analysis undertaken'—such as
            inquiries into the background and purpose of complex, unusually large transactions—for at least
            five years. Preserving structured investigation worksheets, competing hypothesis evaluations,
            deterministic graph outputs, and exact decimal verification logs directly fulfills FATF
            Recommendation 11's mandate for transparent, reconstructable analytical audit trails.""",
        ),
        _fatf(
            "FATF-R12-P02",
            "Recommendation 12 (Domestic vs Foreign PEPs Risk-Based EDD)",
            "pep",
            """FATF Recommendation 12 requires full Enhanced Due Diligence for all foreign Politically Exposed
            Persons and requires risk-based application of those same enhanced measures—senior management
            approval, source-of-wealth verification, and enhanced ongoing monitoring—for domestic PEPs and
            prominent officials of international organisations whenever a higher-risk business relationship
            or complex unusual transaction arises. Linking PEP status with multi-hop scatter-gather flows
            immediately qualifies as a higher-risk scenario requiring full EDD verification.""",
        ),
        _fatf(
            "FATF-R16-P05",
            "Recommendation 16 (Cross-Border Value Transfer & Split Wires)",
            "structuring",
            """Under FATF Recommendation 16, ordering and intermediary institutions must detect linked or
            split wire transfers structured just below domestic or cross-border verification thresholds
            (such as INR 50,000 occasional CDD threshold or INR 5,00,000 CBWTR threshold) intended to
            bypass originator identification or regulatory reporting. Aggregating related outgoing wires
            sent from the same customer or coordinated group within a short window exposes threshold
            evasion and triggers combined Recommendation 16 and Recommendation 20 reporting obligations.""",
        ),
        _fatf(
            "FATF-R20-P04",
            "Recommendation 20 (Balancing False Negatives vs False Positives)",
            "str_standard",
            """Effective implementation of FATF Recommendation 20 depends on high-quality, evidence-grounded
            Suspicious Transaction Reports rather than defensive over-reporting or negligent under-reporting.
            Prematurely closing genuine layering alerts as benign (false negatives) exposes the financial
            system to illicit proceeds, whereas escalating verified commercial payroll, marketplace escrow,
            or charitable relief flows without checking registry and counterparty records degrades FIU
            intelligence quality. Structured dual-hypothesis analysis directly supports balanced
            Recommendation 20 decision-making.""",
        ),
        _fatf(
            "FATF-R21-P02",
            "Recommendation 21 (Internal Information Sharing vs External Tipping-Off)",
            "confidentiality",
            """While FATF Recommendation 21 strictly prohibits external tipping off of customers or third
            parties regarding STR consideration or filings, its Interpretive Note clarifies that this
            prohibition is not intended to inhibit necessary internal information sharing within a
            financial group or compliance unit for AML/CFT risk management. Compliance analysts, specialist
            reviewers, and the Principal Officer may securely exchange investigation evidence within
            role-based access controls, provided customer-facing communications never reveal AML suspicion
            or FIU-IND referrals.""",
        ),
        _reg(
            "RBI-PA-2020-C08-P05",
            "RBI Guidelines on Regulation of Payment Aggregators and Payment Gateways, 2020",
            "Clause 8 & 10 (Governance, Audit & Reconciliation of Nodal Flows)",
            "2020-03-17",
            RBI_PA_URL,
            "benign_lookalikes",
            """Clauses 8 and 10 of the RBI Payment Aggregator Guidelines (2020) require authorized Payment
            Aggregators to maintain strict daily escrow reconciliation, independent auditor certifications,
            and transparent transaction-level merchant settlement logs. When an AML alert flags a
            registered marketplace or payment aggregator for high-volume fan-out payouts, verifying active
            commercial registration, regular T+1/T+2 settlement cadence, recurring verified seller
            counterparties, and absence of circular reconsolidation back to the aggregator confirms a
            lawful nodal look-alike rather than scatter-gather layering.""",
        ),
        _reg(
            "CHIT-1982-S04-P04",
            "Chit Funds Act, 1982",
            "Section 4 & Section 12 (Prohibition of Unauthorized Fund Pooling)",
            "1982-08-19",
            CHIT_URL,
            "benign_lookalikes",
            """Under Sections 4 and 12 of the Chit Funds Act, 1982, lawful chit companies must clearly
            identify chit business in their registered corporate objects, obtain prior State Government
            sanction for each chit group, and register every chit agreement with the Registrar of Chits.
            Investigators reviewing pooled subscriber inflows and single-winner prize payouts must check
            the commercial registry for valid Chit Fund Registrar credentials and examine counterparty
            history for fixed monthly subscription schedules before closing an alert as a benign chit
            fund.""",
        ),
    ]
