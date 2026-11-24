"""
Noise transactions, realistic terse/verbose/Hinglish banking memos (zero label words),
decoy memos/notes, and 12-month counterparty payroll history helpers for Dataset v2.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
import random
from typing import Any

CHANNELS = ("NEFT", "RTGS", "IMPS", "UPI")

# Realistic Indian banking memos across 3 styles: NO label words ("layering", "mule", "shell",
# "laundering", "benign", "suspicious", "skimming", "staggered", "missing hop").
_TERSE_MEMOS = (
    "NEFT trf",
    "IMPS ref 8841",
    "RTGS settlement",
    "UPI/pay/ref",
    "a/c transfer",
    "bill adj",
    "trf agst inv",
    "party payment",
)

_VERBOSE_COMMERCIAL_MEMOS = (
    "Vendor invoice #INV-2026-441 settlement as per PO terms",
    "Monthly retainer & logistics reimbursement batch",
    "GST input trade advance against dispatch challan",
    "Quarterly dealer rebate & trade settlement credit",
    "Procurement advance for raw material lot #77B",
    "Staff stipend & contractor payout cycle",
    "Escrow disbursement against verified delivery receipt",
    "Cooperative member pool distribution installment",
)

_HINGLISH_MEMOS = (
    "party hisaab octmaal advance",
    "dukaan kiraya aur maal bhugtan",
    "vyapari khata adjustment",
    "karigar mazdoori mahina trf",
    "mandi bikri jama parchi",
    "godown bhaada aur transport kharcha",
    "kist jama samiti khata",
    "shaadi caterer advance token",
)

_NEUTRAL_KYC_NOTES = (
    "Standard video-KYC completed; PAN & address proof verified against CKYCR.",
    "Periodic KYC refresh logged at home branch; turnover declaration on file.",
    "Current account opened with board resolution and utility bill verification.",
    "Operating account with multi-city NEFT/IMPS activity; GST certificate uploaded at onboarding.",
    "Savings/business account; customer declared regional wholesale & service receipts.",
)

_BENIGN_SOUNDING_DECOY_NOTES = (
    "Customer submitted trade license & vendor invoice binder during branch review.",
    "Declared regional distribution & staffing disbursement operations across partner accounts.",
    "Regular GST return filer per onboarding dossier; seasonal volume spikes noted.",
)

_CAUTIOUS_SOUNDING_DECOY_NOTES = (
    "High multi-counterparty velocity flagged by branch; seasonal cash-flow spike under review.",
    "Frequent inter-bank outward transfers relative to prior quarter baseline.",
    "Unscheduled bulk disbursements across newly added beneficiaries; invoices requested.",
)


def pick_memo(rng: random.Random, style: str, *, decoy_mode: str = "none") -> str:
    """Pick a memo in `terse|verbose|hinglish` style without any ground-truth label words."""
    if decoy_mode == "benign_cover":
        return rng.choice(_VERBOSE_COMMERCIAL_MEMOS)
    if decoy_mode == "terse_ambiguous":
        return rng.choice(_TERSE_MEMOS + _HINGLISH_MEMOS)
    if style == "terse":
        return rng.choice(_TERSE_MEMOS)
    if style == "verbose":
        return rng.choice(_VERBOSE_COMMERCIAL_MEMOS)
    return rng.choice(_HINGLISH_MEMOS)


def pick_kyc_note(rng: random.Random, *, decoy: str = "neutral") -> str:
    if decoy == "benign_sounding":
        return rng.choice(_BENIGN_SOUNDING_DECOY_NOTES)
    if decoy == "cautious_sounding":
        return rng.choice(_CAUTIOUS_SOUNDING_DECOY_NOTES)
    return rng.choice(_NEUTRAL_KYC_NOTES)


def make_tx(
    rng: random.Random,
    tx_seq: list[int],
    case_tag: str,
    sender: str,
    receiver: str,
    amount: Decimal,
    anchor: datetime,
    offset_days: float,
    memo: str,
    channel: str | None = None,
) -> dict[str, Any]:
    tx_seq[0] += 1
    seconds = int(round(offset_days * 86400)) + rng.randint(60, 7200)
    ts = (anchor + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    amt_q = max(Decimal("100.00"), amount.quantize(Decimal("0.01")))
    return {
        "tx_id": f"TXN-{case_tag}-{tx_seq[0]:03d}",
        "sender_account": sender,
        "receiver_account": receiver,
        "amount_inr": str(amt_q),
        "timestamp": ts,
        "channel": channel or rng.choice(CHANNELS),
        "memo": memo,
    }


def make_kyc_record(
    rng: random.Random,
    account_id: str,
    entity_name: str,
    *,
    entity_type: str,
    risk_category: str,
    income_inr: str,
    registered: bool,
    registry_type: str | None,
    kyc_notes: str,
) -> dict[str, Any]:
    letters = "".join(rng.choices("ABCDEFGHJKLMNPQRSTUVWXYZ", k=5))
    digits = f"{rng.randint(1000, 9999)}"
    check = rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")
    return {
        "account_id": account_id,
        "customer_id": f"CUST-{account_id}",
        "entity_name": entity_name,
        "entity_type": entity_type,
        "pan": f"{letters}{digits}{check}",
        "risk_category": risk_category.lower(),
        "pep_flag": False,
        "sanctions_flag": False,
        "declared_annual_income_inr": str(Decimal(str(income_inr)).quantize(Decimal("0.01"))),
        "is_commercially_registered": registered,
        "registry_type": registry_type,
        "kyc_notes": kyc_notes,
    }


def add_background_noise(
    rng: random.Random,
    tx_seq: list[int],
    case_tag: str,
    root: str,
    core_accounts: list[str],
    anchor: datetime,
    style: str,
) -> tuple[list[str], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Generate 10..60 unrelated background transfers across noise accounts so every graph is realistic."""
    n_noise_tx = rng.randint(10, 60)
    n_noise_accs = rng.randint(4, 12)
    noise_accs = [f"ACC-{case_tag}-NS{i:02d}" for i in range(1, n_noise_accs + 1)]
    noise_kyc: dict[str, dict[str, Any]] = {}
    for acc in noise_accs:
        reg = rng.random() < 0.35
        noise_kyc[acc] = make_kyc_record(
            rng,
            acc,
            f"Counterparty-{acc[-6:]}",
            entity_type=rng.choice(("individual", "company", "partnership")),
            risk_category=rng.choice(("low", "medium")),
            income_inr=str(Decimal(rng.randint(400_000, 9_500_000))),
            registered=reg,
            registry_type="MERCHANT" if reg else None,
            kyc_notes=pick_kyc_note(rng),
        )

    txs: list[dict[str, Any]] = []
    pool = noise_accs + core_accounts[:2]
    for _ in range(n_noise_tx):
        s, r = rng.sample(pool, 2)
        # Ensure noise never accidentally forms a multi-hop bridge out of `root`
        if s == root:
            s = rng.choice(noise_accs)
        amt = Decimal(str(round(rng.uniform(2_500.0, 85_000.0), 2)))
        day_off = rng.uniform(-20.0, 12.0)
        txs.append(make_tx(rng, tx_seq, case_tag, s, r, amt, anchor, day_off, pick_memo(rng, style)))
    return noise_accs, txs, noise_kyc


def add_12m_payroll_history(
    rng: random.Random,
    tx_seq: list[int],
    case_tag: str,
    root: str,
    employees: list[str],
    per_emp_salary: Decimal,
    anchor: datetime,
) -> list[dict[str, Any]]:
    """Generate 11 prior monthly salary cycles (-330d..-30d) so `get_counterparty_history(days_back=365)` sees 12m."""
    hist: list[dict[str, Any]] = []
    for month_ago in range(1, 12):
        day_off = -30.0 * month_ago + rng.uniform(-1.0, 1.0)
        for emp in employees[:3]:
            jitter = Decimal(str(round(rng.uniform(0.98, 1.02), 4)))
            hist.append(
                make_tx(
                    rng,
                    tx_seq,
                    case_tag,
                    root,
                    emp,
                    (per_emp_salary * jitter).quantize(Decimal("0.01")),
                    anchor,
                    day_off,
                    pick_memo(rng, "hinglish"),
                    channel="NEFT",
                )
            )
    return hist
