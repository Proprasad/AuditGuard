"""
AuditGuard Synthetic Ambiguous Fund-Flow Generator (seed=42)

Generates the 60-case Golden Dataset across all 10 AML & Benign Look-Alike Categories:
  - 20 Development cases -> `data/synthetic/dev/` (seeded into operational DB, accessible to Reflexion)
  - 40 Held-Out cases    -> `eval/held_out/` (physically isolated from runtime code per Rule #4)

100% synthetic, zero real PII, exact Python Decimal amounts.
"""
from __future__ import annotations

import json
import random
import shutil
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

SEED = 42

CASE_CATEGORIES = [
    {"id": 1, "name": "clear_scatter_gather", "disposition": "escalate_str",
     "replan_required": False,
     "description": "Standard 7-day, 3-hop scatter-gather network with KYC income mismatch"},
    {"id": 2, "name": "staggered_timing", "disposition": "escalate_str",
     "replan_required": True,
     "description": "Consolidation on days 11-15; initial 7-day search misses leg -> requires replanning"},
    {"id": 3, "name": "fee_skimming", "disposition": "escalate_str",
     "replan_required": True,
     "description": "Intermediaries retain 8-12% fee cut on day 10; requires replanning window & tolerance"},
    {"id": 4, "name": "missing_hop", "disposition": "request_info",
     "replan_required": True,
     "description": "Intermediate external bank leg missing from records; must avoid guessing -> request_info"},
    {"id": 5, "name": "two_tier_layered", "disposition": "escalate_str",
     "replan_required": True,
     "description": "4-hop chain across two intermediary tiers on day 9; initial 7d/3-hop scan fails -> replan"},
    {"id": 6, "name": "marketplace_payout", "disposition": "close_benign",
     "replan_required": False,
     "description": "Structurally scatter-gather, but active GST marketplace + verified seller settlement cadence"},
    {"id": 7, "name": "charitable_donations", "disposition": "close_benign",
     "replan_required": False,
     "description": "Registered Section 80G NGO pooling donor contributions and disbursing relief"},
    {"id": 8, "name": "wedding_collection", "disposition": "close_benign",
     "replan_required": False,
     "description": "Low-risk family pool disbursing payments to GST-registered catering & venue merchants"},
    {"id": 9, "name": "salary_disbursement", "disposition": "close_benign",
     "replan_required": False,
     "description": "MCA-registered employer account running recurring monthly payroll disbursement"},
    {"id": 10, "name": "chit_fund", "disposition": "close_benign",
     "replan_required": False,
     "description": "Actively registered Chit Fund pooling recurring member contributions and prize payout"},
]


def _make_account_id(prefix: str, num: int) -> str:
    return f"ACC-{prefix}-{num:04d}"


def _tx(rng: random.Random, sender: str, receiver: str, amount_inr: float, anchor: datetime, offset_days: int, memo: str) -> dict[str, Any]:
    ts = (anchor + timedelta(days=offset_days, minutes=rng.randint(5, 180))).isoformat() + "Z"
    amt = float(Decimal(str(amount_inr)).quantize(Decimal("0.01")))
    return {
        "tx_id": f"TXN-{rng.randint(1000000, 9999999)}",
        "sender_account": sender,
        "receiver_account": receiver,
        "amount_inr": amt,
        "timestamp": ts,
        "channel": rng.choice(["NEFT", "RTGS", "IMPS", "UPI"]),
        "memo": memo,
    }


def _kyc(
    rng: random.Random,
    account_id: str,
    entity_name: str,
    entity_type: str = "individual",
    risk: str = "MEDIUM",
    income_inr: float = 500_000.0,
    registered: bool = False,
    registry_type: str | None = None,
    notes: str = "",
) -> dict[str, Any]:
    return {
        "account_id": account_id,
        "customer_id": f"CUST-{account_id}",
        "entity_name": entity_name,
        "entity_type": entity_type,
        "pan": f"ABCDE{rng.randint(1000, 9999)}F",
        "risk_category": risk.lower(),
        "pep_flag": False,
        "sanctions_flag": False,
        "declared_annual_income_inr": income_inr,
        "is_commercially_registered": registered,
        "registry_type": registry_type,
        "kyc_notes": notes,
    }


def generate_case(rng: random.Random, category: dict[str, Any], case_num: int, is_held_out: bool) -> dict[str, Any]:
    anchor = datetime(2026, 9, 1, 9, 0, 0)
    root = _make_account_id("ROOT", case_num * 10)
    intermediaries = [_make_account_id("INT", case_num * 10 + i) for i in range(1, 4)]
    destinations = [_make_account_id("DST", case_num * 10 + 7), _make_account_id("DST", case_num * 10 + 8)]

    base_amount = 900_000.00
    per_inter = 300_000.00
    alert_id = f"ALT-2026-{case_num:04d}"
    cat = category["name"]

    transactions: list[dict[str, Any]] = []
    kyc_profiles: dict[str, dict[str, Any]] = {}

    if cat == "clear_scatter_gather":
        for i, inter in enumerate(intermediaries):
            transactions.append(_tx(rng, root, inter, per_inter, anchor, offset_days=i, memo="Transfer"))
            transactions.append(_tx(rng, inter, destinations[i % 2], per_inter * 0.98, anchor, offset_days=3, memo="Consolidation"))
        kyc_profiles[root] = _kyc(rng, root, f"Trader-{case_num}", "individual", "HIGH", 420_000.0, False, None, "Unexplained high velocity")
        for inter in intermediaries + destinations:
            kyc_profiles[inter] = _kyc(rng, inter, f"Holder-{inter[-4:]}", "individual", "MEDIUM", 350_000.0, False)

    elif cat == "staggered_timing":
        # Scatter on days 0..1, staggered consolidation on days 11..13 (missed by 7-day C0 window!)
        for i, inter in enumerate(intermediaries):
            transactions.append(_tx(rng, root, inter, per_inter, anchor, offset_days=i % 2, memo="Advance"))
            transactions.append(_tx(rng, inter, destinations[0], per_inter * 0.97, anchor, offset_days=11 + i, memo="Delayed settlement"))
        kyc_profiles[root] = _kyc(rng, root, f"Consult-{case_num}", "individual", "HIGH", 450_000.0, False, None, "Staggered pass-through pattern")
        for inter in intermediaries + destinations:
            kyc_profiles[inter] = _kyc(rng, inter, f"Mule-{inter[-4:]}", "individual", "MEDIUM", 300_000.0, False)

    elif cat == "fee_skimming":
        # Scatter on day 0, consolidation retaining 8% fee on day 10 (INR 276,000 per leg = 828,000 total)
        for i, inter in enumerate(intermediaries):
            transactions.append(_tx(rng, root, inter, per_inter, anchor, offset_days=0, memo="Transfer"))
            transactions.append(_tx(rng, inter, destinations[0], 276_000.00, anchor, offset_days=10, memo="Net transfer"))
        kyc_profiles[root] = _kyc(rng, root, f"Agency-{case_num}", "individual", "HIGH", 400_000.0, False, None, "8% intermediary fee retention")
        for inter in intermediaries + destinations:
            kyc_profiles[inter] = _kyc(rng, inter, f"Agent-{inter[-4:]}", "individual", "MEDIUM", 310_000.0, False)

    elif cat == "missing_hop":
        # Outbound scatter only; downstream leg occurred across unindexed external bank (missing hop)
        for i, inter in enumerate(intermediaries):
            transactions.append(_tx(rng, root, inter, per_inter, anchor, offset_days=i, memo="External Nostro / Inter-bank gap"))
        kyc_profiles[root] = _kyc(rng, root, f"Exporter-{case_num}", "individual", "MEDIUM", 1_200_000.0, False, None, "Downstream correspondent bank statement pending")
        for inter in intermediaries:
            kyc_profiles[inter] = _kyc(rng, inter, f"ExtAcct-{inter[-4:]}", "individual", "MEDIUM", 600_000.0, False)

    elif cat == "two_tier_layered":
        # 4-hop two-tier network on day 9 (missed by max_hops=3 and window=7 in C0!)
        tier2 = [_make_account_id("T2A", case_num * 10 + 1), _make_account_id("T2B", case_num * 10 + 2)]
        tier3 = _make_account_id("T3A", case_num * 10 + 3)
        for i, inter in enumerate(intermediaries):
            transactions.append(_tx(rng, root, inter, per_inter, anchor, offset_days=0, memo="Layer 1"))
            transactions.append(_tx(rng, inter, tier2[i % 2], per_inter * 0.98, anchor, offset_days=4, memo="Layer 2"))
        transactions.append(_tx(rng, tier2[0], tier3, 580_000.00, anchor, offset_days=8, memo="Layer 3"))
        transactions.append(_tx(rng, tier3, destinations[0], 570_000.00, anchor, offset_days=10, memo="Final consolidation"))
        kyc_profiles[root] = _kyc(rng, root, f"ShellSource-{case_num}", "individual", "HIGH", 380_000.0, False, None, "Multi-tier layering")
        for acc in intermediaries + tier2 + [tier3] + destinations:
            kyc_profiles[acc] = _kyc(rng, acc, f"TierNode-{acc[-4:]}", "individual", "MEDIUM", 320_000.0, False)

    elif cat == "marketplace_payout":
        for i, seller in enumerate(intermediaries):
            transactions.append(_tx(rng, root, seller, per_inter, anchor, offset_days=0, memo="GST Marketplace weekly payout"))
        transactions.append(_tx(rng, intermediaries[0], destinations[0], 25_000.00, anchor, offset_days=1, memo="Logistics escrow fee"))
        kyc_profiles[root] = _kyc(rng, root, f"BazaarHub-{case_num} Pvt Ltd", "company", "LOW", 48_000_000.0, True, "MARKETPLACE", "Verified GST e-commerce marketplace; 24m recurring seller payouts")
        for s in intermediaries + destinations:
            kyc_profiles[s] = _kyc(rng, s, f"VerifiedMerchant-{s[-4:]}", "company", "LOW", 4_500_000.0, True, "MERCHANT")

    elif cat == "charitable_donations":
        for i, donor in enumerate(intermediaries):
            transactions.append(_tx(rng, donor, root, per_inter, anchor, offset_days=i, memo="Section 80G Flood Relief Donation"))
        transactions.append(_tx(rng, root, destinations[0], base_amount * 0.96, anchor, offset_days=4, memo="Verified relief supply vendor payout"))
        kyc_profiles[root] = _kyc(rng, root, f"SevaTrust-{case_num} Foundation", "trust", "LOW", 25_000_000.0, True, "NGO_80G", "Active Section 80G & CSR-1 registered charitable trust")
        for d in intermediaries:
            kyc_profiles[d] = _kyc(rng, d, f"Donor-{d[-4:]}", "individual", "LOW", 2_500_000.0, False)
        kyc_profiles[destinations[0]] = _kyc(rng, destinations[0], f"ReliefSupplies-{case_num}", "company", "LOW", 15_000_000.0, True, "MERCHANT")

    elif cat == "wedding_collection":
        # Low-risk family wedding escrow paying GST-registered hotel & catering merchants
        for i, vendor in enumerate(intermediaries):
            transactions.append(_tx(rng, root, vendor, per_inter, anchor, offset_days=1, memo="Wedding venue & catering invoice"))
        kyc_profiles[root] = _kyc(rng, root, f"SharmaFamilyWeddingEscrow-{case_num}", "individual", "LOW", 6_500_000.0, True, "MERCHANT", "Verified wedding vendor settlement with GST invoices on file")
        for v in intermediaries:
            kyc_profiles[v] = _kyc(rng, v, f"GrandBanquets-{v[-4:]} Pvt Ltd", "company", "LOW", 30_000_000.0, True, "MERCHANT")

    elif cat == "salary_disbursement":
        recipients = intermediaries + destinations
        salary = base_amount / len(recipients)
        for emp in recipients:
            transactions.append(_tx(rng, root, emp, salary, anchor, offset_days=0, memo="Monthly NEFT Salary Payroll"))
        kyc_profiles[root] = _kyc(rng, root, f"TechWorks-{case_num} Solutions Pvt Ltd", "company", "LOW", 95_000_000.0, True, "EMPLOYER", "MCA & EPFO registered employer; 36m monthly payroll cadence")
        for emp in recipients:
            kyc_profiles[emp] = _kyc(rng, emp, f"Employee-{emp[-4:]}", "individual", "LOW", 2_200_000.0, False)

    elif cat == "chit_fund":
        for i, member in enumerate(intermediaries):
            transactions.append(_tx(rng, member, root, per_inter, anchor, offset_days=0, memo="Monthly Chit Installment"))
        transactions.append(_tx(rng, root, destinations[0], base_amount * 0.95, anchor, offset_days=2, memo="Registered Chit Auction Prize Payout"))
        kyc_profiles[root] = _kyc(rng, root, f"SuvidhaChits-{case_num} Ltd", "company", "LOW", 40_000_000.0, True, "CHIT_FUND", "State Registrar of Chits active license under Chit Funds Act 1982")
        for m in intermediaries + destinations:
            kyc_profiles[m] = _kyc(rng, m, f"Subscriber-{m[-4:]}", "individual", "LOW", 1_800_000.0, False)

    return {
        "case_id": f"CASE-{case_num:04d}",
        "alert_id": alert_id,
        "category": cat,
        "category_id": category["id"],
        "expected_disposition": category["disposition"],
        "expected_replan_required": category["replan_required"],
        "description": category["description"],
        "is_held_out": is_held_out,
        "triggered_at": anchor.isoformat() + "Z",
        "root_account": root,
        "network_accounts": intermediaries + destinations,
        "total_amount_inr": base_amount,
        "transactions": transactions,
        "kyc_profiles": kyc_profiles,
    }


def generate_all_cases(
    dev_output_dir: str = "data/synthetic/dev",
    held_out_output_dir: str = "eval/held_out",
) -> dict[str, Any]:
    """
    Generate 60 reproducible cases:
      - 20 dev cases -> `data/synthetic/dev/`
      - 40 held-out cases -> `eval/held_out/` (isolated from runtime data/ folder)
    """
    rng = random.Random(SEED)
    dev_path = Path(dev_output_dir)
    held_path = Path(held_out_output_dir)

    # Clean legacy held_out inside data/synthetic if present to enforce strict isolation
    legacy_held = Path("data/synthetic/held_out")
    if legacy_held.exists():
        shutil.rmtree(legacy_held)

    dev_path.mkdir(parents=True, exist_ok=True)
    held_path.mkdir(parents=True, exist_ok=True)

    all_cases: list[dict[str, Any]] = []
    case_num = 1

    for cat in CASE_CATEGORIES:
        for split_idx in range(6):  # 2 dev + 4 held-out per category = 60 cases
            is_held_out = split_idx >= 2
            case = generate_case(rng, cat, case_num, is_held_out=is_held_out)
            all_cases.append(case)
            target_dir = held_path if is_held_out else dev_path
            (target_dir / f"{case['case_id']}.json").write_text(
                json.dumps(case, indent=2, default=str), encoding="utf-8"
            )
            case_num += 1

    summary = {
        "total": len(all_cases),
        "dev": sum(1 for c in all_cases if not c["is_held_out"]),
        "held_out": sum(1 for c in all_cases if c["is_held_out"]),
        "dev_dir": str(dev_path),
        "held_out_dir": str(held_path),
        "categories": {cat["name"]: cat["disposition"] for cat in CASE_CATEGORIES},
        "seed": SEED,
    }
    Path("data/synthetic").mkdir(parents=True, exist_ok=True)
    Path("data/synthetic/summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # Seed operational SQLite DB with dev cases + showcase alerts
    from src.db.database import seed_operational_db
    seeded = seed_operational_db(dev_path)

    print(f"Generated {summary['total']} cases ({summary['dev']} dev in {dev_path}, {summary['held_out']} held-out in {held_path})")
    print(f"Seeded {seeded} operational alerts into SQLite database.")
    return summary


if __name__ == "__main__":
    generate_all_cases()
