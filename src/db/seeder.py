"""
Operational database seeder (`data/synthetic/dev/` + `data/synthetic/showcase/`).

Extracted from `src/db/database.py` so persistence DDL/connection management and synthetic fixture seeding stay
cleanly separated. Never reads `eval/held_out/` (enforcing strict held-out physical and DB isolation).
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path
from typing import Any, Optional

from src.core.canonical import loads_json, to_money

DEFAULT_SEED_INCOME = Decimal("500000.00")
_BANKS = ("BNK-HDFC", "BNK-ICIC", "BNK-SBIN", "BNK-AXIS")


def _money_str(value: Any) -> str:
    return str(to_money(str(value) if isinstance(value, float) else value))


def _collect_accounts(case: dict[str, Any]) -> list[str]:
    root_acc = str(case["root_account"])
    net_accs = list(case.get("network_accounts", []))
    txs = case.get("transactions", [])
    ordered: list[str] = []
    for acc in [root_acc, *net_accs, *[t["sender_account"] for t in txs], *[t["receiver_account"] for t in txs]]:
        if acc and acc not in ordered:
            ordered.append(str(acc))
    return ordered


def _assert_not_eval_case(case: dict[str, Any]) -> None:
    if case.get("is_held_out") or str(case.get("split", "")) in ("held_out", "challenge"):
        raise PermissionError(
            f"Refusing to load evaluation split case {case.get('case_id') or case.get('alert_id')} into runtime DB"
        )


def _upsert_account_and_kyc(conn: Any, idx: int, acc_id: str, kyc: dict[str, Any]) -> None:
    cust_id = str(kyc.get("customer_id") or f"CUST-{acc_id}")
    pan_raw = str(kyc.get("pan") or f"SYNTH-{acc_id}")
    pan_hash = hashlib.sha256(pan_raw.encode("utf-8")).hexdigest()
    risk = str(kyc.get("risk_category", "MEDIUM")).upper()
    if risk not in ("LOW", "MEDIUM", "HIGH"):
        risk = "MEDIUM"
    income = _money_str(kyc.get("declared_annual_income_inr", DEFAULT_SEED_INCOME))
    entity_type_raw = str(kyc.get("entity_type", "individual")).lower()
    occupation = str(kyc.get("occupation") or entity_type_raw)
    notes = str(kyc.get("kyc_notes", ""))

    conn.execute(
        "INSERT OR REPLACE INTO customers "
        "(customer_id, full_name, synthetic_pan_hash, kyc_tier, occupation, "
        "declared_annual_income_inr, risk_rating, onboarding_date, kyc_notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            cust_id,
            kyc.get("entity_name", f"Entity-{acc_id[-6:]}"),
            pan_hash,
            kyc.get("kyc_tier", "FULL"),
            occupation,
            income,
            risk,
            "2023-06-15",
            notes,
        ),
    )
    acc_type = "CURRENT" if entity_type_raw in ("company", "trust", "ngo") else "SAVINGS"
    conn.execute(
        "INSERT OR REPLACE INTO accounts (account_id, bank_id, customer_id, account_type, status, opened_date) "
        "VALUES (?, ?, ?, ?, 'ACTIVE', '2023-06-15')",
        (acc_id, _BANKS[idx % len(_BANKS)], cust_id, acc_type),
    )
    if kyc.get("is_commercially_registered"):
        reg_type = str(kyc.get("registry_type") or "MERCHANT").upper()
        if reg_type == "GST":
            reg_type = "MERCHANT"
        if reg_type not in ("MARKETPLACE", "EMPLOYER", "NGO_80G", "CHIT_FUND", "MERCHANT"):
            reg_type = "MERCHANT"
        conn.execute(
            "INSERT OR REPLACE INTO commercial_registry "
            "(registry_id, customer_id, entity_type, registration_number, status, registered_since) "
            "VALUES (?, ?, ?, ?, 'ACTIVE', '2022-04-01')",
            (f"REG-{acc_id}", cust_id, reg_type, f"SYNTH-REG-{acc_id}"),
        )


def upsert_case_into_db(conn: Any, case: dict[str, Any]) -> None:
    """Insert a dev synthetic case's customers, accounts, registry rows, transactions, and alert (never eval splits)."""
    _assert_not_eval_case(case)
    kyc_map = case.get("kyc_profiles", {})
    for idx, acc_id in enumerate(_collect_accounts(case)):
        _upsert_account_and_kyc(conn, idx, acc_id, dict(kyc_map.get(acc_id, {})))

    for tx in case.get("transactions", []):
        ch = str(tx.get("channel", "NEFT")).upper()
        if ch not in ("IMPS", "NEFT", "RTGS", "UPI"):
            ch = "NEFT"
        conn.execute(
            "INSERT OR REPLACE INTO transactions "
            "(txn_id, from_account_id, to_account_id, amount_inr, txn_timestamp, channel, memo_text) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                tx["tx_id"],
                tx["sender_account"],
                tx["receiver_account"],
                _money_str(tx["amount_inr"]),
                tx["timestamp"],
                ch,
                tx.get("memo") or tx.get("memo_text") or "",
            ),
        )

    conn.execute(
        "INSERT OR REPLACE INTO alerts "
        "(alert_id, seed_account_id, triggered_at, rule_triggered, initial_amount_inr, network_accounts_json, status) "
        "VALUES (?, ?, ?, ?, ?, ?, 'OPEN')",
        (
            case["alert_id"],
            case["root_account"],
            case["triggered_at"],
            case.get("rule_name", "SCATTER_GATHER"),
            _money_str(case["total_amount_inr"]),
            json.dumps(case.get("network_accounts", [])),
        ),
    )


def seed_from_directories(conn: Any, dev_dir: Optional[Path] = None) -> int:
    root_dir = Path(__file__).resolve().parents[2]
    eval_root = (root_dir / "eval").resolve()
    if dev_dir is not None and (dev_dir.resolve() == eval_root or eval_root in dev_dir.resolve().parents):
        raise PermissionError(f"Runtime seeder is forbidden from reading inside eval/: {dev_dir}")
    dirs = [dev_dir or (root_dir / "data" / "synthetic" / "dev"), root_dir / "data" / "synthetic" / "showcase"]
    count = 0
    for folder in dirs:
        if not folder.exists():
            continue
        for fp in sorted(folder.glob("*.json")):
            case = loads_json(fp.read_text(encoding="utf-8"))
            if case.get("is_held_out") or str(case.get("split", "")) in ("held_out", "challenge"):
                continue
            upsert_case_into_db(conn, case)
            count += 1
    return count
