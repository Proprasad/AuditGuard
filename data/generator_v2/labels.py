"""
Decoupled KYC attribute sampling, label-purity verification (<= 0.75 per single KYC field),
and structural graph fingerprinting (zero duplicate topologies).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from decimal import Decimal
import hashlib
import json
import random
from typing import Any

MAX_SINGLE_KYC_PURITY = 0.75

# Per-disposition independent sampling weights for root KYC fields so no single KYC attribute
# (nor simple combination) deterministically leaks the gold disposition.
_RISK_WEIGHTS: dict[str, tuple[tuple[str, float], ...]] = {
    "escalate_str": (("high", 0.42), ("medium", 0.36), ("low", 0.22)),
    "close_benign": (("low", 0.48), ("medium", 0.36), ("high", 0.16)),
    "request_info": (("medium", 0.40), ("high", 0.30), ("low", 0.30)),
}

_REGISTERED_PROB: dict[str, float] = {
    "escalate_str": 0.38,
    "close_benign": 0.66,
    "request_info": 0.50,
}

_ENTITY_WEIGHTS: dict[str, tuple[tuple[str, float], ...]] = {
    "escalate_str": (("individual", 0.44), ("company", 0.34), ("partnership", 0.14), ("trust", 0.08)),
    "close_benign": (("company", 0.42), ("individual", 0.28), ("trust", 0.16), ("partnership", 0.14)),
    "request_info": (("individual", 0.38), ("company", 0.36), ("partnership", 0.16), ("trust", 0.10)),
}

_REGISTRY_TYPES = ("MERCHANT", "MARKETPLACE", "EMPLOYER", "NGO_80G", "CHIT_FUND")


def _weighted_choice(rng: random.Random, items: tuple[tuple[str, float], ...]) -> str:
    r = rng.random()
    acc = 0.0
    for label, weight in items:
        acc += weight
        if r <= acc:
            return label
    return items[-1][0]


def sample_decoupled_root_kyc_attrs(
    rng: random.Random,
    gold_disposition: str,
    alert_amount: Decimal,
    *,
    force_registered: bool | None = None,
    force_risk: str | None = None,
    preferred_registry_type: str | None = None,
) -> dict[str, Any]:
    """Sample root KYC fields with realistic cross-class overlap so label purity stays <= 0.75."""
    risk = force_risk or _weighted_choice(rng, _RISK_WEIGHTS[gold_disposition])
    registered = (
        force_registered if force_registered is not None else (rng.random() < _REGISTERED_PROB[gold_disposition])
    )
    entity_type = _weighted_choice(rng, _ENTITY_WEIGHTS[gold_disposition])

    # Log-uniform income overlapping across dispositions (3.5L to 4.5Cr)
    income_mult = Decimal(str(round(10 ** rng.uniform(-0.45, 0.85), 4)))
    raw_income = (alert_amount * income_mult).quantize(Decimal("0.01"))
    income_inr = max(Decimal("350000.00"), min(Decimal("45000000.00"), raw_income))

    reg_type: str | None = None
    if registered:
        reg_type = preferred_registry_type or rng.choice(_REGISTRY_TYPES)
    return {
        "risk_category": risk,
        "is_commercially_registered": registered,
        "entity_type": entity_type,
        "declared_annual_income_inr": str(income_inr),
        "registry_type": reg_type,
    }


def _income_band(income_raw: Any) -> str:
    val = Decimal(str(income_raw))
    if val < Decimal("1000000"):
        return "lt_10L"
    if val < Decimal("5000000"):
        return "10L_to_50L"
    return "ge_50L"


def compute_single_kyc_purities(cases: list[dict[str, Any]]) -> dict[str, float]:
    """
    Compute weighted single-field majority-class purity (`sum_v max_y count(F=v, Y=y) / N`)
    for every root KYC attribute across `cases`.
    """
    if not cases:
        return {}
    extractors = {
        "risk_category": lambda k: str(k.get("risk_category", "missing")),
        "is_commercially_registered": lambda k: str(bool(k.get("is_commercially_registered", False))),
        "entity_type": lambda k: str(k.get("entity_type", "missing")),
        "income_band": lambda k: _income_band(k.get("declared_annual_income_inr", "0")),
    }
    purities: dict[str, float] = {}
    n = len(cases)
    for field_name, fn in extractors.items():
        buckets: dict[str, Counter[str]] = defaultdict(Counter)
        for c in cases:
            root = c["root_account"]
            root_kyc = (c.get("kyc_profiles") or {}).get(root, {})
            bucket_val = fn(root_kyc)
            buckets[bucket_val][str(c["gold_disposition"])] += 1
        correct_if_majority = sum(counter.most_common(1)[0][1] for counter in buckets.values())
        purities[field_name] = round(correct_if_majority / n, 4)
    return purities


def assert_kyc_purity_bounds(
    cases: list[dict[str, Any]], max_purity: float = MAX_SINGLE_KYC_PURITY
) -> dict[str, float]:
    purities = compute_single_kyc_purities(cases)
    violations = {k: v for k, v in purities.items() if v > max_purity}
    if violations:
        raise AssertionError(f"Single-KYC field label purity exceeded {max_purity:.2f}: {violations}")
    return purities


def structural_fingerprint(case: dict[str, Any]) -> str:
    """
    Canonical anonymised graph fingerprint of a case: node count, transaction count, sorted
    (out_degree, in_degree) sequence, channel histogram, and rounded relative day-offset sequence.
    """
    txs = case.get("transactions", [])
    out_deg: Counter[str] = Counter()
    in_deg: Counter[str] = Counter()
    channels: Counter[str] = Counter()
    amounts: list[str] = []
    for t in txs:
        s, r = str(t["sender_account"]), str(t["receiver_account"])
        out_deg[s] += 1
        in_deg[r] += 1
        channels[str(t.get("channel", ""))] += 1
        amounts.append(str(Decimal(str(t["amount_inr"])).quantize(Decimal("0.01"))))
    nodes = sorted(set(out_deg) | set(in_deg))
    deg_seq = sorted((out_deg[n], in_deg[n]) for n in nodes)
    payload = {
        "n_nodes": len(nodes),
        "n_tx": len(txs),
        "deg_seq": deg_seq,
        "channels": sorted(channels.items()),
        "amt_multiset": sorted(amounts),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def assert_unique_fingerprints(cases: list[dict[str, Any]]) -> None:
    seen: dict[str, str] = {}
    for c in cases:
        fp = structural_fingerprint(c)
        cid = str(c["case_id"])
        if fp in seen:
            raise AssertionError(f"Duplicate structural fingerprint between {seen[fp]} and {cid}")
        seen[fp] = cid
