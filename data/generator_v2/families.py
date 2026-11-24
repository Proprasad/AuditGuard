"""
Parametric AML & Benign Look-Alike Family Builders (`docs/AGENT_GUIDE.md` §4 Phase 1.1–1.3).

Implements all 5 families and 18 sub-variants (including the 7 `⚑` held-out-only variants),
log-uniform INR amounts (2L–2Cr), 2–8 intermediaries, 1–4 destinations, continuous day offsets (1–28d),
0–15% fee skimming, 1–4 tiers, parallel edges, background noise, decoy memos/notes, and an independent
`registry_records` map so `check_commercial_registry` is genuinely decoupled from KYC flags.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
import math
import random
from typing import Any

from data.generator_v2.labels import sample_decoupled_root_kyc_attrs
from data.generator_v2.noise import (
    add_12m_payroll_history,
    add_background_noise,
    make_kyc_record,
    make_tx,
    pick_kyc_note,
    pick_memo,
)


@dataclass(frozen=True)
class VariantSpec:
    family: str
    family_group: str
    gold_disposition: str
    acceptable_dispositions: tuple[str, ...]
    held_out_only: bool
    default_difficulty: str
    adversarial_tags: tuple[str, ...] = ()


VARIANT_SPECS: tuple[VariantSpec, ...] = (
    # 1. Layering (escalate_str)
    VariantSpec("layering.classic", "layering", "escalate_str", ("escalate_str",), False, "easy"),
    VariantSpec("layering.staggered", "layering", "escalate_str", ("escalate_str",), False, "medium"),
    VariantSpec("layering.fee_skim", "layering", "escalate_str", ("escalate_str",), False, "medium"),
    VariantSpec("layering.two_tier", "layering", "escalate_str", ("escalate_str",), False, "hard"),
    VariantSpec("layering.three_tier_partial", "layering", "escalate_str", ("escalate_str",), True, "hard"),
    VariantSpec("layering.round_trip", "layering", "escalate_str", ("escalate_str",), True, "hard"),
    # 2. Layering with benign cover (escalate_str)
    VariantSpec(
        "layering_benign_cover.shell_valid_gst",
        "layering_benign_cover",
        "escalate_str",
        ("escalate_str",),
        False,
        "hard",
        ("forged_registry", "decoy_memo"),
    ),
    VariantSpec(
        "layering_benign_cover.decoy_memos",
        "layering_benign_cover",
        "escalate_str",
        ("escalate_str",),
        False,
        "hard",
        ("decoy_memo",),
    ),
    VariantSpec(
        "layering_benign_cover.all_registered_merchants",
        "layering_benign_cover",
        "escalate_str",
        ("escalate_str",),
        True,
        "hard",
        ("forged_registry", "all_registered_intermediaries", "decoy_memo"),
    ),
    # 3. Benign look-alike (close_benign)
    VariantSpec("benign_lookalike.marketplace", "benign_lookalike", "close_benign", ("close_benign",), False, "easy"),
    VariantSpec("benign_lookalike.ngo", "benign_lookalike", "close_benign", ("close_benign",), False, "easy"),
    VariantSpec("benign_lookalike.wedding", "benign_lookalike", "close_benign", ("close_benign",), False, "medium"),
    VariantSpec("benign_lookalike.payroll", "benign_lookalike", "close_benign", ("close_benign",), False, "easy"),
    VariantSpec("benign_lookalike.chit", "benign_lookalike", "close_benign", ("close_benign",), False, "medium"),
    VariantSpec(
        "benign_lookalike.unregistered_employer_12m_payroll",
        "benign_lookalike",
        "close_benign",
        ("close_benign",),
        False,
        "hard",
        ("unregistered_benign",),
    ),
    VariantSpec(
        "benign_lookalike.franchise_royalty_pooling",
        "benign_lookalike",
        "close_benign",
        ("close_benign",),
        True,
        "medium",
    ),
    VariantSpec(
        "benign_lookalike.cooperative_society_disbursal",
        "benign_lookalike",
        "close_benign",
        ("close_benign",),
        True,
        "medium",
    ),
    # 4. Incomplete data (request_info)
    VariantSpec("incomplete_data.missing_hop", "incomplete_data", "request_info", ("request_info",), False, "medium"),
    VariantSpec("incomplete_data.missing_kyc", "incomplete_data", "request_info", ("request_info",), False, "medium"),
    VariantSpec(
        "incomplete_data.stale_registry_expired",
        "incomplete_data",
        "request_info",
        ("request_info",),
        True,
        "hard",
        ("stale_registry",),
    ),
    VariantSpec(
        "incomplete_data.conflicting_kyc_vs_registry",
        "incomplete_data",
        "request_info",
        ("request_info",),
        True,
        "hard",
        ("conflicting_registry",),
    ),
    # 5. Ambiguous (acceptable = {escalate_str, request_info})
    VariantSpec(
        "ambiguous.benign_structure_high_risk_root",
        "ambiguous",
        "request_info",
        ("escalate_str", "request_info"),
        False,
        "hard",
        ("ambiguous_risk_signal",),
    ),
    VariantSpec(
        "ambiguous.benign_root_unexplained_leg",
        "ambiguous",
        "escalate_str",
        ("escalate_str", "request_info"),
        False,
        "hard",
        ("unexplained_leg", "decoy_memo"),
    ),
)

DEV_VARIANTS: tuple[VariantSpec, ...] = tuple(v for v in VARIANT_SPECS if not v.held_out_only)
HELD_OUT_ONLY_VARIANTS: tuple[VariantSpec, ...] = tuple(v for v in VARIANT_SPECS if v.held_out_only)


def _sample_log_uniform_inr(rng: random.Random) -> Decimal:
    # Log-uniform between INR 2,00,000 (2L) and INR 2,00,00,000 (2Cr)
    val = math.exp(rng.uniform(math.log(200_000.0), math.log(20_000_000.0)))
    return Decimal(str(round(val, 2))).quantize(Decimal("0.01"))


def _split_amount(rng: random.Random, total: Decimal, parts: int) -> list[Decimal]:
    weights = [rng.uniform(0.6, 1.6) for _ in range(parts)]
    w_sum = sum(weights)
    raw = [(total * Decimal(str(w / w_sum))).quantize(Decimal("0.01")) for w in weights[:-1]]
    remainder = (total - sum(raw, Decimal("0.00"))).quantize(Decimal("0.01"))
    if remainder <= Decimal("0.00"):
        even = (total / Decimal(parts)).quantize(Decimal("0.01"))
        raw = [even for _ in range(parts - 1)]
        remainder = total - sum(raw, Decimal("0.00"))
    return [*raw, remainder]


def _registry_entry(
    account_id: str,
    entity_name: str,
    *,
    registered: bool,
    reg_type: str | None,
    status: str = "ACTIVE",
    since: str = "2021-04-01",
) -> dict[str, Any]:
    if not registered and status == "NOT_FOUND":
        return {
            "evidence_id": f"REGISTRY-NONE-{account_id}",
            "account_id": account_id,
            "entity_name": entity_name,
            "is_registered": False,
            "registry_status": "NOT_FOUND",
        }
    return {
        "evidence_id": f"REGISTRY-{account_id}",
        "account_id": account_id,
        "entity_name": entity_name,
        "is_registered": status == "ACTIVE",
        "registry_type": reg_type or "MERCHANT",
        "registration_number": f"REGN-{account_id[-8:]}",
        "registry_status": status,
        "registered_since": since,
    }


def _layering_window_and_fee(rng: random.Random, family: str) -> tuple[float, Decimal]:
    if family == "layering.classic":
        return rng.uniform(1.0, 5.5), Decimal(str(round(rng.uniform(0.01, 0.06), 4)))
    if family == "layering.staggered":
        return rng.uniform(10.0, 26.0), Decimal(str(round(rng.uniform(0.01, 0.07), 4)))
    if family == "layering.fee_skim":
        return rng.uniform(8.0, 18.0), Decimal(str(round(rng.uniform(0.09, 0.145), 4)))
    return rng.uniform(4.0, 19.0), Decimal(str(round(rng.uniform(0.02, 0.11), 4)))


def _build_multitier_consolidation(
    rng: random.Random,
    spec: VariantSpec,
    tx_seq: list[int],
    case_tag: str,
    inters: list[str],
    shares: list[Decimal],
    dests: list[str],
    consol_day: float,
    fee: Decimal,
    anchor: datetime,
    style: str,
    decoy: str,
) -> tuple[list[dict[str, Any]], list[str], Decimal]:
    txs: list[dict[str, Any]] = []
    t2 = [f"ACC-{case_tag}-T2{i:02d}" for i in range(1, 3)]
    extra_nodes = list(t2)
    active_shares = shares if spec.family == "layering.two_tier" else shares[:-1]
    for idx, (inter, share) in enumerate(zip(inters[: len(active_shares)], active_shares, strict=True)):
        mid_amt = (share * (Decimal("1") - fee / Decimal("2"))).quantize(Decimal("0.01"))
        memo = pick_memo(rng, style, decoy_mode=decoy)
        txs.append(make_tx(rng, tx_seq, case_tag, inter, t2[idx % 2], mid_amt, anchor, consol_day * 0.45, memo))
    if spec.family == "layering.three_tier_partial":
        t3 = f"ACC-{case_tag}-T301"
        extra_nodes.append(t3)
        sum_t2 = sum(active_shares, Decimal("0.00")) * (Decimal("1") - fee)
        a1 = (sum_t2 * Decimal("0.60")).quantize(Decimal("0.01"))
        a2 = (sum_t2 * Decimal("0.40")).quantize(Decimal("0.01"))
        txs.append(
            make_tx(
                rng, tx_seq, case_tag, t2[0], t3, a1, anchor, consol_day * 0.75, pick_memo(rng, style, decoy_mode=decoy)
            )
        )
        txs.append(
            make_tx(
                rng, tx_seq, case_tag, t2[1], t3, a2, anchor, consol_day * 0.80, pick_memo(rng, style, decoy_mode=decoy)
            )
        )
        final_amt = (sum_t2 * Decimal("0.98")).quantize(Decimal("0.01"))
        txs.append(
            make_tx(
                rng,
                tx_seq,
                case_tag,
                t3,
                dests[0],
                final_amt,
                anchor,
                consol_day,
                pick_memo(rng, style, decoy_mode=decoy),
            )
        )
        return txs, extra_nodes, final_amt
    consolidated = Decimal("0.00")
    for idx, node2 in enumerate(t2):
        leg_sum = sum((s for j, s in enumerate(active_shares) if j % 2 == idx), Decimal("0.00"))
        out_amt = (leg_sum * (Decimal("1") - fee)).quantize(Decimal("0.01"))
        txs.append(
            make_tx(
                rng,
                tx_seq,
                case_tag,
                node2,
                dests[0],
                out_amt,
                anchor,
                consol_day,
                pick_memo(rng, style, decoy_mode=decoy),
            )
        )
        consolidated += out_amt
    return txs, extra_nodes, consolidated


def _build_layering_flows(
    rng: random.Random,
    spec: VariantSpec,
    tx_seq: list[int],
    case_tag: str,
    root: str,
    inters: list[str],
    dests: list[str],
    total: Decimal,
    anchor: datetime,
    style: str,
) -> tuple[list[dict[str, Any]], list[str], Decimal, bool]:
    txs: list[dict[str, Any]] = []
    decoy = "benign_cover" if spec.family_group == "layering_benign_cover" or rng.random() < 0.35 else "none"
    shares = _split_amount(rng, total, len(inters))
    consol_day, fee = _layering_window_and_fee(rng, spec.family)

    for idx, (inter, share) in enumerate(zip(inters, shares, strict=True)):
        if idx == 0 and rng.random() < 0.45:
            half1 = (share * Decimal("0.48")).quantize(Decimal("0.01"))
            half2 = (share - half1).quantize(Decimal("0.01"))
            m1 = pick_memo(rng, style, decoy_mode=decoy)
            txs.append(make_tx(rng, tx_seq, case_tag, root, inter, half1, anchor, rng.uniform(0.0, 0.6), m1))
            m2 = pick_memo(rng, style, decoy_mode=decoy)
            txs.append(make_tx(rng, tx_seq, case_tag, root, inter, half2, anchor, rng.uniform(0.7, 1.4), m2))
        else:
            m0 = pick_memo(rng, style, decoy_mode=decoy)
            txs.append(make_tx(rng, tx_seq, case_tag, root, inter, share, anchor, rng.uniform(0.0, 1.8), m0))

    if spec.family in ("layering.two_tier", "layering.three_tier_partial"):
        sub_txs, extra_nodes, consolidated = _build_multitier_consolidation(
            rng, spec, tx_seq, case_tag, inters, shares, dests, consol_day, fee, anchor, style, decoy
        )
        return [*txs, *sub_txs], extra_nodes, consolidated, True

    if spec.family == "layering.round_trip":
        hub = f"ACC-{case_tag}-HUB1"
        consolidated = Decimal("0.00")
        for inter, share in zip(inters, shares, strict=True):
            out_amt = (share * (Decimal("1") - fee)).quantize(Decimal("0.01"))
            mh = pick_memo(rng, style, decoy_mode=decoy)
            txs.append(make_tx(rng, tx_seq, case_tag, inter, hub, out_amt, anchor, consol_day * 0.6, mh))
            consolidated += out_amt
        ret_amt = (consolidated * Decimal("0.97")).quantize(Decimal("0.01"))
        txs.append(
            make_tx(
                rng,
                tx_seq,
                case_tag,
                hub,
                dests[0],
                ret_amt,
                anchor,
                consol_day,
                pick_memo(rng, style, decoy_mode=decoy),
            )
        )
        back_amt = (ret_amt * Decimal("0.85")).quantize(Decimal("0.01"))
        mb = pick_memo(rng, style, decoy_mode=decoy)
        txs.append(make_tx(rng, tx_seq, case_tag, dests[0], root, back_amt, anchor, consol_day + 1.5, mb))
        return txs, [hub], ret_amt, consol_day > 7.0 or fee > Decimal("0.10")

    consolidated = Decimal("0.00")
    for idx, (inter, share) in enumerate(zip(inters, shares, strict=True)):
        dst = dests[idx % len(dests)]
        out_amt = (share * (Decimal("1") - fee)).quantize(Decimal("0.01"))
        md = pick_memo(rng, style, decoy_mode=decoy)
        txs.append(make_tx(rng, tx_seq, case_tag, inter, dst, out_amt, anchor, consol_day + rng.uniform(0.0, 1.5), md))
        consolidated += out_amt
    return txs, [], consolidated, consol_day > 7.0 or fee > Decimal("0.10")


def _build_benign_or_other_flows(
    rng: random.Random,
    spec: VariantSpec,
    tx_seq: list[int],
    case_tag: str,
    root: str,
    inters: list[str],
    dests: list[str],
    total: Decimal,
    anchor: datetime,
    style: str,
) -> tuple[list[dict[str, Any]], Decimal, bool]:
    txs: list[dict[str, Any]] = []
    shares = _split_amount(rng, total, len(inters))
    decoy = "terse_ambiguous" if rng.random() < 0.40 else "none"

    if spec.family in ("benign_lookalike.ngo", "benign_lookalike.chit", "benign_lookalike.franchise_royalty_pooling"):
        for inter, share in zip(inters, shares, strict=True):
            mp = pick_memo(rng, style, decoy_mode=decoy)
            txs.append(make_tx(rng, tx_seq, case_tag, inter, root, share, anchor, rng.uniform(0.0, 3.0), mp))
        payout = (total * Decimal(str(round(rng.uniform(0.92, 0.98), 4)))).quantize(Decimal("0.01"))
        mo = pick_memo(rng, style, decoy_mode=decoy)
        txs.append(make_tx(rng, tx_seq, case_tag, root, dests[0], payout, anchor, rng.uniform(3.2, 6.5), mo))
        return txs, Decimal("0.00"), False

    if spec.family == "benign_lookalike.unregistered_employer_12m_payroll":
        for inter, share in zip(inters, shares, strict=True):
            me = pick_memo(rng, style, decoy_mode=decoy)
            txs.append(
                make_tx(rng, tx_seq, case_tag, root, inter, share, anchor, rng.uniform(0.0, 1.0), me, channel="NEFT")
            )
        per_emp = (total / Decimal(len(inters))).quantize(Decimal("0.01"))
        txs.extend(add_12m_payroll_history(rng, tx_seq, case_tag, root, inters, per_emp, anchor))
        return txs, Decimal("0.00"), False

    if spec.family_group in ("benign_lookalike", "incomplete_data"):
        span = 3.5 if spec.family_group == "benign_lookalike" else 4.0
        for inter, share in zip(inters, shares, strict=True):
            mf = pick_memo(rng, style, decoy_mode=decoy)
            txs.append(make_tx(rng, tx_seq, case_tag, root, inter, share, anchor, rng.uniform(0.0, span), mf))
        return txs, Decimal("0.00"), spec.family_group == "incomplete_data"

    if spec.family == "ambiguous.benign_root_unexplained_leg":
        for inter, share in zip(inters, shares, strict=True):
            ma = pick_memo(rng, style, decoy_mode="benign_cover")
            txs.append(make_tx(rng, tx_seq, case_tag, root, inter, share, anchor, rng.uniform(0.0, 2.0), ma))
        unexplained = (shares[0] * Decimal("0.94")).quantize(Decimal("0.01"))
        mu = pick_memo(rng, "terse")
        txs.append(make_tx(rng, tx_seq, case_tag, inters[0], dests[0], unexplained, anchor, rng.uniform(9.0, 16.0), mu))
        return txs, unexplained, True

    for inter, share in zip(inters, shares, strict=True):
        mb = pick_memo(rng, style, decoy_mode=decoy)
        txs.append(make_tx(rng, tx_seq, case_tag, root, inter, share, anchor, rng.uniform(0.0, 3.0), mb))
    return txs, Decimal("0.00"), False


def _root_constraints(case_rng: random.Random, family: str) -> tuple[bool | None, str | None]:
    if family in ("layering_benign_cover.shell_valid_gst", "layering_benign_cover.all_registered_merchants"):
        return True, case_rng.choice(("low", "medium"))
    if family == "benign_lookalike.unregistered_employer_12m_payroll":
        return False, None
    if family in ("incomplete_data.stale_registry_expired", "incomplete_data.conflicting_kyc_vs_registry"):
        return True, None
    if family == "ambiguous.benign_structure_high_risk_root":
        return None, "high"
    if family == "ambiguous.benign_root_unexplained_leg":
        return True, "low"
    return None, None


def _root_registry_for_spec(
    spec: VariantSpec, root: str, entity_name: str, root_attrs: dict[str, Any]
) -> dict[str, Any]:
    if spec.family == "incomplete_data.stale_registry_expired":
        return _registry_entry(
            root,
            entity_name,
            registered=False,
            reg_type=root_attrs["registry_type"],
            status="EXPIRED",
            since="2018-05-10",
        )
    if spec.family == "incomplete_data.conflicting_kyc_vs_registry":
        return _registry_entry(
            root, entity_name, registered=False, reg_type="REVOKED_ENTITY", status="REVOKED", since="2020-01-15"
        )
    if root_attrs["is_commercially_registered"]:
        return _registry_entry(
            root, entity_name, registered=True, reg_type=root_attrs["registry_type"], status="ACTIVE"
        )
    return _registry_entry(root, entity_name, registered=False, reg_type=None, status="NOT_FOUND")


def generate_v2_case(
    rng: random.Random,
    spec: VariantSpec,
    case_index: int,
    variant_seed: int,
    split: str,
    *,
    force_adversarial: bool = False,
) -> dict[str, Any]:
    """Generate a single deterministic Golden v2 case (`dev`, `held_out`, or `challenge`)."""
    case_rng = random.Random(variant_seed)
    split_tag = {"dev": "D", "held_out": "H", "challenge": "C"}[split]
    case_id = f"CASE-V2-{case_index:04d}"
    case_tag = f"{split_tag}{case_index:04d}"
    alert_id = f"ALT-V2-{case_tag}"
    anchor = datetime(2026, rng.randint(1, 9), rng.randint(1, 25), rng.randint(8, 17), 0, 0, tzinfo=timezone.utc)

    total_amount = _sample_log_uniform_inr(case_rng)
    n_inter = case_rng.randint(2, 8)
    n_dest = case_rng.randint(1, 4)
    style = case_rng.choice(("terse", "verbose", "hinglish"))

    root = f"ACC-{case_tag}-RT00"
    inters = [f"ACC-{case_tag}-IN{i:02d}" for i in range(1, n_inter + 1)]
    dests = [f"ACC-{case_tag}-DS{i:02d}" for i in range(1, n_dest + 1)]
    tx_seq = [0]

    if spec.family_group in ("layering", "layering_benign_cover"):
        core_txs, extra_nodes, consolidated, replan_req = _build_layering_flows(
            case_rng, spec, tx_seq, case_tag, root, inters, dests, total_amount, anchor, style
        )
    else:
        extra_nodes = []
        core_txs, consolidated, replan_req = _build_benign_or_other_flows(
            case_rng, spec, tx_seq, case_tag, root, inters, dests, total_amount, anchor, style
        )

    core_tx_ids = [t["tx_id"] for t in core_txs]
    network_accounts = [*inters, *extra_nodes, *dests]
    force_reg, force_risk = _root_constraints(case_rng, spec.family)
    root_attrs = sample_decoupled_root_kyc_attrs(
        case_rng, spec.gold_disposition, total_amount, force_registered=force_reg, force_risk=force_risk
    )
    if spec.gold_disposition == "escalate_str" and (force_adversarial or case_rng.random() < 0.40):
        note_mode = "benign_sounding"
    elif spec.gold_disposition == "close_benign" and case_rng.random() < 0.35:
        note_mode = "cautious_sounding"
    else:
        note_mode = "neutral"

    kyc_profiles: dict[str, dict[str, Any]] = {}
    registry_records: dict[str, dict[str, Any]] = {}
    kyc_profiles[root] = make_kyc_record(
        case_rng,
        root,
        f"Entity-{case_tag}-Root",
        entity_type=root_attrs["entity_type"],
        risk_category=root_attrs["risk_category"],
        income_inr=root_attrs["declared_annual_income_inr"],
        registered=root_attrs["is_commercially_registered"],
        registry_type=root_attrs["registry_type"],
        kyc_notes=pick_kyc_note(case_rng, decoy=note_mode),
    )
    registry_records[root] = _root_registry_for_spec(spec, root, kyc_profiles[root]["entity_name"], root_attrs)

    all_inter_reg = spec.family == "layering_benign_cover.all_registered_merchants"
    inter_prob = 0.60 if spec.gold_disposition == "close_benign" else 0.30
    for idx, acc in enumerate(network_accounts):
        if spec.family == "incomplete_data.missing_kyc" and idx < max(2, len(inters) // 2):
            continue
        inter_reg = True if all_inter_reg else (case_rng.random() < inter_prob)
        inter_type = "MERCHANT" if inter_reg else None
        kyc_profiles[acc] = make_kyc_record(
            case_rng,
            acc,
            f"Party-{acc[-6:]}",
            entity_type="company" if inter_reg else case_rng.choice(("individual", "company", "partnership")),
            risk_category=case_rng.choice(("low", "medium", "high")),
            income_inr=str(Decimal(case_rng.randint(350_000, 18_000_000))),
            registered=inter_reg,
            registry_type=inter_type,
            kyc_notes=pick_kyc_note(case_rng),
        )
        registry_records[acc] = _registry_entry(
            acc,
            kyc_profiles[acc]["entity_name"],
            registered=inter_reg,
            reg_type=inter_type,
            status="ACTIVE" if inter_reg else "NOT_FOUND",
        )

    _noise_accs, noise_txs, noise_kyc = add_background_noise(
        case_rng, tx_seq, case_tag, root, [root, *network_accounts], anchor, style
    )
    kyc_profiles.update(noise_kyc)
    all_txs = sorted([*core_txs, *noise_txs], key=lambda t: (t["timestamp"], t["tx_id"]))

    adv_tags = list(spec.adversarial_tags)
    if force_adversarial and "decoy_memo" not in adv_tags:
        adv_tags.append("decoy_memo")
    difficulty = "hard" if force_adversarial else spec.default_difficulty

    gold_ev = [f"KYC-{root}", *core_tx_ids[:12]]
    if root in registry_records and registry_records[root]["registry_status"] != "NOT_FOUND":
        gold_ev.append(registry_records[root]["evidence_id"])

    return {
        "dataset_version": "golden_v2",
        "case_id": case_id,
        "alert_id": alert_id,
        "rule_name": "SCATTER_GATHER",
        "family": spec.family,
        "family_group": spec.family_group,
        "held_out_only_variant": spec.held_out_only,
        "variant_seed": variant_seed,
        "split": split,
        "is_held_out": split != "dev",
        "category": spec.family,
        "expected_disposition": spec.gold_disposition,
        "gold_disposition": spec.gold_disposition,
        "acceptable_dispositions": list(spec.acceptable_dispositions),
        "expected_replan_required": replan_req,
        "severity_cost": {"false_close": 10, "false_escalate": 1, "false_request_info": 2},
        "gold_evidence_ids": gold_ev,
        "gold_calc": {
            "outflow": str(total_amount),
            "consolidated": str(consolidated.quantize(Decimal("0.01"))),
        },
        "difficulty": difficulty,
        "adversarial": adv_tags,
        "annotator_ids": [],
        "description": f"Golden v2 {spec.family} ({split}, difficulty={difficulty})",
        "triggered_at": anchor.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root_account": root,
        "network_accounts": network_accounts,
        "total_amount_inr": str(total_amount),
        "transactions": all_txs,
        "kyc_profiles": kyc_profiles,
        "registry_records": registry_records,
    }
