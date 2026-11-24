"""
Phase 1 Acceptance & Gold-Isolation Test Suite (`docs/AGENT_GUIDE.md` §4 Phase 1 & Decisions 1–2):
  1. Reproducibility (`seed=42` stable directory SHA-256) and split sizes (`60` dev / `120` held_out / `30` challenge).
  2. Split disjointness across IDs (`case_id`, `alert_id`, `account_id`, `tx_id`, `variant_seed`) and `⚑` variants.
  3. Single-KYC label purity <= 0.75, log-uniform amount diversity (2L–2Cr), zero structural duplicates, zero label
     words in memos or `kyc_notes`.
  4. Anti-shortcut baselines (`eval/shortcuts.py`): root KYC lookup tree <= 0.80 on held-out.
  5. Strict redaction & runtime isolation: agent-visible inputs/overlays contain zero gold/label keys; runtime loaders
     (`seeder`, `reflexion`) refuse held-out & challenge cases; evaluation harness scores using separated gold records.
  6. Human annotation workflow (`eval/human_labels/` & `eval/adjudication.py`): 40 dev-only cases, empty templates,
     honest `awaiting_human_annotations` status, and verified Cohen's kappa + disagreement reporting on mock sheets.
"""

from __future__ import annotations

import csv
from decimal import Decimal
import json
from pathlib import Path
import sqlite3
from typing import Any

import pytest

from data.generator_v2.build import (
    CHALLENGE_DIR,
    DEV_DIR,
    HELD_OUT_DIR,
    HUMAN_LABELS_DIR,
    build_dataset_v2,
    compute_directory_sha256,
)
from data.generator_v2.families import HELD_OUT_ONLY_VARIANTS
from data.generator_v2.labels import (
    assert_kyc_purity_bounds,
    assert_unique_fingerprints,
    structural_fingerprint,
)
from eval.adjudication import evaluate_adjudication_status
from eval.run_eval import extract_gold_record, load_cases, run as run_eval_cmd
from eval.shortcuts import assert_shortcut_ceiling, evaluate_shortcuts
from src.db import seeder
from src.mcp_servers import bank_records
from src.mcp_servers.client import call_mcp_tool
from src.reflexion.loop import generate_candidate_lesson

FORBIDDEN_MEMO_WORDS = (
    "layering",
    "laundering",
    "mule",
    "shell",
    "skimming",
    "staggered",
    "benign",
    "suspicious",
    "missing hop",
)


def _load_split(folder: Path) -> list[dict[str, Any]]:
    return [json.loads(fp.read_text(encoding="utf-8")) for fp in sorted(folder.glob("*.json"))]


def _collect_all_ids(cases: list[dict[str, Any]]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {
        "case_id": set(),
        "alert_id": set(),
        "account_id": set(),
        "tx_id": set(),
        "variant_seed": set(),
    }
    for c in cases:
        out["case_id"].add(str(c["case_id"]))
        out["alert_id"].add(str(c["alert_id"]))
        out["variant_seed"].add(str(c["variant_seed"]))
        out["account_id"].add(str(c["root_account"]))
        out["account_id"].update(str(a) for a in c.get("network_accounts", []))
        out["account_id"].update(str(a) for a in (c.get("kyc_profiles") or {}).keys())
        for tx in c.get("transactions", []):
            out["tx_id"].add(str(tx["tx_id"]))
            out["account_id"].add(str(tx["sender_account"]))
            out["account_id"].add(str(tx["receiver_account"]))
    return out


def test_dataset_v2_reproducible_seed_42_and_directory_separation(tmp_path: Path) -> None:
    d1, h1, c1, l1, s1 = (
        tmp_path / "r1" / "data" / "dev",
        tmp_path / "r1" / "eval" / "held_out",
        tmp_path / "r1" / "eval" / "challenge",
        tmp_path / "r1" / "eval" / "labels",
        tmp_path / "r1" / "summary.json",
    )
    d2, h2, c2, l2, s2 = (
        tmp_path / "r2" / "data" / "dev",
        tmp_path / "r2" / "eval" / "held_out",
        tmp_path / "r2" / "eval" / "challenge",
        tmp_path / "r2" / "eval" / "labels",
        tmp_path / "r2" / "summary.json",
    )
    sum1 = build_dataset_v2(seed=42, dev_dir=d1, held_out_dir=h1, challenge_dir=c1, labels_dir=l1, summary_path=s1)
    sum2 = build_dataset_v2(seed=42, dev_dir=d2, held_out_dir=h2, challenge_dir=c2, labels_dir=l2, summary_path=s2)
    assert sum1["output_sha256"] == sum2["output_sha256"] == compute_directory_sha256(d1, h1, c1)

    # Physical directory separation check on workspace dataset
    assert DEV_DIR == Path("data/golden_v2/dev") and DEV_DIR.exists()
    assert HELD_OUT_DIR == Path("eval/golden_v2/held_out") and HELD_OUT_DIR.exists()
    assert CHALLENGE_DIR == Path("eval/golden_v2/challenge") and CHALLENGE_DIR.exists()
    assert not Path("data/golden_v2/held_out").exists()
    assert not Path("data/golden_v2/challenge").exists()

    dev = _load_split(DEV_DIR)
    held = _load_split(HELD_OUT_DIR)
    chal = _load_split(CHALLENGE_DIR)
    assert len(dev) == 60
    assert len(held) == 120
    assert len(chal) == 30
    assert all(c["adversarial"] for c in chal)
    assert len(load_cases("golden_v1_regression")) == 60


def test_dataset_v2_split_disjointness_ids_and_variants() -> None:
    dev = _load_split(DEV_DIR)
    held = _load_split(HELD_OUT_DIR)
    chal = _load_split(CHALLENGE_DIR)

    ids_dev = _collect_all_ids(dev)
    ids_held = _collect_all_ids(held)
    ids_chal = _collect_all_ids(chal)

    for key in ("case_id", "alert_id", "account_id", "tx_id", "variant_seed"):
        assert ids_dev[key].isdisjoint(ids_held[key]), f"dev vs held_out overlap on {key}"
        assert ids_dev[key].isdisjoint(ids_chal[key]), f"dev vs challenge overlap on {key}"
        assert ids_held[key].isdisjoint(ids_chal[key]), f"held_out vs challenge overlap on {key}"

    held_only_names = {v.family for v in HELD_OUT_ONLY_VARIANTS}
    dev_families = {c["family"] for c in dev}
    held_families = {c["family"] for c in held}
    assert len(held_only_names) == 7
    assert dev_families.isdisjoint(held_only_names)
    assert held_only_names <= held_families


def test_dataset_v2_purity_amounts_fingerprints_and_clean_memos() -> None:
    dev = _load_split(DEV_DIR)
    held = _load_split(HELD_OUT_DIR)
    chal = _load_split(CHALLENGE_DIR)
    all_cases = [*dev, *held, *chal]

    for split_cases in (dev, held, all_cases):
        purities = assert_kyc_purity_bounds(split_cases, max_purity=0.75)
        assert all(v <= 0.75 for v in purities.values()), purities

    assert_unique_fingerprints(all_cases)
    assert len({structural_fingerprint(c) for c in all_cases}) == 210

    amounts = [Decimal(str(c["total_amount_inr"])) for c in all_cases]
    assert min(amounts) >= Decimal("200000.00")
    assert max(amounts) <= Decimal("20000000.00")
    assert max(amounts) - min(amounts) >= Decimal("5000000.00")
    assert len(set(amounts)) >= 200

    for c in all_cases:
        for tx in c["transactions"]:
            memo_low = str(tx.get("memo", "")).lower()
            assert not any(w in memo_low for w in FORBIDDEN_MEMO_WORDS), f"{c['case_id']}: {memo_low}"
        for kyc in c["kyc_profiles"].values():
            notes_low = str(kyc.get("kyc_notes", "")).lower()
            assert not any(w in notes_low for w in FORBIDDEN_MEMO_WORDS), f"{c['case_id']}: {notes_low}"


def test_dataset_v2_shortcut_baselines_ceiling() -> None:
    dev = _load_split(DEV_DIR)
    held = _load_split(HELD_OUT_DIR)
    chal = _load_split(CHALLENGE_DIR)

    held_metrics = assert_shortcut_ceiling(dev, held, ceiling=0.80)
    chal_metrics = evaluate_shortcuts(dev, chal)
    assert held_metrics["root_kyc_tree"]["accuracy"] <= 0.80
    assert set(held_metrics.keys()) == {"root_kyc_tree", "hand_features_logreg", "memo_keyword_nb"}
    assert set(chal_metrics.keys()) == {"root_kyc_tree", "hand_features_logreg", "memo_keyword_nb"}


@pytest.mark.asyncio
async def test_overlay_hides_labels_and_runtime_cannot_load_eval_gold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    held = _load_split(HELD_OUT_DIR)
    chal = _load_split(CHALLENGE_DIR)
    forbidden_keys = {
        "category",
        "category_id",
        "description",
        "family",
        "family_group",
        "held_out_only_variant",
        "variant_seed",
        "split",
        "is_held_out",
        "expected_disposition",
        "expected_replan_required",
        "gold_disposition",
        "acceptable_dispositions",
        "severity_cost",
        "gold_evidence_ids",
        "gold_calc",
        "difficulty",
        "adversarial",
        "annotator_ids",
    }

    for sample in (held[0], chal[0]):
        tok = bank_records.set_eval_case_overlay(sample)
        try:
            visible = bank_records.get_active_eval_overlay()
            assert visible is not None
            assert forbidden_keys.isdisjoint(visible.keys())
            assert not any(k.startswith(("expected_", "gold_")) for k in visible)

            ctx = await call_mcp_tool("bank-records", "get_alert_context", {"alert_id": sample["alert_id"]})
            kyc = await call_mcp_tool("bank-records", "get_kyc_profile", {"account_id": sample["root_account"]})
            reg = await call_mcp_tool(
                "bank-records",
                "check_commercial_registry",
                {"entity_name": "Entity", "account_id": sample["root_account"]},
            )
            for payload in (ctx, kyc, reg):
                assert forbidden_keys.isdisjoint(payload.keys())
        finally:
            bank_records.reset_eval_case_overlay(tok)

    # Verify independent registry status (`EXPIRED`) & 12-month payroll counterparty history work via MCP
    stale_case = next(c for c in held if c["family"] == "incomplete_data.stale_registry_expired")
    tok_s = bank_records.set_eval_case_overlay(stale_case)
    try:
        kyc_s = await call_mcp_tool("bank-records", "get_kyc_profile", {"account_id": stale_case["root_account"]})
        reg_s = await call_mcp_tool(
            "bank-records",
            "check_commercial_registry",
            {"entity_name": kyc_s["entity_name"], "account_id": stale_case["root_account"]},
        )
        assert kyc_s["is_commercially_registered"] is True
        assert reg_s["is_registered"] is False and reg_s["registry_status"] == "EXPIRED"
    finally:
        bank_records.reset_eval_case_overlay(tok_s)

    dev = _load_split(DEV_DIR)
    unreg_payroll = next(c for c in dev if c["family"] == "benign_lookalike.unregistered_employer_12m_payroll")
    tok_p = bank_records.set_eval_case_overlay(unreg_payroll)
    try:
        emp = unreg_payroll["network_accounts"][0]
        cp_hist = await call_mcp_tool(
            "bank-records",
            "get_counterparty_history",
            {"account_id": unreg_payroll["root_account"], "counterparty_id": emp, "days_back": 365},
        )
        assert cp_hist["total_transactions"] >= 12
    finally:
        bank_records.reset_eval_case_overlay(tok_p)

    # Runtime loaders MUST refuse held-out and challenge splits/cases
    conn = sqlite3.connect(tmp_path / "rt.db")
    try:
        with pytest.raises(PermissionError):
            seeder.seed_from_directories(conn, HELD_OUT_DIR)
        with pytest.raises(PermissionError):
            seeder.seed_from_directories(conn, CHALLENGE_DIR)
        with pytest.raises(PermissionError):
            seeder.upsert_case_into_db(conn, held[0])
        with pytest.raises(PermissionError):
            seeder.upsert_case_into_db(conn, chal[0])
    finally:
        conn.close()

    with pytest.raises(PermissionError):
        generate_candidate_lesson(held[0], "request_info")
    with pytest.raises(PermissionError):
        generate_candidate_lesson(chal[0], "request_info")


def test_eval_harness_scores_gold_while_passing_redacted_inputs_only(monkeypatch: pytest.MonkeyPatch) -> None:
    chal = _load_split(CHALLENGE_DIR)
    forbidden_keys = {
        "category",
        "category_id",
        "description",
        "family",
        "family_group",
        "held_out_only_variant",
        "variant_seed",
        "split",
        "is_held_out",
        "expected_disposition",
        "expected_replan_required",
        "gold_disposition",
        "acceptable_dispositions",
        "severity_cost",
        "gold_evidence_ids",
        "gold_calc",
        "difficulty",
        "adversarial",
        "annotator_ids",
    }
    seen_by_agent: list[set[str]] = []
    from eval import run_eval as re_mod

    orig_run_case = re_mod.run_case

    async def _spy_run_case(case: dict[str, Any], **kw: Any) -> dict[str, Any]:
        seen_by_agent.append(set(case.keys()))
        return await orig_run_case(case, **kw)

    monkeypatch.setattr(re_mod, "run_case", _spy_run_case)
    gold_rec = extract_gold_record(chal[0])
    assert gold_rec["gold_disposition"] in {"escalate_str", "close_benign", "request_info"}
    eval_summary = run_eval_cmd(config="E1", split="v2_challenge", repeats=1, limit=1)
    assert eval_summary["split"] == "v2_challenge"
    assert seen_by_agent and all(forbidden_keys.isdisjoint(keys) for keys in seen_by_agent)


def test_human_annotation_templates_and_adjudication_workflow(tmp_path: Path) -> None:
    dev_ids = {c["case_id"] for c in _load_split(DEV_DIR)}
    held_ids = {c["case_id"] for c in _load_split(HELD_OUT_DIR)}
    chal_ids = {c["case_id"] for c in _load_split(CHALLENGE_DIR)}

    p1 = HUMAN_LABELS_DIR / "cases_to_annotate_annotator_1.csv"
    p2 = HUMAN_LABELS_DIR / "cases_to_annotate_annotator_2.csv"
    pc = HUMAN_LABELS_DIR / "cases.csv"
    pa = HUMAN_LABELS_DIR / "adjudicated_cases.csv"
    assert p1.exists() and p2.exists() and pc.exists() and pa.exists()

    with p1.open("r", encoding="utf-8", newline="") as f1, p2.open("r", encoding="utf-8", newline="") as f2:
        r1 = list(csv.reader(f1))
        r2 = list(csv.reader(f2))

    expected_cols = ["case_id", "annotator", "disposition", "confidence", "notes"]
    assert r1[0] == expected_cols and r2[0] == expected_cols
    ids_1 = [row[0] for row in r1[1:]]
    ids_2 = [row[0] for row in r2[1:]]
    assert len(ids_1) == 40 and ids_1 == ids_2
    assert set(ids_1) <= dev_ids
    assert set(ids_1).isdisjoint(held_ids | chal_ids)
    # All annotation fields MUST be strictly empty (zero fabricated human labels!)
    assert all(row[1:] == ["", "", "", ""] for row in r1[1:])
    assert all(row[1:] == ["", "", "", ""] for row in r2[1:])

    real_status = evaluate_adjudication_status(HUMAN_LABELS_DIR)
    assert real_status["status"] == "awaiting_human_annotations"
    assert real_status["adjudication_complete"] is False
    assert real_status["paired_cases"] == 0

    # Verify Cohen's kappa + disagreement + adjudication workflow on an isolated tmp_path fixture
    mock_dir = tmp_path / "mock_labels"
    mock_dir.mkdir()
    sample_ids = ids_1[:4]
    with (mock_dir / "cases_to_annotate_annotator_1.csv").open("w", encoding="utf-8", newline="\n") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(expected_cols)
        w.writerow([sample_ids[0], "ann_a", "escalate_str", "0.9", "clear layering"])
        w.writerow([sample_ids[1], "ann_a", "close_benign", "0.8", "verified payroll"])
        w.writerow([sample_ids[2], "ann_a", "request_info", "0.7", "missing hop"])
        w.writerow([sample_ids[3], "ann_a", "escalate_str", "0.6", "unexplained leg"])
    with (mock_dir / "cases_to_annotate_annotator_2.csv").open("w", encoding="utf-8", newline="\n") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(expected_cols)
        w.writerow([sample_ids[0], "ann_b", "escalate_str", "0.85", "agree"])
        w.writerow([sample_ids[1], "ann_b", "close_benign", "0.9", "agree"])
        w.writerow([sample_ids[2], "ann_b", "request_info", "0.75", "agree"])
        w.writerow([sample_ids[3], "ann_b", "request_info", "0.65", "needs bank stmt"])
    (mock_dir / "cases.csv").write_text("case_id,annotator,disposition,confidence,notes\n", encoding="utf-8")
    (mock_dir / "adjudicated_cases.csv").write_text(
        "case_id,adjudicated_disposition,acceptable_dispositions,adjudicator,resolution_notes\n",
        encoding="utf-8",
    )

    in_prog = evaluate_adjudication_status(mock_dir)
    assert in_prog["adjudication_complete"] is False
    assert in_prog["paired_cases"] == 4
    assert in_prog["cohens_kappa"] is not None and in_prog["cohens_kappa"] > 0.5
    assert in_prog["unresolved_disagreements"] == [sample_ids[3]]

    with (mock_dir / "adjudicated_cases.csv").open("a", encoding="utf-8", newline="\n") as f:
        csv.writer(f, lineterminator="\n").writerow(
            [sample_ids[3], "request_info", "escalate_str|request_info", "lead_adj", "ambiguous leg"]
        )
    resolved = evaluate_adjudication_status(mock_dir)
    assert resolved["adjudication_complete"] is True
    assert resolved["unresolved_disagreements"] == []
