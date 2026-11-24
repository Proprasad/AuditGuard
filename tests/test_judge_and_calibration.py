"""
Phase 4 — Offline Cassette Judge, Blindness, Cross-Family Lineage & Calibration Suite
(`tests/test_judge_and_calibration.py`).
"""

from __future__ import annotations

from collections import Counter
import csv
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from eval.calibration import (
    assert_dev_only_for_tuning,
    evaluate_held_out_calibration,
    extract_dev_tuning_disagreements,
    run_calibration,
)
from eval.calibration_stats import (
    EXPECTED_CSV_COLUMNS,
    AnnotationValidationError,
    read_and_validate_annotator_csv,
)
from eval.judge import (
    ALL_CRITERIA,
    BINARY_CRITERIA,
    ORDINAL_CRITERIA,
    CrossFamilyViolationError,
    LLMJudge,
    _scrub_log_obj,
    cohens_kappa,
    criterion_kappa,
    infer_model_family,
    linear_weighted_kappa,
    validate_cross_family_judge,
)
from eval.judge_prompts import blind_worksheet_for_judge, verify_dev_only_examples
from src.llm.client import LLMClient

REPO_ROOT = Path(__file__).resolve().parents[1]
JUDGE_CASSETTE = REPO_ROOT / "eval" / "cassettes" / "judge_smoke.jsonl"
REAL_LABELS_DIR = REPO_ROOT / "eval" / "human_labels"
REAL_MANIFEST = REPO_ROOT / "eval" / "calibration_manifest" / "packet_manifest.json"


class _ForbidNetworkTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"Offline cassette test attempted network call to {request.url}")


def _load_packet_and_manifest() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    manifest = json.loads(REAL_MANIFEST.read_text(encoding="utf-8"))
    pkt_path = REAL_LABELS_DIR / "worksheets_packet_blinded.jsonl"
    packet = {
        rec["worksheet_id"]: rec
        for rec in (json.loads(line) for line in pkt_path.read_text(encoding="utf-8").splitlines() if line.strip())
    }
    return packet, manifest


@pytest.mark.asyncio
async def test_judge_schema(tmp_path: Path) -> None:
    """Replay recorded Gemini cassette offline -> validate Pydantic G1..G7 schema, swap probe & PII-scrubbed log."""
    assert JUDGE_CASSETTE.exists(), "Missing eval/cassettes/judge_smoke.jsonl"
    packet, manifest = _load_packet_and_manifest()
    items = manifest["worksheets"]
    dev_wids = sorted(w for w, m in items.items() if m["split"] == "dev")
    w_a = next(w for w in dev_wids if items[w]["mode"] == "c0_fixed")
    w_b = next(w for w in dev_wids if items[w]["mode"] == "c1_single")

    replay_client = LLMClient(
        mode="replay",
        cassette_path=JUDGE_CASSETTE,
        run_id="test_judge_replay",
        runs_dir=tmp_path,
        transport=_ForbidNetworkTransport(),
    )
    judge = LLMJudge(llm_client=replay_client, run_id="test_judge_replay", runs_dir=tmp_path)

    r1 = await judge.score_worksheet(packet[w_a]["worksheet"], packet[w_a]["evidence_summary"], worksheet_id=w_a)
    r2 = await judge.score_worksheet(packet[w_b]["worksheet"], packet[w_b]["evidence_summary"], worksheet_id=w_b)
    swap = await judge.evaluate_position_swap(
        packet[w_a]["worksheet"], packet[w_b]["worksheet"], packet[w_b]["evidence_summary"]
    )

    for rec in (r1, r2):
        assert rec.judge_family == "google_gemini"
        assert rec.rubric_version == "1.0.0"
        assert rec.prompt_version == "judge-prompt-v1.0.0"
        assert rec.prompt_tokens > 0 and rec.completion_tokens > 0
        for c in ORDINAL_CRITERIA:
            assert 1 <= getattr(rec.scores, c) <= 5
        for b in BINARY_CRITERIA:
            assert getattr(rec.scores, b) in ("pass", "fail")
        assert rec.scores.judge_citation_relevant is (rec.scores.G5 >= 4)

    assert swap.forward_winner in ("first", "second", "tie")
    assert swap.swapped_winner in ("first", "second", "tie")
    assert isinstance(swap.position_consistent, bool)
    assert 0.0 <= swap.mean_abs_ordinal_drift <= 4.0

    raw_log = tmp_path / "test_judge_replay" / "judge_raw_responses.jsonl"
    logged = [json.loads(line) for line in raw_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(logged) == 4
    assert [e["type"] for e in logged] == ["single_score", "single_score", "pairwise", "pairwise"]
    for e in logged:
        assert "rubric_version" in e and "prompt_version" in e and "cost_usd" in e


def test_judge_blindness_and_dev_only_few_shot(tmp_path: Path) -> None:
    """Verify blind sanitizer strips mode/model/gold leaks and few-shot check enforces dev-only origin."""
    dirty_ws = {
        "worksheet_id": "DWS-LEAK",
        "investigator_agent": "auditguard-c2",
        "agent_mode": "c2_multi",
        "model_id": "openai/gpt-5-mini",
        "split": "held_out",
        "gold_disposition": "escalate_str",
        "is_correct": True,
        "recommended_disposition": "escalate_str",
        "confidence_score": "0.8400",
        "recommendation_rationale": (
            "[Live LLM: openai/gpt-5-mini] C0 Fair Baseline: auditguard-c1: TXN-001 shows layering "
            "evaluated by c1_single and gpt-5-mini [reasoning=llm_tool_loop]."
        ),
        "hypotheses": [
            {
                "label": "suspicious",
                "evidence_ids": ["TXN-001"],
                "explanation": "Generated by c2_multi using claude-3-haiku.",
            }
        ],
    }
    blinded = blind_worksheet_for_judge(dirty_ws)
    serialized = json.dumps(blinded)
    for forbidden in (
        "investigator_agent",
        "agent_mode",
        "gold_disposition",
        "is_correct",
        "DWS-LEAK",
        "gpt-5-mini",
        "claude-3-haiku",
        "c1_single",
        "c2_multi",
        "C0 Fair Baseline",
        "Live LLM",
        "held_out",
    ):
        assert forbidden not in serialized

    assert verify_dev_only_examples() == ("CASE-V2-0001", "CASE-V2-0006")
    scrubbed = _scrub_log_obj({"hdr": "Bearer sk-abcdef1234567890", "pan": "PAN ABCDE1234F phone +919876543210"})
    assert "sk-abcdef" not in json.dumps(scrubbed) and "ABCDE1234F" not in json.dumps(scrubbed)
    fake_dir = tmp_path / "fake_dev"
    fake_dir.mkdir()
    (fake_dir / "CASE-V2-0001.json").write_text(
        json.dumps({"split": "held_out", "is_held_out": True}), encoding="utf-8"
    )
    (fake_dir / "CASE-V2-0006.json").write_text(
        json.dumps({"split": "dev", "is_held_out": False}), encoding="utf-8"
    )
    with pytest.raises(PermissionError, match="not a pure dev record"):
        verify_dev_only_examples(fake_dir)


def test_cross_family_model_validation() -> None:
    """Verify canonical model-lineage check catches same-family models even across different names/providers."""
    default_check = validate_cross_family_judge()
    assert default_check["cross_family_verified"] is True
    assert default_check["judge_family"] == "google_gemini"
    assert default_check["investigator_families"]["c1_investigator"] == "openai_gpt"

    # Different model name (gemma vs gemini), same canonical Google lineage -> MUST fail!
    with pytest.raises(CrossFamilyViolationError, match="google_gemini"):
        validate_cross_family_judge(
            judge_model="google/gemma-4-31b-it",
            investigator_models={"c1_investigator": "vertex/gemini-3.1-flash-lite"},
        )

    # Different provider prefix (azure vs openai) & model version (gpt-4o-mini vs gpt-5-mini) -> MUST fail!
    with pytest.raises(CrossFamilyViolationError, match="openai_gpt"):
        validate_cross_family_judge(
            judge_model="azure/gpt-4o-mini",
            investigator_models={"c1_investigator": "openai/gpt-5-mini"},
        )

    # Unknown lineage must raise ValueError rather than silently assuming cross-family
    with pytest.raises(ValueError, match="unrecognized model slug"):
        infer_model_family("acme-corp/mystery-7b")


def test_kappa_linear_weighted_and_plain() -> None:
    """Hand-verify plain nominal Cohen's kappa and linear-weighted 1..5 ordinal kappa."""
    # Plain binary kappa: 8/10 observed agreement; P(pass)=0.5 & 0.5 -> p_e=0.5 -> kappa=(0.8-0.5)/(1-0.5)=0.6
    a_bin = ["pass", "pass", "pass", "pass", "pass", "fail", "fail", "fail", "fail", "fail"]
    b_bin = ["pass", "pass", "pass", "pass", "fail", "pass", "fail", "fail", "fail", "fail"]
    assert round(cohens_kappa(a_bin, b_bin), 6) == 0.6
    assert round(criterion_kappa("G2", a_bin, b_bin), 6) == 0.6

    # Ordinal 1..5: near-miss (1,2,3,4,5 vs 1,2,3,4,4) -> obs_dis = (1/4)/5 = 0.05 = 5/100
    # freq_a = {1:1/5, 2:1/5, 3:1/5, 4:1/5, 5:1/5}; freq_b = {1:1/5, 2:1/5, 3:1/5, 4:2/5, 5:0}
    # exp_dis = (10 + 7 + 6 + 14 + 0) / (5 * 5 * 4) = 37/100 = 0.37 -> kappa_w = 1 - 5/37 = 32/37
    s_a = [1, 2, 3, 4, 5]
    s_b = [1, 2, 3, 4, 4]
    expected_kw = round(32 / 37, 6)
    assert round(linear_weighted_kappa(s_a, s_b), 6) == expected_kw
    assert round(criterion_kappa("G1", s_a, s_b), 6) == expected_kw
    # Plain nominal kappa treats 4 vs 5 as full miss (4/5 = 0.80 obs, p_e = 0.20 -> 0.75 < 0.875)
    assert cohens_kappa([str(x) for x in s_a], [str(x) for x in s_b]) < linear_weighted_kappa(s_a, s_b)


def _write_csv_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(EXPECTED_CSV_COLUMNS))
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def test_calibration_empty_partial_invalid_duplicate_missing_and_complete(tmp_path: Path) -> None:
    """Exercise empty real labels, malformed CSV errors, dev-ready, and frozen held-out calibration."""
    # 1. Real empty human templates MUST report awaiting_human_annotations with zero fabricated numbers
    real_out = tmp_path / "real_cal"
    empty_res = run_calibration(labels_dir=REAL_LABELS_DIR, out_dir=real_out, manifest_path=REAL_MANIFEST)
    assert empty_res["status"] == "awaiting_human_annotations"
    assert empty_res["calibration_complete"] is False
    assert empty_res["paired_completed"] == 0
    assert empty_res["dev_criteria_kappa"] is None
    assert empty_res["held_out_criteria_kappa"] is None

    # 2. Malformed CSV validation: out-of-range, missing criterion, duplicate ID, mismatched coverage
    bad_csv = tmp_path / "bad.csv"
    base_row = {
        "worksheet_id": "WS-CAL-001",
        "annotator": "a1",
        "G1": "6",
        "G2": "pass",
        "G3": "4",
        "G4": "4",
        "G5": "4",
        "G6": "pass",
        "G7": "4",
        "comments": "",
    }
    _write_csv_rows(bad_csv, [base_row])
    with pytest.raises(AnnotationValidationError, match="INVALID_SCORE"):
        read_and_validate_annotator_csv(bad_csv)

    _write_csv_rows(bad_csv, [{**base_row, "G1": "4", "G7": ""}])
    with pytest.raises(AnnotationValidationError, match="MISSING_CRITERIA"):
        read_and_validate_annotator_csv(bad_csv)

    valid_row = {**base_row, "G1": "4"}
    _write_csv_rows(bad_csv, [valid_row, valid_row])
    with pytest.raises(AnnotationValidationError, match="DUPLICATE_WORKSHEET_ID"):
        read_and_validate_annotator_csv(bad_csv)

    # 3. Synthetic isolated copy testing partial -> dev_calibration_ready -> final_held_out_complete
    _, manifest = _load_packet_and_manifest()
    items = manifest["worksheets"]
    all_wids = sorted(items.keys())
    dev_set = {w for w, m in items.items() if m["split"] == "dev"}

    sim_dir = tmp_path / "sim_labels"
    sim_dir.mkdir()
    (sim_dir / "worksheets_packet_blinded.jsonl").write_text(
        (REAL_LABELS_DIR / "worksheets_packet_blinded.jsonl").read_text(encoding="utf-8"), encoding="utf-8"
    )

    def _blank(wid: str) -> dict[str, str]:
        return {col: (wid if col == "worksheet_id" else "") for col in EXPECTED_CSV_COLUMNS}

    def _scored(wid: str, who: str, g1: int, g2: str, g3: int = 4) -> dict[str, Any]:
        return {
            "worksheet_id": wid,
            "annotator": who,
            "G1": str(g1),
            "G2": g2,
            "G3": str(g3),
            "G4": "4",
            "G5": "5",
            "G6": "pass",
            "G7": "4",
            "comments": "test",
        }

    # Partial (only 5 rows scored)
    first5 = set(all_wids[:5])
    _write_csv_rows(
        sim_dir / "worksheets_to_score_annotator_1.csv",
        [_scored(w, "a1", 4, "pass") if w in first5 else _blank(w) for w in all_wids],
    )
    _write_csv_rows(
        sim_dir / "worksheets_to_score_annotator_2.csv",
        [_scored(w, "a2", 4, "pass") if w in first5 else _blank(w) for w in all_wids],
    )
    part_res = run_calibration(labels_dir=sim_dir, out_dir=tmp_path / "part_out", manifest_path=REAL_MANIFEST)
    assert part_res["status"] == "incomplete_annotations"

    # Dev 20 completed (held-out blank)
    dev_rows_1 = [
        _scored(w, "a1", (5 if i % 2 == 0 else 2), ("pass" if i % 2 == 0 else "fail"))
        if w in dev_set
        else _blank(w)
        for i, w in enumerate(all_wids)
    ]
    dev_rows_2 = [
        _scored(w, "a2", (5 if i % 2 == 0 else 2), ("pass" if i % 2 == 0 else "fail"))
        if w in dev_set
        else _blank(w)
        for i, w in enumerate(all_wids)
    ]
    _write_csv_rows(sim_dir / "worksheets_to_score_annotator_1.csv", dev_rows_1)
    _write_csv_rows(sim_dir / "worksheets_to_score_annotator_2.csv", dev_rows_2)
    dev_res = run_calibration(labels_dir=sim_dir, out_dir=tmp_path / "dev_out", manifest_path=REAL_MANIFEST)
    assert dev_res["status"] == "dev_calibration_ready"
    assert dev_res["dev_criteria_kappa"] is not None
    assert dev_res["held_out_criteria_kappa"] is None

    # Full 60 completed with family-skewed disagreement on `ambiguous` (sample weight 0.20 vs pop weight 0.10)
    rows_1, rows_2 = [], []
    judge_scores: dict[str, dict[str, Any]] = {}
    for idx, w in enumerate(all_wids):
        hi = idx % 2 == 0
        fam = items[w]["family_group"]
        a1_g1 = 5 if hi else 2
        # Annotator 2 disagrees on `ambiguous` family so sample agreement != population-weighted agreement!
        a2_g1 = (1 if hi else 5) if fam == "ambiguous" else a1_g1
        b_val = "pass" if hi else "fail"
        rows_1.append(_scored(w, "a1", a1_g1, b_val, g3=(5 if hi else 2)))
        rows_2.append(_scored(w, "a2", a2_g1, b_val, g3=(5 if hi else 2)))
        # Judge agrees strongly on G2, but inverted on G3 so G3 < 0.75 -> excluded_from_headline!
        judge_scores[w] = {
            "G1": a1_g1,
            "G2": b_val,
            "G3": (2 if hi else 5),
            "G4": 4,
            "G5": 5,
            "G6": "pass",
            "G7": 4,
        }

    _write_csv_rows(sim_dir / "worksheets_to_score_annotator_1.csv", rows_1)
    _write_csv_rows(sim_dir / "worksheets_to_score_annotator_2.csv", rows_2)
    j_path = tmp_path / "judge_scores.json"
    j_path.write_text(
        json.dumps(
            {
                "scores": judge_scores,
                "position_swaps": [
                    {"position_consistent": True, "mean_abs_ordinal_drift": 0.0},
                    {"position_consistent": False, "mean_abs_ordinal_drift": 0.4},
                ],
            }
        ),
        encoding="utf-8",
    )

    # Without rubric_frozen=True, held-out MUST remain untouched even when all 60 rows exist!
    unfrozen = run_calibration(
        labels_dir=sim_dir,
        out_dir=tmp_path / "unfrozen_out",
        manifest_path=REAL_MANIFEST,
        judge_scores_path=j_path,
        rubric_frozen_override=False,
    )
    assert unfrozen["status"] == "dev_calibration_ready"
    assert unfrozen["held_out_criteria_kappa"] is None

    # With rubric_frozen=True, final held-out agreement is computed once
    frozen = run_calibration(
        labels_dir=sim_dir,
        out_dir=tmp_path / "frozen_out",
        manifest_path=REAL_MANIFEST,
        judge_scores_path=j_path,
        rubric_frozen_override=True,
    )
    assert frozen["status"] == "final_held_out_complete"
    assert frozen["calibration_complete"] is True
    ho_g1 = frozen["held_out_criteria_kappa"]["G1"]
    assert ho_g1["human_sample_agreement"] != ho_g1["human_population_weighted_agreement"]
    assert "G3" in frozen["excluded_from_headline"]
    assert frozen["bias_checks"]["verbosity_word_count_pearson_r"] is not None
    assert frozen["bias_checks"]["position_swap_flip_rate"] == 0.5


def test_held_out_annotations_blocked_from_dev_tuning() -> None:
    """Ensure held-out worksheet IDs cannot enter dev tuning and unfrozen rubrics cannot score held-out."""
    _, manifest = _load_packet_and_manifest()
    items = manifest["worksheets"]
    ho_wid = next(w for w, m in items.items() if m["split"] == "held_out")
    dev_wid = next(w for w, m in items.items() if m["split"] == "dev")

    assert_dev_only_for_tuning(dev_wid, manifest)
    with pytest.raises(PermissionError, match="Held-out isolation violation"):
        assert_dev_only_for_tuning(ho_wid, manifest)

    dummy = {c: (4 if c in ORDINAL_CRITERIA else "pass") for c in ALL_CRITERIA}
    with pytest.raises(PermissionError, match="Held-out isolation violation"):
        extract_dev_tuning_disagreements(
            {ho_wid: dummy}, {ho_wid: dummy}, {ho_wid: dummy}, manifest, requested_ids=[ho_wid]
        )

    with pytest.raises(PermissionError, match="rubric_frozen=True"):
        evaluate_held_out_calibration(
            [ho_wid], {ho_wid: dummy}, {ho_wid: dummy}, None, manifest, rubric_frozen=False
        )


def test_generated_packet_stratification_and_blindness() -> None:
    """Verify the real 60-worksheet packet, empty randomized CSV templates, and zero metadata leakage."""
    packet, manifest = _load_packet_and_manifest()
    items = manifest["worksheets"]
    assert len(packet) == 60
    assert len(items) == 60
    assert manifest["blocked_slots"] == []
    assert REAL_MANIFEST.parent.resolve() != REAL_LABELS_DIR.resolve()

    split_counts = Counter(m["split"] for m in items.values())
    assert split_counts == {"dev": 20, "held_out": 40}

    mode_counts = Counter(m["mode"] for m in items.values())
    assert mode_counts == {"c0_fixed": 15, "rule_engine": 15, "c1_single": 15, "c2_multi": 15}

    for mode in ("c0_fixed", "rule_engine", "c1_single", "c2_multi"):
        dev_fams = Counter(m["family_group"] for m in items.values() if m["mode"] == mode and m["split"] == "dev")
        ho_fams = Counter(m["family_group"] for m in items.values() if m["mode"] == mode and m["split"] == "held_out")
        assert all(v == 1 for v in dev_fams.values()) and len(dev_fams) == 5
        assert all(v == 2 for v in ho_fams.values()) and len(ho_fams) == 5

    # Verify genuine LLM tokens & cost on all 30 C1/C2 worksheets
    for m in items.values():
        if m["mode"] in ("c1_single", "c2_multi"):
            assert int(m["tokens_used"]) > 0
            assert float(m["cost_usd"]) > 0.0

    # Verify both CSVs have identical 60 IDs in different randomized orders and 100% empty score cells
    ids_1, completed_1 = read_and_validate_annotator_csv(REAL_LABELS_DIR / "worksheets_to_score_annotator_1.csv")
    ids_2, completed_2 = read_and_validate_annotator_csv(REAL_LABELS_DIR / "worksheets_to_score_annotator_2.csv")
    assert len(ids_1) == 60 and set(ids_1) == set(ids_2) == set(items.keys())
    assert ids_1 != ids_2
    assert completed_1 == {} and completed_2 == {}

    # Verify blinded packet leaks zero mode/model/split/gold metadata
    raw_pkt = (REAL_LABELS_DIR / "worksheets_packet_blinded.jsonl").read_text(encoding="utf-8")
    for leak_term in (
        "c0_fixed",
        "rule_engine",
        "c1_single",
        "c2_multi",
        "gpt-5-mini",
        "gold_disposition",
        "acceptable_dispositions",
        "investigator_agent",
    ):
        assert leak_term not in raw_pkt
