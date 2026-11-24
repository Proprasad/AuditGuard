"""
Phase 3 — Verifier v2 Acceptance & Negative Test Suite (`tests/test_verifier_v2.py`).

Covers all 6 named checks in `verify_worksheet(ws, evidence_registry, corpus_ids, calc_log)`:
  1. `numbers_match_calc` (`INR`, `₹`, `Rs.`, lakh/crore, `%`, ₹0.01 Decimal tolerance,
     `inr_error_count`, `inr_numbers_total`, and `verify_inr_math`)
  2. `citations_exist` (fake citation `PMLA-2002-S13` caught even if injected into `evidence_registry`)
  3. `citations_relevant` (typology category map + separate `deterministic_citation_relevant`
     and `judge_citation_relevant` signals)
  4. `evidence_ids_registered` (`TXN-*/KYC-*/REGISTRY-*/CALC-*` resolved AND each material claim >= 1 ID)
  5. `no_guilt_claims` (`"has clearly laundered"`, `"is a criminal"`, paraphrases caught; negations allowed)
  6. `both_hypotheses_present` and `missing_evidence_stated`
  7. E4 `"no_verifier"` vs `"verifier on"` ablation semantics
"""

from __future__ import annotations

from typing import Any

import pytest

from src.agent.c1_single import run_investigation
from src.guardrails.verifier import load_corpus_category_map, verify_inr_math, verify_worksheet
from src.models import Alert, DispositionDecision, RiskLevel
from tests.fakes import FakeLLM, make_text_turn, make_tool_turn

ALERT = Alert(
    alert_id="ALT-2026-0412",
    rule_name="SCATTER_GATHER_900K",
    root_account="ACC-IND-1042",
    total_amount_inr="900000.00",
    risk_level=RiskLevel.HIGH,
)


def _valid_fixture() -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    registry: dict[str, Any] = {
        "TXN-1001": {"tx_id": "TXN-1001", "amount_inr": "900000.00"},
        "KYC-ACC-IND-1042": {"evidence_id": "KYC-ACC-IND-1042", "declared_annual_income_inr": "450000.00"},
        "REGISTRY-NONE-ACC-IND-1042": {"evidence_id": "REGISTRY-NONE-ACC-IND-1042", "is_registered": False},
        "PATH-SG01": {
            "path_id": "PATH-SG01",
            "total_outflow_inr": "900000.00",
            "total_consolidated_inr": "828000.00",
            "net_difference_inr": "72000.00",
            "retention_pct": "8.00",
        },
        "CALC-FEE01": {"calc_id": "CALC-FEE01", "op": "diff", "result_inr": "72000.00", "amount_inr": "72000.00"},
        "FIU-IND-RFI-BA-01": {"clause_id": "FIU-IND-RFI-BA-01", "category": "layering"},
        "RBI-KYC-2016-P35-P04": {"clause_id": "RBI-KYC-2016-P35-P04", "category": "commercial_verification"},
    }
    calc_log = [
        {"calc_id": "CALC-FEE01", "result_inr": "72000.00"},
        {"calc_id": "CALC-PCT01", "result_pct": "8.00", "percentage": "8.00%"},
    ]
    ws: dict[str, Any] = {
        "alert_id": "ALT-2026-0412",
        "recommended_disposition": "escalate_str",
        "confidence_score": "0.8600",
        "recommendation_rationale": (
            "Path PATH-SG01 dispersed INR 9,00,000.00 (9 lakhs) and consolidated INR 8,28,000.00 "
            "retaining INR 72,000.00 (8.00%) per CALC-FEE01 under FIU-IND-RFI-BA-01. "
            "Missing evidence: Destination beneficiary source-of-wealth statements."
        ),
        "candidate_paths": [
            {
                "path_id": "PATH-SG01",
                "total_outflow_inr": "900000.00",
                "total_consolidated_inr": "828000.00",
                "net_difference_inr": "72000.00",
                "retention_pct": "8.00",
            }
        ],
        "regulatory_citations": ["FIU-IND-RFI-BA-01", "RBI-KYC-2016-P35-P04"],
        "hypotheses": [
            {
                "label": "suspicious",
                "explanation": "Multi-hop consolidation on PATH-SG01 from TXN-1001 with 8.00% retention.",
                "confidence": "0.8600",
                "evidence_ids": ["PATH-SG01", "TXN-1001", "CALC-FEE01"],
                "regulatory_citations": ["FIU-IND-RFI-BA-01"],
            },
            {
                "label": "benign",
                "explanation": "Checked commercial status via KYC-ACC-IND-1042 and REGISTRY-NONE-ACC-IND-1042.",
                "confidence": "0.1400",
                "evidence_ids": ["KYC-ACC-IND-1042", "REGISTRY-NONE-ACC-IND-1042"],
                "regulatory_citations": ["RBI-KYC-2016-P35-P04"],
            },
        ],
        "missing_evidence": ["Destination beneficiary source-of-wealth statements"],
        "alert_amount_inr": "900000.00",
    }
    return ws, registry, calc_log


def test_verifier_correct_worksheet_and_cent_tolerance() -> None:
    ws, registry, calc_log = _valid_fixture()
    corpus_ids = set(load_corpus_category_map().keys())
    vr = verify_worksheet(ws, registry, corpus_ids, calc_log)

    assert vr.passed is True, vr.errors
    assert vr.inr_error_count == 0
    assert vr.inr_numbers_total >= 8
    assert vr.deterministic_citation_relevant is True
    assert vr.judge_citation_relevant is None
    for required_check in (
        "numbers_match_calc",
        "citations_exist",
        "citations_relevant",
        "evidence_ids_registered",
        "no_guilt_claims",
        "both_hypotheses_present",
        "missing_evidence_stated",
    ):
        assert vr.checks[required_check] is True

    # Within ₹0.01 Decimal tolerance passes; ₹0.02 deviation fails
    ws_cent = {**ws, "recommendation_rationale": "Dispersed INR 900000.01 on PATH-SG01. Missing evidence: invoices."}
    assert verify_worksheet(ws_cent, registry, corpus_ids, calc_log).passed is True

    ws_two_cents = {
        **ws,
        "recommendation_rationale": "Dispersed INR 900000.02 on PATH-SG01. Missing evidence: invoices.",
    }
    vr_two = verify_worksheet(ws_two_cents, registry, corpus_ids, calc_log)
    assert vr_two.passed is False and vr_two.checks["numbers_match_calc"] is False
    assert vr_two.inr_error_count == 1

    ok_math, _ = verify_inr_math("900000.00", "828000.00", tolerance="0.10")
    bad_math, _ = verify_inr_math("900000.00", "700000.00", tolerance="0.10")
    assert ok_math is True and bad_math is False


@pytest.mark.parametrize(
    ("mutated_rationale", "expected_code", "expected_err_count"),
    [
        (
            "Path PATH-SG01 dispersed INR 900,500.00 under FIU-IND-RFI-BA-01. Missing evidence: invoices.",
            "UNGROUNDED_AMOUNT",
            1,
        ),
        (
            "Path PATH-SG01 consolidated 8.50 lakhs under FIU-IND-RFI-BA-01. Missing evidence: invoices.",
            "UNGROUNDED_AMOUNT",
            1,
        ),
        (
            "Path PATH-SG01 moved 1.25 crores under FIU-IND-RFI-BA-01. Missing evidence: invoices.",
            "UNGROUNDED_AMOUNT",
            1,
        ),
        (
            "Path PATH-SG01 retained 11.25% commission under FIU-IND-RFI-BA-01. Missing evidence: invoices.",
            "UNGROUNDED_PERCENTAGE",
            1,
        ),
        (
            "Path PATH-SG01 moved INR 999,999.00 with 14.50% skim under FIU-IND-RFI-BA-01. Missing evidence: invoices.",
            "UNGROUNDED_AMOUNT",
            2,
        ),
    ],
)
def test_verifier_seeded_wrong_numbers_each_caught(
    mutated_rationale: str, expected_code: str, expected_err_count: int
) -> None:
    ws, registry, calc_log = _valid_fixture()
    ws["recommendation_rationale"] = mutated_rationale
    vr = verify_worksheet(ws, registry, None, calc_log)

    assert vr.passed is False
    assert vr.checks["numbers_match_calc"] is False
    assert vr.inr_error_count == expected_err_count
    assert any(d.code == expected_code for d in vr.discrepancies)


def test_verifier_fake_citation_pmla_2002_s13_and_dual_relevance_signals() -> None:
    ws, registry, calc_log = _valid_fixture()
    # Even if PMLA-2002-S13 is injected into evidence_registry, corpus index check MUST reject it!
    registry_with_fake = {**registry, "PMLA-2002-S13": {"clause_id": "PMLA-2002-S13", "category": "layering"}}
    ws_fake = {**ws, "regulatory_citations": ["PMLA-2002-S13"]}
    vr_fake = verify_worksheet(ws_fake, registry_with_fake, None, calc_log)
    assert vr_fake.passed is False
    assert vr_fake.checks["citations_exist"] is False
    assert any(d.code == "UNRESOLVED_CITATION" and "PMLA-2002-S13" in d.detail for d in vr_fake.discrepancies)

    # Irrelevant corpus clause (`SOP-MEM-001` memory_policy) fails deterministic relevance
    reg_mem = {**registry, "SOP-MEM-001": {"clause_id": "SOP-MEM-001", "category": "memory_policy"}}
    ws_irrel = {
        **ws,
        "regulatory_citations": ["SOP-MEM-001"],
        "hypotheses": [
            {**ws["hypotheses"][0], "regulatory_citations": ["SOP-MEM-001"]},
            {**ws["hypotheses"][1], "regulatory_citations": ["SOP-MEM-001"]},
        ],
    }
    vr_irrel = verify_worksheet(ws_irrel, reg_mem, None, calc_log)
    assert vr_irrel.passed is False
    assert vr_irrel.deterministic_citation_relevant is False
    assert vr_irrel.judge_citation_relevant is None
    assert vr_irrel.checks["citations_relevant"] is False
    assert any(d.code == "IRRELEVANT_CITATION" for d in vr_irrel.discrepancies)

    # Dual-signal check: when Phase 4 judge marks citation relevant (`judge_citation_relevant=True`),
    # both signals remain stored separately while `citations_relevant` becomes True!
    vr_judged = verify_worksheet(ws_irrel, reg_mem, None, calc_log, judge_citation_relevant=True)
    assert vr_judged.deterministic_citation_relevant is False
    assert vr_judged.judge_citation_relevant is True
    assert vr_judged.checks["citations_relevant"] is True


def test_verifier_evidence_ids_registered_and_material_claims_require_ids() -> None:
    ws, registry, calc_log = _valid_fixture()
    for ghost_id in ("TXN-GHOST-1", "KYC-GHOST-1", "REGISTRY-GHOST-1", "CALC-GHOST-1"):
        ws_ghost = {
            **ws,
            "recommendation_rationale": f"Verified {ghost_id} under FIU-IND-RFI-BA-01. Missing evidence: invoices.",
        }
        vr = verify_worksheet(ws_ghost, registry, None, calc_log)
        assert vr.passed is False
        assert vr.checks["evidence_ids_registered"] is False
        assert any(d.code == "UNRESOLVED_EVIDENCE_ID" for d in vr.discrepancies)

    # Hypothesis with zero evidence IDs fails `evidence_ids_registered` (`UNCITED_MATERIAL_CLAIM`)
    ws_uncited_hyp = {
        **ws,
        "hypotheses": [
            {
                "label": "suspicious",
                "explanation": "Generic ungrounded suspicious claim without any ID.",
                "confidence": "0.8600",
                "evidence_ids": [],
                "regulatory_citations": ["FIU-IND-RFI-BA-01"],
            },
            ws["hypotheses"][1],
        ],
    }
    vr_uncited = verify_worksheet(ws_uncited_hyp, registry, None, calc_log)
    assert vr_uncited.passed is False
    assert vr_uncited.checks["evidence_ids_registered"] is False
    assert any(d.code == "UNCITED_MATERIAL_CLAIM" for d in vr_uncited.discrepancies)


@pytest.mark.parametrize(
    "guilt_text",
    [
        "The account holder has clearly laundered funds through intermediaries.",
        "R. Verma is a criminal operating shell accounts.",
        "Investigation proves the subject definitely laundered the proceeds.",
        "The entity is blatantly a money launderer.",
        "Criminal guilt has been established across all three legs.",
        "Customer perpetrated money laundering over 14 days.",
    ],
)
def test_verifier_guilt_paraphrases_caught_and_negations_pass(guilt_text: str) -> None:
    ws, registry, calc_log = _valid_fixture()
    ws_bad = {**ws, "recommendation_rationale": f"{guilt_text} [PATH-SG01]. Missing evidence: invoices."}
    vr = verify_worksheet(ws_bad, registry, None, calc_log)
    assert vr.passed is False
    assert vr.checks["no_guilt_claims"] is False
    assert any(d.code == "PROHIBITED_CLAIM" for d in vr.discrepancies)

    # Safe compliance disclaimer with explicit negation must pass cleanly
    ws_safe = {
        **ws,
        "recommendation_rationale": (
            "Escalated PATH-SG01 under FIU-IND-RFI-BA-01 without asserting the customer is a criminal "
            "or that money laundering has occurred. Missing evidence: beneficiary invoices."
        ),
    }
    vr_safe = verify_worksheet(ws_safe, registry, None, calc_log)
    assert vr_safe.passed is True and vr_safe.checks["no_guilt_claims"] is True


def test_verifier_both_hypotheses_and_missing_evidence_required() -> None:
    ws, registry, calc_log = _valid_fixture()
    ws_one_hyp = {**ws, "hypotheses": [ws["hypotheses"][0]]}
    vr_one = verify_worksheet(ws_one_hyp, registry, None, calc_log)
    assert vr_one.passed is False and vr_one.checks["both_hypotheses_present"] is False

    ws_no_missing = {
        **ws,
        "missing_evidence": [],
        "degraded_evidence": [],
        "recommendation_rationale": "Path PATH-SG01 dispersed INR 900000.00 under FIU-IND-RFI-BA-01.",
    }
    vr_no_missing = verify_worksheet(ws_no_missing, registry, None, calc_log)
    assert vr_no_missing.passed is False and vr_no_missing.checks["missing_evidence_stated"] is False


@pytest.mark.asyncio
async def test_e4_no_verifier_ablation_vs_verifier_on() -> None:
    def _ungrounded_finish(messages: list[dict[str, Any]], _: Any) -> Any:
        import json

        reg_out = next(json.loads(m["content"]) for m in messages if m.get("name") == "search_regulations")
        kyc_out = next(json.loads(m["content"]) for m in messages if m.get("name") == "get_kyc_profile")
        cid = reg_out["clauses"][0]["clause_id"]
        kid = kyc_out["evidence_id"]
        return make_tool_turn(
            (
                "finish",
                {
                    "recommended_disposition": "escalate_str",
                    "confidence_score": "0.85",
                    "recommendation_rationale": f"Seed {kid} dispersed unverified INR 777,777.00 under {cid}.",
                    "suspicious_hypothesis": {
                        "explanation": f"Suspicious flow from {kid}.",
                        "confidence": "0.85",
                        "evidence_ids": [kid],
                        "regulatory_citations": [cid],
                    },
                    "benign_hypothesis": {
                        "explanation": f"Checked commercial profile {kid}.",
                        "confidence": "0.15",
                        "evidence_ids": [kid],
                        "regulatory_citations": [cid],
                    },
                    "missing_evidence": ["Beneficiary bank statements"],
                    "regulatory_citations": [cid],
                },
            )
        )

    steps = [
        make_tool_turn(
            ("get_alert_context", {"alert_id": "ALT-2026-0412"}),
            ("get_kyc_profile", {"account_id": "ACC-IND-1042"}),
            ("search_regulations", {"query": "scatter gather layering", "top_k": 2}),
        ),
        _ungrounded_finish,
        make_text_turn("No valid repair provided"),
    ]

    # 1. E4 `no_verifier`: checks still run and record UNGROUNDED_AMOUNT, but do NOT repair or downgrade!
    st_off = await run_investigation(ALERT, llm_client=FakeLLM(steps), deterministic_verifier=False)
    assert st_off.critique_retries_used == 0
    assert st_off.worksheet is not None
    assert st_off.worksheet.recommended_disposition == DispositionDecision.ESCALATE_STR
    assert any(d["code"] == "UNGROUNDED_AMOUNT" for d in st_off.worksheet.verification_discrepancies)

    # 2. `verifier on`: failed check triggers repair retry and downgrades to `request_info` when unverified!
    st_on = await run_investigation(ALERT, llm_client=FakeLLM(steps), deterministic_verifier=True)
    assert st_on.critique_retries_used == 1
    assert st_on.worksheet is not None
    assert st_on.worksheet.recommended_disposition == DispositionDecision.REQUEST_INFO
