"""
Comprehensive tests for:
  * Section 10.C: Competing Suspicious vs. Benign Hypothesis Evaluation (all 10 scenarios)
  * Section 10.D: Claim-Level Evidence Grounding, Case Ownership & Independent Critique
  * Section 10.E: Structured Evidence-Driven Replanning & Before/After Comparison
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from src.agent.hypothesis_eval import evaluate_competing_hypotheses, run_independent_critique
from src.agent.tooling import GuardedToolbox
from src.agent.tools import AgentToolRuntime
from src.config import get_policy
from src.core.claims import build_evidence_claims, verify_claim_grounding
from src.core.investigation_contracts import EvidenceClaim
from src.core.verifier import verify_worksheet
from src.models import Alert, FundFlowPath, RiskLevel


def _alert(aid: str = "ALT-TEST-01", root: str = "ACC-ROOT-1", amt: str = "900000.00") -> Alert:
    return Alert(
        alert_id=aid,
        rule_name="SCATTER_GATHER_TEST",
        root_account=root,
        network_accounts=[root, "ACC-INT-1", "ACC-INT-2", "ACC-DST-1"],
        total_amount_inr=amt,
        risk_level=RiskLevel.HIGH,
    )


def _path(
    pid: str = "PATH-001",
    nodes: list[str] | None = None,
    outflow: str = "900000.00",
    cons: str = "828000.00",
    net: str = "72000.00",
    ret: str = "8.00",
    hops: int = 2,
    days: str = "11.00",
    susp: bool = True,
) -> FundFlowPath:
    return FundFlowPath(
        path_id=pid,
        nodes=nodes or ["ACC-ROOT-1", "ACC-INT-1", "ACC-DST-1"],
        edge_tx_ids=["TXN-1", "TXN-2"],
        total_outflow_inr=outflow,
        total_consolidated_inr=cons,
        net_difference_inr=net,
        retention_pct=ret,
        hop_count=hops,
        time_span_days=days,
        amount_leaked_ratio=Decimal("0.0800"),
        is_suspicious=susp,
        suspicion_reason="scatter_gather_consolidation" if susp else "none",
    )


def _clause() -> dict[str, Any]:
    return {
        "clause_id": "FIU-IND-RFI-BA-01",
        "title": "FIU-IND Alert Indicators",
        "category": "fiu_indicators",
        "text": "Rapid movement of funds through multiple accounts without economic rationale.",
    }


# ── Section 10.C: All 10 Competing Hypothesis Scenarios ──────────────────────────────────────────


def test_hypothesis_1_suspicious_scatter_gather_and_6_fee_skimming() -> None:
    p = _path(ret="8.00", days="3.00", susp=True)
    kyc = [
        {
            "evidence_id": "KYC-ACC-ROOT-1",
            "account_id": "ACC-ROOT-1",
            "risk_category": "high",
            "declared_annual_income_inr": "350000.00",
            "is_commercially_registered": False,
        }
    ]
    txs = [{"tx_id": "TXN-1", "sender_account": "ACC-ROOT-1", "receiver_account": "ACC-INT-1", "memo": "transfer"}]
    reg = {
        "PATH-001": p.model_dump(mode="json"),
        "KYC-ACC-ROOT-1": kyc[0],
        "TXN-1": txs[0],
        "FIU-IND-RFI-BA-01": _clause(),
    }
    res = evaluate_competing_hypotheses(
        alert=_alert(),
        transactions=txs,
        fund_flow_paths=[p],
        kyc_profiles=kyc,
        regulatory_clauses=[_clause()],
        evidence_registry=reg,
    )
    assert res.leading_hypothesis == "suspicious"
    assert res.suspicious.outcome == "supported"
    assert res.benign.outcome == "contradicted"
    assert "scatter_gather_multi_hop" in res.suspicious.candidate_typologies
    assert "possible_intermediary_fee_skimming" in res.suspicious.candidate_typologies
    assert "not a calibrated probability" in res.suspicious.score_note


@pytest.mark.parametrize(
    ("scenario", "memo", "registry_type", "expected_typology"),
    [
        ("marketplace", "monthly ecommerce marketplace escrow vendor payout", "GST", "marketplace_settlement"),
        ("payroll", "monthly employee salary payroll disbursement", "MCA", "payroll_distribution"),
        ("charity", "80g ngo charitable relief donation pool", "80G", "charitable_collection"),
        ("wedding_social", "family wedding social gift collection pool", "CHIT", "wedding_social_pool"),
    ],
)
def test_hypothesis_2_3_4_benign_marketplace_payroll_charity_and_social_pools(
    scenario: str, memo: str, registry_type: str, expected_typology: str
) -> None:
    kyc = [
        {
            "evidence_id": "KYC-ACC-ROOT-1",
            "account_id": "ACC-ROOT-1",
            "risk_category": "low",
            "declared_annual_income_inr": "5000000.00",
            "is_commercially_registered": True,
            "registry_type": registry_type,
            "registry_check": {
                "evidence_id": "REGISTRY-ACC-ROOT-1",
                "account_id": "ACC-ROOT-1",
                "is_registered": True,
                "registry_status": "ACTIVE",
                "registry_type": registry_type,
                "registration_age_days": 820,
            },
        },
        {
            "evidence_id": "KYC-ACC-INT-1",
            "account_id": "ACC-INT-1",
            "risk_category": "low",
            "is_commercially_registered": True,
            "registry_check": {"is_registered": True, "registry_status": "ACTIVE"},
        },
    ]
    txs = [{"tx_id": "TXN-1", "sender_account": "ACC-ROOT-1", "receiver_account": "ACC-INT-1", "memo": memo}]
    reg = {
        "KYC-ACC-ROOT-1": kyc[0],
        "KYC-ACC-INT-1": kyc[1],
        "REGISTRY-ACC-ROOT-1": kyc[0]["registry_check"],
        "CP-ACC-ROOT-1-ACC-INT-1": {
            "account_id": "ACC-ROOT-1",
            "counterparty_id": "ACC-INT-1",
            "historical_tx_count": 14,
            "span_days": 330,
            "recurring_cadence": True,
        },
        "TXN-1": txs[0],
        "FIU-IND-RFI-BA-01": _clause(),
    }
    res = evaluate_competing_hypotheses(
        alert=_alert(aid=f"ALT-{scenario}"),
        transactions=txs,
        fund_flow_paths=[],
        kyc_profiles=kyc,
        regulatory_clauses=[_clause()],
        evidence_registry=reg,
    )
    assert expected_typology in res.benign.candidate_typologies
    assert res.benign.outcome == "supported"
    assert res.suspicious.outcome == "contradicted"
    assert res.leading_hypothesis == "benign"


def test_hypothesis_5_staggered_7_contradictory_kyc_8_missing_ubo_9_insufficient_10_tie() -> None:
    # 5. Staggered transfers with outbound legs but 0 multi-hop yet -> additional_investigation_required
    txs = [{"tx_id": "TXN-1", "sender_account": "ACC-ROOT-1", "receiver_account": "ACC-INT-1", "memo": "phase 1"}]
    kyc_ok = [
        {
            "evidence_id": "KYC-ACC-ROOT-1",
            "account_id": "ACC-ROOT-1",
            "risk_category": "medium",
            "kyc_notes": "missing UBO nominee",
        }
    ]
    res_stag = evaluate_competing_hypotheses(
        alert=_alert(),
        transactions=txs,
        fund_flow_paths=[],
        kyc_profiles=kyc_ok,
        regulatory_clauses=[_clause()],
        evidence_registry={"TXN-1": txs[0], "KYC-ACC-ROOT-1": kyc_ok[0]},
        replan_count=0,
        max_replans=3,
    )
    assert res_stag.overall_outcome == "additional_investigation_required"
    assert "missing_beneficial_ownership_context" in res_stag.suspicious.candidate_typologies

    # 7. Contradictory KYC (forged/new registry + staggered multi-hop scatter-gather)
    p_stag = _path(days="14.00", susp=True)
    kyc_forged = [
        {
            "evidence_id": "KYC-ACC-ROOT-1",
            "account_id": "ACC-ROOT-1",
            "risk_category": "low",
            "is_commercially_registered": True,
            "registry_check": {
                "evidence_id": "REGISTRY-ACC-ROOT-1",
                "account_id": "ACC-ROOT-1",
                "is_registered": True,
                "registry_status": "ACTIVE",
                "registration_age_days": 12,
            },
        }
    ]
    res_contra = evaluate_competing_hypotheses(
        alert=_alert(),
        transactions=txs,
        fund_flow_paths=[p_stag],
        kyc_profiles=kyc_forged,
        regulatory_clauses=[_clause()],
        evidence_registry={"PATH-001": p_stag.model_dump(mode="json"), "KYC-ACC-ROOT-1": kyc_forged[0]},
    )
    assert "staggered_transfer_layering" in res_contra.suspicious.candidate_typologies
    assert res_contra.unresolved_contradictions
    assert res_contra.benign.outcome != "supported"

    # 9. Insufficient evidence (tool failures + missing KYC + max replans reached)
    res_insuff = evaluate_competing_hypotheses(
        alert=_alert(),
        transactions=[],
        fund_flow_paths=[],
        kyc_profiles=[],
        regulatory_clauses=[],
        evidence_registry={},
        tool_errors=[{"server": "bank-records", "tool": "get_kyc_profile", "error_code": "TIMEOUT"}],
        replan_count=3,
        max_replans=3,
    )
    assert res_insuff.overall_outcome == "insufficient_evidence"
    assert res_insuff.leading_hypothesis == "tie_inconclusive"
    assert "not proof contradicting" in res_insuff.distinction_note

    # 10. Equally plausible competing / topology-only with non-flagged path and no KYC -> does not infer guilt
    p_unflagged = _path(susp=False, ret="0.00", net="0.00", cons="900000.00", days="2.00")
    res_tie = evaluate_competing_hypotheses(
        alert=_alert(),
        transactions=txs,
        fund_flow_paths=[p_unflagged],
        kyc_profiles=[],
        regulatory_clauses=[_clause()],
        evidence_registry={"PATH-001": p_unflagged.model_dump(mode="json")},
        replan_count=3,
        max_replans=3,
    )
    assert res_tie.leading_hypothesis == "tie_inconclusive"
    assert res_tie.overall_outcome == "insufficient_evidence"


# ── Section 10.D: Evidence Verification, Case Ownership & Independent Critique ───────────────────


def test_evidence_verification_wrong_case_ungrounded_claims_and_critic_challenges() -> None:
    p = _path()
    reg = {
        "PATH-001": p.model_dump(mode="json"),
        "KYC-ACC-ROOT-1": {"account_id": "ACC-ROOT-1", "alert_id": "ALT-TEST-01", "risk_category": "high"},
        "TXN-OTHER-99": {
            "tx_id": "TXN-OTHER-99",
            "alert_id": "ALT-DIFFERENT-999",
            "sender_account": "ACC-FOREIGN-1",
            "receiver_account": "ACC-FOREIGN-2",
            "amount_inr": "500000.00",
        },
        "FIU-IND-RFI-BA-01": _clause(),
    }

    # Wrong-case evidence reference rejected deterministically
    claims = [
        EvidenceClaim(claim_id="CLM-1", claim_text="Valid path claim", evidence_ids=["PATH-001"]),
        EvidenceClaim(claim_id="CLM-2", claim_text="Foreign tx claim", evidence_ids=["TXN-OTHER-99"]),
        EvidenceClaim(claim_id="CLM-3", claim_text="Missing ID claim", evidence_ids=["TXN-NONEXISTENT"]),
        EvidenceClaim(claim_id="CLM-4", claim_text="Empty evidence claim", evidence_ids=[]),
    ]
    checked = verify_claim_grounding(claims, reg, alert_id="ALT-TEST-01", root_account="ACC-ROOT-1")
    assert checked[0].verification_status == "verified"
    assert checked[1].verification_status == "wrong_case"
    assert checked[2].verification_status == "ungrounded"
    assert checked[3].verification_status == "ungrounded"

    # verify_worksheet rejects wrong-case evidence, ungrounded claims, and bad INR math
    bad_ws = {
        "alert_id": "ALT-TEST-01",
        "recommended_disposition": "escalate_str",
        "confidence_score": "0.85",
        "recommendation_rationale": "Moved INR 999,999.00 referencing TXN-OTHER-99 under FIU-IND-RFI-BA-01.",
        "candidate_paths": [p.model_dump(mode="json")],
        "regulatory_citations": ["FIU-IND-RFI-BA-01"],
        "hypotheses": [
            {
                "label": "suspicious",
                "explanation": "Path PATH-001 layering",
                "confidence": "0.85",
                "evidence_ids": ["PATH-001"],
            },
            {
                "label": "benign",
                "explanation": "Checked KYC-ACC-ROOT-1",
                "confidence": "0.15",
                "evidence_ids": ["KYC-ACC-ROOT-1"],
            },
        ],
        "claims": [c.model_dump(mode="json") for c in claims],
        "missing_evidence": ["External logs"],
    }
    vr = verify_worksheet(bad_ws, reg)
    assert vr.passed is False
    assert vr.checks["evidence_case_ownership"] is False
    assert vr.checks["claims_grounded"] is False
    assert vr.checks["numbers_match_calc"] is False

    # Independent Critic catches unsupported benign, missing regulatory support, and specialist inconsistency
    assessment = evaluate_competing_hypotheses(
        alert=_alert(),
        transactions=[],
        fund_flow_paths=[p],
        kyc_profiles=[reg["KYC-ACC-ROOT-1"]],
        regulatory_clauses=[],
        evidence_registry=reg,
    )
    critic = run_independent_critique(
        assessment=assessment,
        specialist_findings=[
            {"agent_name": "flow_tracer", "summary": "Flagged multi-hop gap", "recommended_replan": {"expand": True}},
            {"agent_name": "benign_investigator", "summary": "Looks benign registered merchant"},
        ],
        claims=checked,
        recommended_disposition="close_benign",
        regulatory_citations=[],
    )
    cats = {c.category for c in critic.challenges}
    assert critic.passed_independent_critique is False
    expected_cats = {
        "unsupported_conclusion",
        "unsupported_benign",
        "missing_regulatory_support",
        "specialist_inconsistency",
    }
    assert expected_cats <= cats

    # build_evidence_claims populates verifiable claim list
    built = build_evidence_claims(
        rationale="Path PATH-001 under FIU-IND-RFI-BA-01.",
        hypotheses=bad_ws["hypotheses"],
        regulatory_citations=["FIU-IND-RFI-BA-01"],
        evidence_registry=reg,
        alert_id="ALT-TEST-01",
        root_account="ACC-ROOT-1",
    )
    assert built and all(c.verification_status == "verified" for c in built)


# ── Section 10.E: Structured Replanning, Bounds, Preservation & Failed Replans ─────────────────


@pytest.mark.asyncio
async def test_replanning_preserves_initial_paths_compares_before_after_and_enforces_limits() -> None:
    alert = Alert(
        alert_id="ALT-2026-0412",
        rule_name="SCATTER_GATHER_900K",
        root_account="ACC-IND-1042",
        total_amount_inr="900000.00",
        risk_level=RiskLevel.HIGH,
    )
    policy = get_policy().model_copy(
        update={"budgets": get_policy().budgets.model_copy(update={"max_replans": 2, "max_tool_calls": 10})}
    )
    rt = AgentToolRuntime(
        role="c1_single",
        box=GuardedToolbox("c1_single", policy.new_ledger(), "thr-replan-test"),
        alert=alert,
    )
    await rt.execute("get_alert_context", {"alert_id": "ALT-2026-0412"})
    await rt.execute("find_candidate_fund_flows", {"root_account": "ACC-IND-1042"})
    initial_paths_snapshot = list(rt.fund_flow_paths)
    assert len(rt.initial_fund_flow_paths) == len(initial_paths_snapshot)

    # 1. Out-of-bounds replan rejected & recorded
    bad_b = await rt.execute(
        "replan_graph", {"time_window_days": 99, "max_hops": 9, "amount_tolerance": "0.10", "reason": "too wide"}
    )
    assert bad_b["error_code"] == "POLICY_BOUNDS_EXCEEDED"
    assert rt.replan_records[-1]["validation_result"] == "rejected_bounds"
    assert rt.replan_records[-1]["execution_status"] == "skipped"

    # 2. Valid replan improves coverage & preserves initial_fund_flow_paths
    ok_r1 = await rt.execute(
        "replan_graph",
        {
            "time_window_days": 18,
            "max_hops": 4,
            "amount_tolerance": "0.15",
            "reason": "Staggered Day-11 consolidation beyond 7d window",
        },
    )
    assert ok_r1.get("status") != "error" and rt.replan_count == 1
    assert rt.initial_fund_flow_paths == initial_paths_snapshot  # initial findings preserved!
    rec1 = rt.replan_records[-1]
    assert rec1["trigger_condition"] == "staggered_transaction_window"
    assert rec1["validation_result"] == "approved" and rec1["execution_status"] == "executed"
    assert rec1["comparison"]["before"]["time_window_days"] == 7
    assert rec1["comparison"]["after"]["time_window_days"] == 18
    assert rec1["comparison"]["improved"] is True

    # 3. Non-improving replan recorded transparently with improved=False
    ok_r2 = await rt.execute(
        "replan_graph",
        {"time_window_days": 20, "max_hops": 4, "amount_tolerance": "0.15", "reason": "Verify no deeper paths"},
    )
    assert ok_r2.get("status") != "error" and rt.replan_count == 2
    assert rt.replan_records[-1]["comparison"]["improved"] is False

    # 4. Max replans exceeded -> rejected_budget
    over = await rt.execute(
        "replan_graph",
        {"time_window_days": 25, "max_hops": 5, "amount_tolerance": "0.20", "reason": "Over max replans"},
    )
    assert over["error_code"] == "REPLAN_BUDGET_EXCEEDED"
    assert rt.replan_records[-1]["validation_result"] == "rejected_budget"
