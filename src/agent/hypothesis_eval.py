"""
Competing Hypothesis Investigation & Independent Critique Engine (`src/agent/hypothesis_eval.py`).

Shared across BOTH `c1_single` and `c2_multi` so both architectures produce identical,
standardized `CompetingHypothesisAssessment`, `EvidenceClaim`, and `CriticAssessment` contracts:
  * Evaluates suspicious indicators (scatter-gather, multi-hop layering, staggered transfers,
    fee-skimming, contradictory KYC/income mismatch, missing beneficial ownership).
  * Evaluates benign explanations (marketplace settlement, payroll distribution, charitable/NGO
    collection, wedding/social pool, verified merchant settlement, corroborated commercial entity).
  * Distinguishes lack of evidence (`insufficient_evidence` / `additional_investigation_required`)
    from evidence that actively contradicts a hypothesis (`contradicted`).
  * Separates semantic/structural critique (`CriticAssessment`) from deterministic verification.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
import re
from typing import Any, Literal

from src.agent.planning import RunContext, sync_budget
from src.core.adapters import is_registered
from src.core.canonical import to_money
from src.core.claims import build_evidence_claims
from src.core.corroboration import assess_registration_corroboration, detect_missing_data
from src.core.investigation_contracts import (
    CompetingHypothesisAssessment,
    CriticAssessment,
    CriticChallenge,
    EvidenceClaim,
    EvidenceQuality,
    HypothesisEvaluation,
    HypothesisOutcome,
)
from src.models import Alert, FundFlowPath, HypothesisLabel, InvestigationState

_BENIGN_TYPOLOGY_CUES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("marketplace_settlement", ("marketplace", "escrow", "vendor", "settlement", "ecommerce", "merchant", "payout")),
    ("payroll_distribution", ("payroll", "salary", "wages", "stipend", "hr", "employee")),
    ("charitable_collection", ("charity", "charitable", "ngo", "80g", "donation", "relief", "trust", "foundation")),
    ("wedding_social_pool", ("wedding", "marriage", "family", "gift", "social", "pool", "chit", "kitty")),
)
_OWNERSHIP_GAP_CUES = (
    "beneficial owner",
    "ubo",
    "shell",
    "nominee",
    "unverified owner",
    "missing kyc",
    "unknown owner",
)
_TAG_STRIP = re.compile(r"<[^>]+>")


def _clean_text_corpus(
    transactions: Sequence[Mapping[str, Any]], kyc_profiles: Sequence[Mapping[str, Any]]
) -> str:
    parts: list[str] = []
    for tx in transactions[:40]:
        parts.append(str(tx.get("memo") or tx.get("memo_text") or ""))
    for k in kyc_profiles[:10]:
        for field in ("entity_name", "entity_type", "registry_type", "kyc_notes", "business_description"):
            parts.append(str(k.get(field) or ""))
    return _TAG_STRIP.sub(" ", " ".join(parts)).lower()


def _detect_benign_typologies(
    corpus_low: str, root_registered: bool, recurring_payroll: bool, merchants_verified: bool
) -> list[str]:
    found: list[str] = []
    for name, cues in _BENIGN_TYPOLOGY_CUES:
        if any(re.search(rf"\b{re.escape(c)}\b", corpus_low) for c in cues):
            found.append(name)
    if recurring_payroll and "payroll_distribution" not in found:
        found.append("payroll_distribution")
    if (root_registered or merchants_verified) and "commercial_settlement" not in found:
        found.append("commercial_settlement")
    return found or ["legitimate_commercial_or_personal_transfer"]


def _detect_suspicious_typologies(
    paths: Sequence[FundFlowPath],
    income_mismatch: bool,
    high_risk: bool,
    missing_ubo: bool,
) -> list[str]:
    found: list[str] = []
    multi = [p for p in paths if p.hop_count >= 2]
    if multi:
        found.append("scatter_gather_multi_hop")
    if any(p.time_span_days >= Decimal("7.00") for p in multi):
        found.append("staggered_transfer_layering")
    if any(p.retention_pct >= Decimal("5.00") for p in multi):
        found.append("possible_intermediary_fee_skimming")
    if income_mismatch or high_risk:
        found.append("contradictory_kyc_or_income_mismatch")
    if missing_ubo:
        found.append("missing_beneficial_ownership_context")
    return found or ["unexplained_fund_movement"]


def _evidence_quality(ev_ids: Sequence[str], degraded: Sequence[str], tool_errors: Sequence[Any]) -> EvidenceQuality:
    if not ev_ids:
        return "none"
    if tool_errors or len(degraded) >= 2:
        return "low"
    if len(ev_ids) >= 3:
        return "high"
    return "moderate"


def _root_kyc_record(root_account: str, kyc_profiles: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    for k in kyc_profiles:
        if str(k.get("account_id") or "") == root_account:
            return k
    return kyc_profiles[0] if kyc_profiles else {}


def _classify_outcomes(
    *,
    has_multi_hop: bool,
    flagged_path: bool,
    corroborated_benign: bool,
    merchants_verified_low_risk: bool,
    recurring_payroll_clean: bool,
    registry_uncorroborated: bool,
    has_kyc: bool,
    has_missing_data: bool,
    has_tool_errors: bool,
    can_replan_more: bool,
    has_transactions: bool,
) -> tuple[
    HypothesisOutcome, HypothesisOutcome, Literal["suspicious", "benign", "tie_inconclusive"], HypothesisOutcome, str
]:
    benign_strong = (corroborated_benign or merchants_verified_low_risk or recurring_payroll_clean) and not flagged_path
    susp_strong = has_multi_hop and not corroborated_benign and not recurring_payroll_clean

    if has_tool_errors and not has_multi_hop and not benign_strong:
        return (
            "insufficient_evidence",
            "insufficient_evidence",
            "tie_inconclusive",
            "insufficient_evidence",
            "Tool failures degraded evidence; lack of confirming records is not proof contradicting either hypothesis.",
        )
    if has_missing_data and (not susp_strong or not has_kyc or not flagged_path or registry_uncorroborated):
        next_out: HypothesisOutcome = (
            "additional_investigation_required" if can_replan_more else "insufficient_evidence"
        )
        return (
            next_out,
            next_out,
            "tie_inconclusive",
            next_out,
            "Key identity, counterparty, or downstream transfer records are missing; absence of evidence does not "
            "establish either criminal intent or benign legitimacy.",
        )
    if susp_strong and not benign_strong:
        benign_out: HypothesisOutcome = (
            "contradicted" if (registry_uncorroborated or flagged_path) else "insufficient_evidence"
        )
        return (
            "supported",
            benign_out,
            "suspicious",
            "supported",
            "Suspicious layering indicators are supported by reconstructed paths while benign commercial claims "
            "lack corroboration or are contradicted by multi-hop consolidation.",
        )
    if benign_strong and not susp_strong:
        return (
            "contradicted",
            "supported",
            "benign",
            "supported",
            "Corroborated registration, merchant verification, or regular counterparty cadence contradicts "
            "the illicit layering hypothesis.",
        )
    if susp_strong and benign_strong:
        return (
            "additional_investigation_required",
            "additional_investigation_required",
            "tie_inconclusive",
            "additional_investigation_required",
            "Both suspicious topology and plausible benign commercial indicators exist; contradicting evidence "
            "prevents confident closure without deeper investigation or human review.",
        )
    if has_transactions and not has_multi_hop and can_replan_more:
        return (
            "additional_investigation_required",
            "insufficient_evidence",
            "tie_inconclusive",
            "additional_investigation_required",
            "Outbound transfers are observed without multi-hop consolidation in the current window; additional "
            "bounded graph/counterparty investigation is required rather than inferring guilt or innocence.",
        )
    return (
        "insufficient_evidence",
        "insufficient_evidence",
        "tie_inconclusive",
        "insufficient_evidence",
        "Available evidence is insufficient to support or conclusively contradict either hypothesis.",
    )


def evaluate_competing_hypotheses(
    *,
    alert: Alert,
    transactions: Sequence[Mapping[str, Any]],
    fund_flow_paths: Sequence[FundFlowPath],
    kyc_profiles: Sequence[Mapping[str, Any]],
    regulatory_clauses: Sequence[Mapping[str, Any]],
    evidence_registry: Mapping[str, Any],
    degraded_evidence: Sequence[str] = (),
    tool_errors: Sequence[Mapping[str, Any]] = (),
    replan_count: int = 0,
    max_replans: int = 3,
) -> CompetingHypothesisAssessment:
    """Evaluate competing suspicious vs. benign hypotheses using grounded case evidence."""
    root = alert.root_account
    root_kyc = _root_kyc_record(root, kyc_profiles)
    recipients = [k for k in kyc_profiles if str(k.get("account_id") or "") != root]
    corr = assess_registration_corroboration(
        root, root_kyc, recipients, fund_flow_paths, transactions, evidence_registry
    )
    missing_rep = detect_missing_data(
        root,
        alert.network_accounts,
        transactions,
        fund_flow_paths,
        kyc_profiles,
        degraded_evidence,
        corr,
        at_max_window=replan_count >= max_replans,
    )
    multi = [p for p in fund_flow_paths if p.hop_count >= 2]
    flagged_path = any(p.is_suspicious for p in fund_flow_paths)
    risk = str(root_kyc.get("risk_category") or "").lower()
    raw_inc = root_kyc.get("declared_annual_income_inr")
    income = to_money(raw_inc) if raw_inc not in (None, "") else Decimal("0.00")
    income_mismatch = income > 0 and alert.total_amount_inr > income
    merchants_ok = bool(recipients) and all(is_registered(k) for k in recipients)
    corpus_low = _clean_text_corpus(transactions, kyc_profiles)
    missing_ubo = (not root_kyc) or any(c in corpus_low for c in _OWNERSHIP_GAP_CUES)

    susp_typs = _detect_suspicious_typologies(fund_flow_paths, income_mismatch, risk == "high", missing_ubo)
    benign_typs = _detect_benign_typologies(corpus_low, corr.registry_active, corr.recurring_payroll_12m, merchants_ok)

    path_ids = [p.path_id for p in fund_flow_paths if p.path_id in evidence_registry]
    tx_ids = [str(t["tx_id"]) for t in transactions[:6] if t.get("tx_id") and str(t["tx_id"]) in evidence_registry]
    kyc_ids = [
        str(k["evidence_id"])
        for k in kyc_profiles[:4]
        if k.get("evidence_id") and str(k["evidence_id"]) in evidence_registry
    ]
    reg_ids = [k for k in evidence_registry if str(k).startswith(("REGISTRY-", "CP-"))][:4]
    clause_ids = [str(c["clause_id"]) for c in regulatory_clauses[:3] if c.get("clause_id")]

    susp_claims: list[str] = []
    benign_claims: list[str] = []
    contradictions: list[str] = []

    if multi:
        p0 = multi[0]
        susp_claims.append(
            f"Multi-hop path {p0.path_id} spans {p0.time_span_days}d across {p0.hop_count} hops "
            f"(outflow INR {p0.total_outflow_inr}, consolidated INR {p0.total_consolidated_inr}, "
            f"retention {p0.retention_pct}%)."
        )
    if income_mismatch:
        susp_claims.append(f"Alert amount INR {alert.total_amount_inr} exceeds declared annual income INR {income}.")
    if risk == "high":
        susp_claims.append(f"Root account {root} carries HIGH KYC risk category.")
    if corr.registry_active and corr.corroborated_benign:
        benign_claims.append(
            f"Corroborated registration (score={corr.corroboration_score}, age_days={corr.registry_age_days}, "
            f"cp_tx={corr.counterparty_tx_count})."
        )
    elif corr.registry_active:
        contradictions.append(
            f"Registry flag active on {root} but uncorroborated or contradicted by multi-hop topology "
            f"(score={corr.corroboration_score}, age_days={corr.registry_age_days})."
        )
    if corr.recurring_payroll_12m and not multi:
        benign_claims.append(
            f"Recurring 12-month counterparty cadence ({corr.counterparty_tx_count} tx "
            f"over {corr.counterparty_span_days}d)."
        )
    if merchants_ok and risk == "low" and not multi:
        benign_claims.append("Low-risk customer transacting directly with commercially registered counterparties.")
    if multi and corr.registry_active and risk == "low":
        contradictions.append("Low-risk registered entity exhibits multi-hop scatter-gather consolidation.")

    missing_items = list(missing_rep.missing_evidence_items)
    if not kyc_profiles:
        missing_items.append("Root and counterparty KYC profiles not retrieved.")
    if not regulatory_clauses:
        missing_items.append("Applicable PMLA/RBI/FIU-IND regulatory clauses not retrieved.")
    if missing_ubo and "Beneficial ownership (UBO) documentation unavailable" not in missing_items:
        missing_items.append("Beneficial ownership (UBO) documentation unavailable.")
    missing_items = list(dict.fromkeys(missing_items))

    s_out, b_out, leader, overall, distinction = _classify_outcomes(
        has_multi_hop=bool(multi),
        flagged_path=flagged_path,
        corroborated_benign=corr.corroborated_benign,
        merchants_verified_low_risk=(merchants_ok and risk == "low" and not multi),
        recurring_payroll_clean=(corr.recurring_payroll_12m and not multi),
        registry_uncorroborated=(corr.registry_active and not corr.corroborated_benign),
        has_kyc=bool(kyc_profiles),
        has_missing_data=missing_rep.has_explicit_missing_data or (not kyc_profiles),
        has_tool_errors=bool(tool_errors),
        can_replan_more=(replan_count < max_replans),
        has_transactions=bool(transactions),
    )

    next_step = (
        "Expand graph window/hops or fetch counterparty history to resolve evidence gap."
        if overall == "additional_investigation_required"
        else "Request out-of-band KYC, UBO, or external-bank documentation before disposition."
        if overall == "insufficient_evidence"
        else "Submit evidence-grounded worksheet for independent critique, verification, and human review."
    )
    susp_ev_ids = list(dict.fromkeys([*path_ids, *tx_ids[:4], *kyc_ids[:2], *clause_ids[:2]]))
    benign_ev_ids = list(dict.fromkeys([*kyc_ids, *reg_ids, *tx_ids[:3], *clause_ids[:2]]))
    limitations = [
        *(f"Degraded evidence: {d}" for d in degraded_evidence[:3]),
        *(f"Tool failure: {e.get('tool')}:{e.get('error_code')}" for e in tool_errors[:3]),
    ] or ["Visibility limited to internal bank records and indexed synthetic registry data."]

    susp_eval = HypothesisEvaluation(
        hypothesis_id="HYP-SUSPICIOUS",
        label=HypothesisLabel.SUSPICIOUS,
        explanation=(
            f"Evaluated suspicious typologies ({', '.join(susp_typs)}) against reconstructed graph paths and KYC."
        ),
        candidate_typologies=susp_typs,
        outcome=s_out,
        supporting_evidence_ids=susp_ev_ids if susp_claims else [],
        contradicting_evidence_ids=benign_ev_ids if benign_claims else [],
        supporting_claims=susp_claims,
        contradicting_claims=benign_claims,
        evidence_quality=_evidence_quality(susp_ev_ids, degraded_evidence, tool_errors),
        missing_information=missing_items,
        unresolved_contradictions=contradictions,
        limitations=limitations,
        recommended_next_step=next_step,
    )
    benign_eval = HypothesisEvaluation(
        hypothesis_id="HYP-BENIGN",
        label=HypothesisLabel.BENIGN,
        explanation=(
            f"Evaluated legitimate explanations ({', '.join(benign_typs)}) "
            "using KYC, registry, and counterparty cadence."
        ),
        candidate_typologies=benign_typs,
        outcome=b_out,
        supporting_evidence_ids=benign_ev_ids if benign_claims else [],
        contradicting_evidence_ids=susp_ev_ids if susp_claims else [],
        supporting_claims=benign_claims,
        contradicting_claims=susp_claims,
        evidence_quality=_evidence_quality(benign_ev_ids, degraded_evidence, tool_errors),
        missing_information=missing_items,
        unresolved_contradictions=contradictions,
        limitations=limitations,
        recommended_next_step=next_step,
    )
    return CompetingHypothesisAssessment(
        suspicious=susp_eval,
        benign=benign_eval,
        leading_hypothesis=leader,
        overall_outcome=overall,
        distinction_note=distinction,
        unresolved_contradictions=contradictions,
        missing_information=missing_items,
        recommended_next_step=next_step,
    )


def run_independent_critique(
    *,
    assessment: CompetingHypothesisAssessment,
    specialist_findings: Sequence[Mapping[str, Any]],
    claims: Sequence[EvidenceClaim],
    recommended_disposition: str,
    regulatory_citations: Sequence[str],
    degraded_evidence: Sequence[str] = (),
    tool_errors: Sequence[Mapping[str, Any]] = (),
) -> CriticAssessment:
    """
    Independent structural/semantic critique separated from deterministic Verifier v2 checks.
    Flags unsupported conclusions, specialist inconsistencies, ignored contradictions, and gaps.
    """
    challenges: list[CriticChallenge] = []
    inconsistencies: list[str] = []
    ignored_contradictions: list[str] = []
    reg_gaps: list[str] = []
    uncertain: list[str] = []
    idx = 1

    def add_challenge(
        category: Any, severity: Literal["high", "medium", "low"], desc: str, ev_ids: Sequence[str] = ()
    ) -> None:
        nonlocal idx
        challenges.append(
            CriticChallenge(
                challenge_id=f"CRT-{idx:02d}",
                category=category,
                severity=severity,
                description=desc,
                evidence_ids=list(ev_ids)[:6],
            )
        )
        idx += 1

    bad_claims = [c for c in claims if c.verification_status in ("ungrounded", "wrong_case")]
    if bad_claims:
        add_challenge(
            "unsupported_conclusion",
            "high",
            f"{len(bad_claims)} material claim(s) failed deterministic grounding/case-ownership checks.",
            [eid for c in bad_claims for eid in c.evidence_ids],
        )

    if recommended_disposition == "close_benign" and assessment.benign.outcome != "supported":
        add_challenge(
            "unsupported_benign",
            "high",
            f"Disposition 'close_benign' proposed while benign hypothesis outcome is {assessment.benign.outcome!r}.",
            assessment.benign.contradicting_evidence_ids,
        )
    if recommended_disposition == "escalate_str" and assessment.suspicious.outcome == "contradicted":
        add_challenge(
            "unjustified_suspicious",
            "high",
            "Disposition 'escalate_str' proposed despite suspicious hypothesis being contradicted "
            "by corroborated benign evidence.",
            assessment.benign.supporting_evidence_ids,
        )

    if assessment.unresolved_contradictions:
        ignored_contradictions.extend(assessment.unresolved_contradictions)
        summary_c = "; ".join(assessment.unresolved_contradictions[:2])
        add_challenge(
            "contradictory_evidence",
            "medium",
            f"Unresolved contradiction(s) require reviewer review: {summary_c}",
        )

    if not regulatory_citations:
        reg_gaps.append("No verified regulatory citations attached to support the proposed disposition.")
        add_challenge("missing_regulatory_support", "high", reg_gaps[-1])

    flow_findings = [f for f in specialist_findings if f.get("agent_name") == "flow_tracer"]
    benign_findings = [f for f in specialist_findings if f.get("agent_name") == "benign_investigator"]
    if flow_findings and benign_findings:
        flow_replan = any(bool(f.get("recommended_replan")) for f in flow_findings)
        benign_txt = " ".join(str(f.get("summary") or "").lower() for f in benign_findings)
        benign_claimed = "benign" in benign_txt or "registered" in benign_txt
        if flow_replan and benign_claimed and assessment.benign.outcome != "supported":
            msg = (
                "flow_tracer flagged unresolved/suspicious flow gap while benign_investigator "
                "suggested benign context without full corroboration."
            )
            inconsistencies.append(msg)
            add_challenge("specialist_inconsistency", "medium", msg)

    if tool_errors or assessment.overall_outcome in ("insufficient_evidence", "additional_investigation_required"):
        uncertain.append(f"Overall investigation outcome is {assessment.overall_outcome!r}; human review required.")
        add_challenge(
            "incomplete_investigation",
            "medium" if not tool_errors else "high",
            f"Investigation incomplete (outcome={assessment.overall_outcome}, "
            f"tool_errors={len(tool_errors)}, degraded={len(degraded_evidence)}).",
        )

    high_sev = any(c.severity == "high" for c in challenges)
    return CriticAssessment(
        challenges=challenges,
        inconsistencies_found=inconsistencies,
        ignored_contradictions=ignored_contradictions,
        regulatory_grounding_gaps=reg_gaps,
        uncertain_findings=uncertain,
        passed_independent_critique=not high_sev,
        requires_additional_investigation=assessment.overall_outcome == "additional_investigation_required",
    )


async def hypothesis_evaluation_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    """
    Shared LangGraph node for BOTH live C1 and live C2:
    runs `evaluate_competing_hypotheses`, `build_evidence_claims`, and `run_independent_critique`.
    """
    assessment = evaluate_competing_hypotheses(
        alert=state.alert,
        transactions=state.transactions,
        fund_flow_paths=state.fund_flow_paths,
        kyc_profiles=state.kyc_profiles,
        regulatory_clauses=state.regulatory_clauses,
        evidence_registry=state.evidence_registry,
        degraded_evidence=state.degraded_evidence,
        tool_errors=state.tool_errors,
        replan_count=state.replan_count,
        max_replans=ctx.policy.budgets.max_replans,
    )
    ws = state.worksheet
    hyps_dicts = [h.model_dump(mode="json") for h in (ws.hypotheses if ws else state.active_hypotheses)]
    citations = list(ws.regulatory_citations) if ws else [
        str(c["clause_id"]) for c in state.regulatory_clauses if c.get("clause_id")
    ]
    claims = build_evidence_claims(
        rationale=ws.recommendation_rationale if ws else "",
        hypotheses=hyps_dicts,
        regulatory_citations=citations,
        evidence_registry=state.evidence_registry,
        alert_id=state.alert.alert_id,
        root_account=state.alert.root_account,
        network_accounts=state.alert.network_accounts,
        transactions=state.transactions,
    )
    disp = ws.recommended_disposition.value if ws else "pending"
    critic = run_independent_critique(
        assessment=assessment,
        specialist_findings=state.specialist_findings,
        claims=claims,
        recommended_disposition=disp,
        regulatory_citations=citations,
        degraded_evidence=state.degraded_evidence,
        tool_errors=state.tool_errors,
    )
    return {
        "hypothesis_assessment": assessment.model_dump(mode="json"),
        "evidence_claims": [c.model_dump(mode="json") for c in claims],
        "critic_assessment": critic.model_dump(mode="json"),
        "current_node": "hypothesis_evaluation",
        "current_step": state.current_step + 1,
        **sync_budget(ctx),
    }
