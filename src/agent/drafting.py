"""
Shared, FAIL-CLOSED worksheet drafting used by C0 / C1 / C2.

1. Build the narrative (deterministic base; optionally LLM-synthesised, grounded on verified facts only).
2. Run the deterministic verifier against the run's evidence registry.
3. On failure feed the exact structured discrepancies back into the next attempt (up to max_critique_retries,
   enforced by the BudgetLedger). Only attempts that can change (live LLM) are retried.
4. If it still fails, the worksheet is routed to `request_info` with `verification_status=failed`, which blocks
   normal disposition commit until an analyst edit passes verification.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.agent.llm_client import synthesize_investigation_narrative
from src.agent.tooling import GuardedToolbox, is_error
from src.core.canonical import dec_str
from src.core.policy import BudgetLedger
from src.core.verifier import verify_worksheet
from src.models import (
    Alert,
    DispositionDecision,
    DispositionWorksheet,
    FundFlowPath,
    Hypothesis,
    HypothesisLabel,
)


class DraftError(RuntimeError):
    """The case-actions draft call failed; no worksheet exists."""


@dataclass
class DraftOutcome:
    worksheet: DispositionWorksheet
    verification_failed: bool
    discrepancies: list[dict[str, Any]]
    llm_model: str


def _payload(
    *, alert: Alert, thread_id: str, disposition: DispositionDecision, rationale: str, confidence: float,
    paths: list[FundFlowPath], hypotheses: list[Hypothesis], citations: list[str], summaries: list[str],
    degraded: list[str], status: str, discrepancies: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "thread_id": thread_id,
        "recommended_disposition": disposition.value,
        "recommendation_rationale": rationale,
        "confidence_score": confidence,
        "candidate_paths": [p.model_dump() for p in paths[:3]],
        "regulatory_citations": citations,
        "kyc_summaries": summaries,
        "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
        "degraded_evidence": degraded,
        "alert_amount_inr": dec_str(alert.total_amount_inr),
        "verification_status": status,
        "verification_discrepancies": discrepancies,
    }


def _with_llm_text(hypotheses: list[Hypothesis], llm_out: Mapping[str, Any]) -> list[Hypothesis]:
    copies = [h.model_copy(deep=True) for h in hypotheses]
    if llm_out.get("used_live_llm"):
        for hyp in copies:
            override = llm_out.get("suspicious_explanation") if hyp.label == HypothesisLabel.SUSPICIOUS else llm_out.get("benign_explanation")
            if override:
                hyp.explanation = override
    return copies


async def draft_and_verify(
    *, box: GuardedToolbox, ledger: BudgetLedger, alert: Alert, agent_label: str, thread_id: str,
    disposition: DispositionDecision, confidence: float, paths: list[FundFlowPath], hypotheses: list[Hypothesis],
    citations: list[str], summaries: list[str], registry: Mapping[str, Any], replan_count: int, base_rationale: str,
    degraded: list[str], use_strong_model: bool, verify: bool = True,
) -> DraftOutcome:
    feedback: list[dict[str, Any]] = []
    rationale, hyps, llm_model = base_rationale, hypotheses, "offline-deterministic"
    discrepancies: list[dict[str, Any]] = []
    passed = True

    while True:
        llm_out = await synthesize_investigation_narrative(
            alert_id=alert.alert_id, disposition=disposition.value, confidence=confidence,
            paths_summary=[p.model_dump(mode="json") for p in paths[:3]], kyc_summaries=summaries, citations=citations,
            replan_count=replan_count, fallback_rationale=base_rationale, use_strong_model=use_strong_model,
            ledger=ledger, verifier_feedback=feedback,
        )
        rationale, llm_model = llm_out["rationale"], llm_out["model"]
        hyps = _with_llm_text(hypotheses, llm_out)
        candidate = _payload(
            alert=alert, thread_id=thread_id, disposition=disposition, rationale=rationale, confidence=confidence,
            paths=paths, hypotheses=hyps, citations=citations, summaries=summaries, degraded=degraded,
            status="passed", discrepancies=[],
        )
        if not verify:
            break
        result = verify_worksheet(candidate, registry)
        passed = result.passed
        discrepancies = [d.model_dump() for d in result.discrepancies]
        if passed or not llm_out["used_live_llm"]:
            break
        feedback = discrepancies
        if not ledger.try_critique_retry().allowed:
            break

    failed = verify and not passed
    if failed:
        codes = sorted({d["code"] for d in discrepancies})
        rationale = f"{base_rationale} [VERIFICATION FAILED - manual review required: {', '.join(codes)}]"
        hyps = [h.model_copy(deep=True) for h in hypotheses]
        disposition = DispositionDecision.REQUEST_INFO
    payload = _payload(
        alert=alert, thread_id=thread_id, disposition=disposition, rationale=rationale, confidence=confidence,
        paths=paths, hypotheses=hyps, citations=citations, summaries=summaries, degraded=degraded,
        status="failed" if failed else "passed", discrepancies=discrepancies if failed else [],
    )
    draft = await box.call("case-actions", "draft_disposition_report", payload)
    if is_error(draft):
        raise DraftError(f"draft_disposition_report failed: {draft.get('error_code') or draft.get('error')}")
    worksheet = DispositionWorksheet(
        worksheet_id=draft["worksheet_id"], alert_id=alert.alert_id, investigator_agent=f"{agent_label} ({llm_model})",
        candidate_paths=paths[:3], hypotheses=hyps, regulatory_citations=citations, kyc_summaries=summaries,
        recommended_disposition=disposition, recommendation_rationale=rationale, confidence_score=confidence,
        payload_hash=draft["payload_hash"],
    )
    return DraftOutcome(worksheet, failed, discrepancies if failed else [], llm_model)


def security_notes(box: GuardedToolbox) -> list[str]:
    return sorted({f"Prompt-injection attempt detected in {e['source']}; content withheld" for e in box.security_events})


__all__ = ["DraftError", "DraftOutcome", "draft_and_verify", "security_notes"]
