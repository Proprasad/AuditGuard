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

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from src.agent.llm_client import synthesize_investigation_narrative
from src.agent.tooling import GuardedToolbox, is_error
from src.core.canonical import dec_str, to_confidence
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


DEFAULT_MISSING_EVIDENCE = ["Out-of-network beneficiary bank statements and source-of-funds documentation"]


def _payload(
    *,
    alert: Alert,
    thread_id: str,
    disposition: DispositionDecision,
    rationale: str,
    confidence: float,
    paths: list[FundFlowPath],
    hypotheses: list[Hypothesis],
    citations: list[str],
    summaries: list[str],
    degraded: list[str],
    status: str,
    discrepancies: list[dict[str, Any]],
    missing_evidence: Optional[list[str]] = None,
) -> dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "thread_id": thread_id,
        "recommended_disposition": disposition.value,
        "recommendation_rationale": rationale,
        "confidence_score": dec_str(to_confidence(confidence)),
        "candidate_paths": [p.model_dump(mode="json") for p in paths[:3]],
        "regulatory_citations": citations,
        "kyc_summaries": summaries,
        "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
        "degraded_evidence": degraded,
        "missing_evidence": list(missing_evidence if missing_evidence is not None else DEFAULT_MISSING_EVIDENCE),
        "alert_amount_inr": dec_str(alert.total_amount_inr),
        "verification_status": status,
        "verification_discrepancies": discrepancies,
    }


def _with_llm_text(hypotheses: list[Hypothesis], llm_out: Mapping[str, Any]) -> list[Hypothesis]:
    copies = [h.model_copy(deep=True) for h in hypotheses]
    if llm_out.get("used_live_llm"):
        for hyp in copies:
            override = (
                llm_out.get("suspicious_explanation")
                if hyp.label == HypothesisLabel.SUSPICIOUS
                else llm_out.get("benign_explanation")
            )
            if override:
                hyp.explanation = str(override)
    return copies


async def _verify_narrative_loop(
    *,
    ledger: BudgetLedger,
    alert: Alert,
    thread_id: str,
    disposition: DispositionDecision,
    confidence: float,
    paths: list[FundFlowPath],
    hypotheses: list[Hypothesis],
    citations: list[str],
    summaries: list[str],
    registry: Mapping[str, Any],
    calc_log: Optional[list[dict[str, Any]]] = None,
    replan_count: int = 0,
    base_rationale: str = "",
    degraded: Optional[list[str]] = None,
    use_strong_model: bool = False,
    narrative_role: Optional[str] = None,
    verify: bool = True,
    allow_llm: bool = True,
) -> tuple[str, list[Hypothesis], str, bool, list[dict[str, Any]]]:
    deg_list = list(degraded or [])
    feedback: list[dict[str, Any]] = []
    discrepancies: list[dict[str, Any]] = []
    while True:
        if allow_llm:
            llm_out = await synthesize_investigation_narrative(
                alert_id=alert.alert_id,
                disposition=disposition.value,
                confidence=confidence,
                paths_summary=[p.model_dump(mode="json") for p in paths[:3]],
                kyc_summaries=summaries,
                citations=citations,
                replan_count=replan_count,
                fallback_rationale=base_rationale,
                use_strong_model=use_strong_model,
                role_override=narrative_role,
                ledger=ledger,
                verifier_feedback=feedback,
            )
        else:
            llm_out = {"used_live_llm": False, "model": "offline-deterministic", "rationale": base_rationale}
        rationale, llm_model = str(llm_out["rationale"]), str(llm_out["model"])
        hyps = _with_llm_text(hypotheses, llm_out)
        candidate = _payload(
            alert=alert,
            thread_id=thread_id,
            disposition=disposition,
            rationale=rationale,
            confidence=confidence,
            paths=paths,
            hypotheses=hyps,
            citations=citations,
            summaries=summaries,
            degraded=deg_list,
            status="passed",
            discrepancies=[],
        )
        result = verify_worksheet(candidate, registry, calc_log=calc_log)
        discrepancies = [d.model_dump() for d in result.discrepancies]
        # In E4 `no_verifier` (`verify=False`), checks run and discrepancies are recorded,
        # without blocking, repairing, or downgrading the disposition.
        if not verify or result.passed or not llm_out.get("used_live_llm"):
            return rationale, hyps, llm_model, result.passed, discrepancies
        feedback = discrepancies
        if not ledger.try_critique_retry().allowed:
            return rationale, hyps, llm_model, False, discrepancies


def _worksheet_from_draft(
    *,
    draft: Mapping[str, Any],
    payload: Mapping[str, Any],
    alert: Alert,
    agent_label: str,
    llm_model: str,
    paths: list[FundFlowPath],
    hyps: list[Hypothesis],
    citations: list[str],
    summaries: list[str],
    degraded: list[str],
    disposition: DispositionDecision,
    rationale: str,
) -> DraftOutcome:
    raw_stored = draft.get("content")
    stored: dict[str, Any] = dict(raw_stored) if isinstance(raw_stored, Mapping) else {}
    stored_status = str(stored.get("verification_status", payload["verification_status"]))
    stored_disp = DispositionDecision(str(stored.get("recommended_disposition", disposition.value)))
    stored_discrepancies = list(stored.get("verification_discrepancies", payload["verification_discrepancies"]))
    worksheet = DispositionWorksheet(
        worksheet_id=str(draft["worksheet_id"]),
        alert_id=alert.alert_id,
        drafted_at=str(stored.get("drafted_at") or draft.get("created_at") or ""),
        investigator_agent=f"{agent_label} ({llm_model})",
        candidate_paths=paths[:3],
        hypotheses=hyps,
        regulatory_citations=citations,
        kyc_summaries=summaries,
        degraded_evidence=degraded,
        missing_evidence=list(stored.get("missing_evidence", payload["missing_evidence"])),
        alert_amount_inr=str(payload["alert_amount_inr"]),
        verification_status=stored_status,
        verification_discrepancies=stored_discrepancies,
        recommended_disposition=stored_disp,
        recommendation_rationale=str(stored.get("recommendation_rationale", rationale)),
        confidence_score=payload["confidence_score"],
        payload_hash=str(draft["payload_hash"]),
    )
    return DraftOutcome(worksheet, stored_status == "failed", stored_discrepancies, llm_model)


async def draft_and_verify(
    *,
    box: GuardedToolbox,
    ledger: BudgetLedger,
    alert: Alert,
    agent_label: str,
    thread_id: str,
    disposition: DispositionDecision,
    confidence: float,
    paths: list[FundFlowPath],
    hypotheses: list[Hypothesis],
    citations: list[str],
    summaries: list[str],
    registry: Mapping[str, Any],
    replan_count: int,
    base_rationale: str,
    degraded: list[str],
    use_strong_model: bool,
    calc_log: Optional[list[dict[str, Any]]] = None,
    narrative_role: Optional[str] = None,
    verify: bool = True,
    allow_llm: bool = True,
) -> DraftOutcome:
    rationale, hyps, llm_model, passed, discrepancies = await _verify_narrative_loop(
        ledger=ledger,
        alert=alert,
        thread_id=thread_id,
        disposition=disposition,
        confidence=confidence,
        paths=paths,
        hypotheses=hypotheses,
        citations=citations,
        summaries=summaries,
        registry=registry,
        calc_log=calc_log,
        replan_count=replan_count,
        base_rationale=base_rationale,
        degraded=degraded,
        use_strong_model=use_strong_model,
        narrative_role=narrative_role,
        verify=verify,
        allow_llm=allow_llm,
    )
    gate_failed = verify and not passed
    if gate_failed:
        codes = sorted({d["code"] for d in discrepancies})
        rationale = f"{base_rationale} [VERIFICATION FAILED - manual review required: {', '.join(codes)}]"
        hyps = [h.model_copy(deep=True) for h in hypotheses]
        disposition = DispositionDecision.REQUEST_INFO
    payload = {
        **_payload(
            alert=alert, thread_id=thread_id, disposition=disposition, rationale=rationale, confidence=confidence,
            paths=paths, hypotheses=hyps, citations=citations, summaries=summaries, degraded=degraded,
            status="passed" if passed else "failed", discrepancies=[] if passed else discrepancies,
        ),
        "evidence_registry": dict(registry),
        "calc_log": list(calc_log or []),
        "enforce_verifier_gate": verify,
    }
    draft = await box.call("case-actions", "draft_disposition_report", payload)
    if is_error(draft):
        raise DraftError(f"draft_disposition_report failed: {draft.get('error_code') or draft.get('error')}")
    return _worksheet_from_draft(
        draft=draft,
        payload=payload,
        alert=alert,
        agent_label=agent_label,
        llm_model=llm_model,
        paths=paths,
        hyps=hyps,
        citations=citations,
        summaries=summaries,
        degraded=degraded,
        disposition=disposition,
        rationale=rationale,
    )


def security_notes(box: GuardedToolbox) -> list[str]:
    return sorted(
        {f"Prompt-injection attempt detected in {e['source']}; content withheld" for e in box.security_events}
    )


__all__ = ["DraftError", "DraftOutcome", "draft_and_verify", "security_notes"]
