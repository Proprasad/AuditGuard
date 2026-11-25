"""
Comprehensive tests for C1 ReAct, C2 Supervisor Dynamic Routing, Typed Specialist Handoffs,
Dynamic MCP RBAC, Independent Critique, and Live Multi-Stage LangGraph Checkpoint Recovery.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from src.agent.c1_single import SimulatedCrashInterrupt, run_investigation
from src.agent.c2_routing import MANDATORY_ROLES, build_routing_plan
from src.agent.c2_stages import enrich_specialist_finding
from src.agent.c2_multi import run_multi_agent
from src.agent.graph import resume_gate
from src.db.database import get_db, load_checkpoint
from src.guardrails.hooks import AGENT_TOOL_ALLOWLIST
from src.models import Alert, DispositionDecision, RiskLevel, SpecialistFinding, SpecialistHandOff
from tests.fakes import FakeLLM, make_text_turn, make_tool_turn

ALERT = Alert(
    alert_id="ALT-2026-0412",
    rule_name="SCATTER_GATHER_900K",
    root_account="ACC-IND-1042",
    total_amount_inr="900000.00",
    risk_level=RiskLevel.HIGH,
)


def _tool_outputs(messages: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for m in messages:
        if m.get("role") == "tool" and m.get("name"):
            out.setdefault(str(m["name"]), []).append(json.loads(str(m["content"])))
    return out


def _finish_from_messages(messages: list[dict[str, Any]], _: Any) -> Any:
    outs = _tool_outputs(messages)
    paths = (outs.get("replan_graph") or outs.get("find_candidate_fund_flows") or [{}])[-1].get("paths") or []
    p0 = paths[0] if paths else None
    clause_id = (outs.get("search_regulations") or [{}])[-1].get("clauses", [{}])[0].get("clause_id", "")
    kyc_id = (outs.get("get_kyc_profile") or [{}])[0].get("evidence_id", "")
    ev_ids = [x for x in ([p0["path_id"]] if p0 else []) + ([kyc_id] if kyc_id else []) if x]
    rationale = (
        f"Path {p0['path_id']} dispersed INR {p0['total_outflow_inr']} and consolidated "
        f"INR {p0['total_consolidated_inr']} under {clause_id}."
        if p0
        else f"Investigation reviewed {kyc_id} under {clause_id} with incomplete downstream records."
    )
    return make_tool_turn(
        (
            "finish",
            {
                "recommended_disposition": "escalate_str" if p0 else "request_info",
                "confidence_score": "0.86" if p0 else "0.45",
                "recommendation_rationale": rationale,
                "suspicious_hypothesis": {
                    "explanation": (
                        f"Multi-hop scatter-gather pattern evaluated against {ev_ids[0] if ev_ids else 'alert'}."
                    ),
                    "confidence": "0.86" if p0 else "0.45",
                    "supporting_evidence": [p0["path_id"]] if p0 else ["Incomplete outbound legs"],
                    "evidence_ids": ev_ids,
                    "regulatory_citations": [clause_id] if clause_id else [],
                },
                "benign_hypothesis": {
                    "explanation": f"Legitimate settlement hypothesis evaluated for {kyc_id or 'root account'}.",
                    "confidence": "0.14" if p0 else "0.45",
                    "contradicting_evidence": [p0["path_id"]] if p0 else [],
                    "evidence_ids": [kyc_id] if kyc_id else ev_ids,
                    "regulatory_citations": [clause_id] if clause_id else [],
                },
                "missing_evidence": ["Beneficial ownership and external-bank credit logs"],
                "regulatory_citations": [clause_id] if clause_id else [],
            },
        )
    )


@pytest.mark.asyncio
async def test_c1_observation_driven_tool_selection_and_invalid_call_handling() -> None:
    """Different observations drive different tool choices; invalid args & failures are tracked."""

    def observe_and_decide(messages: list[dict[str, Any]], _: Any) -> Any:
        outs = _tool_outputs(messages)
        paths = outs["find_candidate_fund_flows"][-1].get("paths", [])
        if not any(p.get("hop_count", 0) >= 2 for p in paths):
            return make_tool_turn(
                (
                    "replan_graph",
                    {
                        "time_window_days": 18,
                        "max_hops": 4,
                        "amount_tolerance": "0.15",
                        "reason": "Initial 7-day scan missed delayed consolidation",
                    },
                )
            )
        return make_tool_turn(("get_kyc_profile", {"account_id": "ACC-IND-1042"}))

    fake = FakeLLM(
        [
            make_tool_turn(("get_alert_context", {"alert_id": "ALT-2026-0412"})),
            make_tool_turn(("find_candidate_fund_flows", {"root_account": "ACC-IND-1042"})),
            observe_and_decide,
            make_tool_turn(
                ("get_kyc_profile", {"_invalid_json": "{broken"}),
                ("get_kyc_profile", {"account_id": "ACC-IND-1042"}),
                ("search_regulations", {"query": "scatter gather layering red flags", "top_k": 2}),
            ),
            _finish_from_messages,
        ]
    )
    state = await run_investigation(ALERT, thread_id="thr-c1-obs", llm_client=fake)
    assert state.worksheet is not None and state.worksheet.verification_status == "passed"
    assert state.react_steps_completed >= 4
    assert any(e["tool"] == "get_kyc_profile" and e["status"] == "error" for e in state.tool_execution_log)
    assert any(e["tool"] == "replan_graph" and e["status"] == "ok" for e in state.tool_execution_log)
    assert state.replan_count == 1 and len(state.replan_records) == 1
    assert state.replan_records[0]["comparison"]["improved"] is True
    assert state.hypothesis_assessment is not None
    assert state.hypothesis_assessment["suspicious"]["hypothesis_id"] == "HYP-SUSPICIOUS"
    assert state.hypothesis_assessment["benign"]["hypothesis_id"] == "HYP-BENIGN"
    assert len(state.evidence_claims) >= 2
    assert state.critic_assessment is not None
    assert state.critic_assessment["assessment_type"] == "semantic_and_structural_critique"


@pytest.mark.asyncio
async def test_c1_live_checkpoint_and_resume_without_duplicate_worksheets() -> None:
    """Crashing live C1 right after `agent_loop` resumes directly at `hypothesis_evaluation`."""
    fake = FakeLLM(
        [
            make_tool_turn(("get_alert_context", {"alert_id": "ALT-2026-0412"})),
            make_tool_turn(
                (
                    "replan_graph",
                    {"time_window_days": 18, "max_hops": 4, "amount_tolerance": "0.15", "reason": "widen"},
                ),
                ("get_kyc_profile", {"account_id": "ACC-IND-1042"}),
                ("search_regulations", {"query": "scatter gather layering", "top_k": 2}),
            ),
            _finish_from_messages,
        ]
    )
    tid = "thr-c1-live-resume"
    with pytest.raises(SimulatedCrashInterrupt):
        await run_investigation(ALERT, thread_id=tid, llm_client=fake, stop_after_node="agent_loop")

    calls_before_resume = len(fake.calls)
    cp = load_checkpoint(tid)
    assert cp is not None and cp["current_node"] == "agent_loop"

    resumed = await run_investigation(ALERT, thread_id=tid, llm_client=fake, resume=True)
    assert len(fake.calls) == calls_before_resume  # zero duplicate LLM calls on resume!
    assert resumed.hypothesis_assessment is not None and resumed.critic_assessment is not None
    assert resumed.worksheet is not None
    with get_db() as conn:
        cnt = conn.execute("SELECT COUNT(*) FROM worksheets WHERE thread_id = ?", (tid,)).fetchone()[0]
    assert cnt == 1
    assert await resume_gate(tid, "c1_single", {"action": "reject", "reviewer": "rev1"}) is True


def test_c2_supervisor_routing_mandatory_coverage_rbac_and_budget_clamping() -> None:
    """Supervisor routing enforces mandatory 4-role coverage, RBAC allowlists, and critic budget reserve."""
    # Supervisor attempts to omit benign_investigator & regulatory_analyst AND over-allocate 24 tool calls!
    raw_plan = {
        "steps": ["Trace flow", "Draft report"],
        "execution_order": [["flow_tracer"], ["reporter_critic"]],
        "selection_rationale": {"flow_tracer": "High-value scatter-gather alert"},
        "completion_conditions": ["Verified fund-flow and regulatory grounding"],
        "replan_conditions": ["Zero multi-hop paths in 7d window"],
    }
    partial_handoffs = [
        SpecialistHandOff(
            task_id="HO-FLOW",
            target_agent="flow_tracer",
            objective="Trace network",
            allowed_tool_budget=12,
            permitted_tools=["submit_case_disposition"],  # attempted privilege escalation!
        ),
        SpecialistHandOff(
            task_id="HO-CRITIC",
            target_agent="reporter_critic",
            objective="Critique and draft",
            allowed_tool_budget=10,
        ),
    ]
    routing, enriched = build_routing_plan(raw_plan, partial_handoffs, max_calls=15)

    assert routing.mandatory_coverage_verified is True
    assert set(routing.selected_specialists) == set(MANDATORY_ROLES)
    assert set(enriched.keys()) == set(MANDATORY_ROLES)
    # Privilege escalation in LLM plan is overwritten by authoritative AGENT_TOOL_ALLOWLIST
    assert "submit_case_disposition" not in enriched["flow_tracer"].permitted_tools
    assert set(enriched["flow_tracer"].permitted_tools) == AGENT_TOOL_ALLOWLIST["flow_tracer"]
    # Investigation specialists clamped to leave reserved critic capacity
    inv_sum = sum(
        enriched[r].allowed_tool_budget for r in ("flow_tracer", "benign_investigator", "regulatory_analyst")
    )
    assert inv_sum <= 15 - routing.reserved_critic_budget
    assert enriched["reporter_critic"].allowed_tool_budget >= 2

    # Rich SpecialistFinding enrichment preserves provenance & metadata
    raw_f = SpecialistFinding(
        task_id="HO-FLOW",
        agent_name="flow_tracer",
        summary="Found 1 path",
        tool_calls=2,
        evidence_ids_added=["PATH-001", "TXN-001"],
        recommended_replan={"expand_window": True},
    )
    rich = enrich_specialist_finding(
        enriched["flow_tracer"], raw_f, {"PATH-001": {}, "TXN-001": {}}, degraded=[], tool_errors=[], duration_ms=12.5
    )
    assert rich.objective == "Trace network"
    assert rich.claims and rich.evidence_relevance["PATH-001"] == "graph-engine.fund_flow_path"
    assert rich.missing_information and rich.execution_metadata["tool_calls_used"] == 2


def _make_c2_fake(with_replan: bool = True) -> FakeLLM:
    plan_json = json.dumps(
        {
            "steps": ["Trace flow", "Check KYC and regulations in parallel", "Critique and draft"],
            "execution_order": [["flow_tracer"], ["benign_investigator", "regulatory_analyst"], ["reporter_critic"]],
            "selection_rationale": {
                "flow_tracer": "Reconstruct scatter-gather topology",
                "benign_investigator": "Test commercial/payroll/charity benign explanations",
                "regulatory_analyst": "Ground PMLA/RBI/FIU-IND indicators",
                "reporter_critic": "Challenge findings and draft verified worksheet",
            },
            "handoffs": [
                {
                    "task_id": "HO-FLOW",
                    "target_agent": "flow_tracer",
                    "objective": "Trace flows",
                    "allowed_tool_budget": 4,
                },
                {
                    "task_id": "HO-BENIGN",
                    "target_agent": "benign_investigator",
                    "objective": "Check KYC & registry",
                    "allowed_tool_budget": 4,
                },
                {
                    "task_id": "HO-REG",
                    "target_agent": "regulatory_analyst",
                    "objective": "Search PMLA clauses",
                    "allowed_tool_budget": 2,
                },
                {
                    "task_id": "HO-CRITIC",
                    "target_agent": "reporter_critic",
                    "objective": "Challenge & draft",
                    "allowed_tool_budget": 2,
                },
            ],
        }
    )
    replan_json = json.dumps(
        {
            "request_replan": with_replan,
            "time_window_days": 18,
            "max_hops": 4,
            "amount_tolerance": "0.15",
            "reason": "7-day initial window missed staggered Day-11 consolidation",
        }
    )

    def critic_finish(messages: list[dict[str, Any]], _: Any) -> Any:
        sys_txt = str(messages[0]["content"])
        idx = sys_txt.find("Current Investigation Context:\n")
        ctx_blob = json.loads(sys_txt[idx + len("Current Investigation Context:\n") :].split("\nUse your allowed")[0])
        paths = ctx_blob.get("candidate_paths") or []
        p0 = paths[0] if paths else None
        cid = (ctx_blob.get("regulatory_clauses") or [{}])[0].get("clause_id", "")
        kyc_id = (ctx_blob.get("kyc_profiles") or [{}])[0].get("evidence_id", "")
        ev_ids = [x for x in ([p0["path_id"]] if p0 else []) + ([kyc_id] if kyc_id else []) if x]
        rat = (
            f"Multi-hop path {p0['path_id']} dispersed INR {p0['total_outflow_inr']} and consolidated "
            f"INR {p0['total_consolidated_inr']} under {cid}."
            if p0
            else f"Incomplete downstream trail reviewed for {kyc_id} under {cid}."
        )
        return make_tool_turn(
            (
                "finish",
                {
                    "recommended_disposition": "escalate_str" if p0 else "request_info",
                    "confidence_score": "0.87" if p0 else "0.45",
                    "recommendation_rationale": rat,
                    "suspicious_hypothesis": {
                        "explanation": f"Staggered consolidation evidence on {ev_ids[0] if ev_ids else 'alert'}.",
                        "confidence": "0.87" if p0 else "0.45",
                        "supporting_evidence": [p0["path_id"]] if p0 else [],
                        "evidence_ids": ev_ids,
                        "regulatory_citations": [cid] if cid else [],
                    },
                    "benign_hypothesis": {
                        "explanation": f"Commercial settlement assessed for {kyc_id or 'root'} without corroboration.",
                        "confidence": "0.13" if p0 else "0.45",
                        "contradicting_evidence": [p0["path_id"]] if p0 else [],
                        "evidence_ids": [kyc_id] if kyc_id else ev_ids,
                        "regulatory_citations": [cid] if cid else [],
                    },
                    "missing_evidence": ["External beneficiary bank KYC records"],
                    "regulatory_citations": [cid] if cid else [],
                },
            )
        )

    flow_turns = [
        make_tool_turn(("get_alert_context", {"alert_id": "ALT-2026-0412"})),
        make_tool_turn(("find_candidate_fund_flows", {"root_account": "ACC-IND-1042"})),
        make_text_turn("Initial 7d scan found outbound legs without consolidation."),
        make_tool_turn(
            (
                "replan_graph",
                {
                    "time_window_days": 18,
                    "max_hops": 4,
                    "amount_tolerance": "0.15",
                    "reason": "Staggered Day-11 consolidation",
                },
            )
        ),
        make_text_turn("Replanned 18d scan uncovered multi-hop consolidation path."),
    ]
    return FakeLLM(
        role_scripts={
            "C2 Investigation Supervisor": [make_text_turn(plan_json), make_text_turn(replan_json)],
            "C2 Specialist `flow_tracer`": flow_turns,
            "C2 Specialist `benign_investigator`": [
                make_tool_turn(
                    ("get_kyc_profile", {"account_id": "ACC-IND-1042"}),
                    ("check_commercial_registry", {"entity_name": "Account Holder", "account_id": "ACC-IND-1042"}),
                ),
                make_text_turn("Root account unregistered; benign commercial explanation uncorroborated."),
            ],
            "C2 Specialist `regulatory_analyst`": [
                make_tool_turn(("search_regulations", {"query": "scatter gather layering red flags", "top_k": 2})),
                make_text_turn("Retrieved PMLA and FIU-IND scatter-gather clauses."),
            ],
            "C2 Specialist `reporter_critic`": [critic_finish],
        }
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "crash_stage",
    [
        "supervisor_plan",
        "flow_tracer",
        "parallel_specialists",
        "hypothesis_evaluation",
        "flow_replan",
        "reporter_critic",
    ],
)
async def test_c2_live_multi_stage_crash_and_resume_across_all_stages(crash_stage: str) -> None:
    """Crash recovery works at every live C2 LangGraph stage with zero duplicate side effects."""
    fake = _make_c2_fake(with_replan=True)
    tid = f"thr-c2-crash-{crash_stage}"
    with pytest.raises(SimulatedCrashInterrupt):
        await run_multi_agent(ALERT, thread_id=tid, llm_client=fake, stop_after_node=crash_stage)

    cp = load_checkpoint(tid)
    assert cp is not None and cp["current_node"] == crash_stage
    calls_at_crash = len(fake.calls)

    resumed = await run_multi_agent(ALERT, thread_id=tid, llm_client=fake, resume=True)
    assert resumed.worksheet is not None and resumed.worksheet.verification_status == "passed"
    assert resumed.worksheet.recommended_disposition == DispositionDecision.ESCALATE_STR
    assert resumed.routing_plan is not None and resumed.routing_plan["mandatory_coverage_verified"] is True
    assert resumed.hypothesis_assessment is not None and resumed.critic_assessment is not None
    assert resumed.replan_count == 1 and len(resumed.replan_records) == 1
    assert resumed.replan_records[0]["comparison"]["improved"] is True
    # Resuming after reporter_critic must make 0 additional LLM calls and create 0 extra worksheets!
    if crash_stage == "reporter_critic":
        assert len(fake.calls) == calls_at_crash
    with get_db() as conn:
        ws_cnt = conn.execute("SELECT COUNT(*) FROM worksheets WHERE thread_id = ?", (tid,)).fetchone()[0]
    assert ws_cnt == 1
    assert await resume_gate(tid, "c2_multi", {"action": "reject", "reviewer": "rev1"}) is True
