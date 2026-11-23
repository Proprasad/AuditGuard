"""Step 5 gate: compiled LangGraph topology, reducers, interrupt/resume, closed-loop replan and LLM-grounded reasoning."""
from decimal import Decimal

import pytest

from src.agent import reasoning
from src.agent.c1_single import run_investigation
from src.agent.c2_multi import run_multi_agent
from src.agent.graph import build_graph, make_context, merge_investigation, open_saver, recursion_limit, resume_gate
from src.agent.llm_client import LlmCallMeta
from src.config import get_policy
from src.core.scoring import EvidenceFeatures, rubric_scores
from src.models import Alert, RiskLevel

ALERT = Alert(alert_id="ALT-2026-0412", rule_name="SCATTER_GATHER_900K", root_account="ACC-IND-1042",
              total_amount_inr="900000.00", risk_level=RiskLevel.HIGH)


def test_reducer_merges_registry_and_dedupes_lists():
    old = {"evidence_registry": {"A": 1}, "degraded_evidence": ["x", "y"], "tool_calls_used": 1}
    new = {"evidence_registry": {"B": 2}, "degraded_evidence": ["y", "z"], "tool_calls_used": 3}
    merged = merge_investigation(old, new)
    assert merged["evidence_registry"] == {"A": 1, "B": 2}
    assert merged["degraded_evidence"] == ["x", "y", "z"]
    assert merged["tool_calls_used"] == 3


def test_graph_topology_has_no_orphans_and_reaches_end():
    ctx = make_context("c1_single", "thr-topology")
    graph = build_graph(ctx, "thr-topology").compile().get_graph()
    nodes = {n for n in graph.nodes if not n.startswith("__")}
    assert nodes == {"plan", "gather_evidence", "form_hypotheses", "critique", "replan", "draft", "human_gate"}
    edges = {(e.source, e.target) for e in graph.edges}
    assert ("critique", "replan") in edges and ("critique", "draft") in edges and ("replan", "gather_evidence") in edges
    assert ("human_gate", "__end__") in edges and ("__start__", "plan") in edges
    for node in nodes:  # every node is reachable and has an outgoing edge
        assert any(t == node for _, t in edges) and any(s == node for s, _ in edges)


def test_recursion_limit_is_derived_from_replan_budget():
    policy = get_policy()
    assert recursion_limit(policy) == (policy.budgets.max_replans + 1) * 4 + 8


def test_rubric_confidences_are_evidence_derived_not_constants():
    cfg = get_policy().scoring
    strong = rubric_scores(EvidenceFeatures(multi_hop_path=True, income_mismatch=True, high_kyc_risk=True, unregistered_root=True), cfg)
    benign = rubric_scores(EvidenceFeatures(registered_root=True, low_kyc_risk=True), cfg)
    none = rubric_scores(EvidenceFeatures(), cfg)
    assert strong.suspicious > none.suspicious > benign.suspicious
    assert none.suspicious == cfg.prior
    assert strong.suspicious + strong.benign == Decimal("1")


@pytest.mark.asyncio
async def test_c1_replans_when_evidence_contradicts_and_pauses_at_interrupt():
    state = await run_investigation(ALERT, thread_id="thr-s5-c1")
    assert state.replan_count >= 1
    assert state.plan is not None and state.plan.replan_reason and "multi-hop consolidation" in state.plan.replan_reason
    assert state.plan.graph_params.time_window_days > get_policy().graph_bounds.time_window_days.default
    assert state.worksheet is not None and state.worksheet.recommended_disposition.value == "escalate_str"
    assert len(state.agent_runs) == 1 and len(state.workflow_steps) == 7

    async with open_saver() as saver:
        snap = await build_graph(make_context("c1_single", "thr-s5-c1"), "thr-s5-c1").compile(checkpointer=saver).aget_state(
            {"configurable": {"thread_id": "thr-s5-c1"}})
    assert snap.next == ("human_gate",) and any(t.interrupts for t in snap.tasks)

    assert await resume_gate("thr-s5-c1", "c1_single", {"action": "approve", "disposition": "escalate_str", "reviewer": "r"}) is True
    async with open_saver() as saver:
        done = await build_graph(make_context("c1_single", "thr-s5-c1"), "thr-s5-c1").compile(checkpointer=saver).aget_state(
            {"configurable": {"thread_id": "thr-s5-c1"}})
    assert done.next == () and done.values["inv"]["current_node"] == "committed"
    assert await resume_gate("thr-s5-c1", "c1_single", {"action": "approve"}) is False  # no double release


@pytest.mark.asyncio
async def test_c2_uses_four_specialists_with_shared_budget():
    state = await run_multi_agent(ALERT, thread_id="thr-s5-c2")
    assert [r["agent_id"] for r in state.agent_runs] == ["flow_tracer", "benign_investigator", "regulatory_analyst", "reporter_critic"]
    assert state.tool_calls_used <= get_policy().budgets.max_tool_calls
    assert state.replan_count >= 1 and state.worksheet is not None


@pytest.mark.asyncio
async def test_llm_reasoning_is_used_and_fabricated_evidence_ids_are_dropped(monkeypatch):
    async def fake_chat_json(*, system, user, schema, ledger, role="c1_investigator", strong=False):
        meta = LlmCallMeta(used_live_llm=True, model="fake/model")
        if schema is reasoning.HypothesisScoring:
            return schema.model_validate({
                "suspicious": {"explanation": "Layering pattern across intermediaries.", "supporting_evidence_ids": ["FAKE-ID-1"], "confidence": 0.91},
                "benign": {"explanation": "No registration found.", "contradicting_evidence_ids": [], "confidence": 0.09}}), meta
        if schema is reasoning.CritiqueVerdict:
            return schema.model_validate({"contradiction_found": False}), meta
        return None, LlmCallMeta(used_live_llm=True, model="fake/model", error="plan call disabled in this test")

    monkeypatch.setattr(reasoning, "chat_json", fake_chat_json)
    state = await run_investigation(ALERT, thread_id="thr-s5-llm")
    assert state.reasoning_mode == "llm"
    susp = next(h for h in state.worksheet.hypotheses if h.label.value == "suspicious")
    assert susp.confidence == pytest.approx(0.91)
    assert "FAKE-ID-1" not in susp.evidence_ids
    assert any("FAKE-ID-1" in d for d in state.degraded_evidence)
    assert any("LLM planning unavailable" in d for d in state.degraded_evidence)  # explicit degradation, not silent
