"""Regression tests for runtime LLM model selection via `system_flags` in C1 and C2 loops."""

from __future__ import annotations

import json

import pytest

from src.agent.c1_single import run_investigation
from src.agent.c2_multi import run_multi_agent
from src.agent.graph import make_context
from src.agent.llm_client import set_runtime_llm_config
from src.agent.planning import resolve_model_for_role
from src.models import Alert, RiskLevel
from tests.fakes import FakeLLM, make_text_turn

ALERT = Alert(
    alert_id="ALT-2026-0412",
    rule_name="SCATTER_GATHER_900K",
    root_account="ACC-IND-1042",
    total_amount_inr="900000.00",
    risk_level=RiskLevel.HIGH,
)


def test_resolve_model_for_role_precedence_and_replay_isolation() -> None:
    set_runtime_llm_config(
        enabled=True,
        model="anthropic/claude-haiku-5.5",
        strong_model="google/gemini-3.1-flash-lite",
    )

    live_ctx = make_context("c2_multi", "thr-live-resolve")
    assert resolve_model_for_role(live_ctx, "c1_investigator") == "anthropic/claude-haiku-5.5"
    assert resolve_model_for_role(live_ctx, "c2_specialists") == "anthropic/claude-haiku-5.5"
    assert resolve_model_for_role(live_ctx, "c2_supervisor", strong=True) == "google/gemini-3.1-flash-lite"

    override_ctx = make_context(
        "c2_multi",
        "thr-override-resolve",
        model_override="openai/gpt-4.1-mini",
        strong_model_override="deepseek/deepseek-chat",
    )
    assert resolve_model_for_role(override_ctx, "c2_specialists") == "openai/gpt-4.1-mini"
    assert resolve_model_for_role(override_ctx, "c2_supervisor", strong=True) == "deepseek/deepseek-chat"

    replay_ctx = make_context("c2_multi", "thr-replay-resolve", llm_mode="replay")
    assert resolve_model_for_role(replay_ctx, "c1_investigator") == (
        replay_ctx.policy.model_for("c1_investigator").model_id
    )
    assert resolve_model_for_role(replay_ctx, "c2_supervisor", strong=True) == (
        replay_ctx.policy.model_for("c2_supervisor").model_id
    )


@pytest.mark.asyncio
async def test_c1_and_c2_loops_apply_runtime_db_models() -> None:
    set_runtime_llm_config(
        enabled=True,
        model="anthropic/claude-haiku-5.5",
        strong_model="google/gemini-3.1-flash-lite",
    )

    c1_fake = FakeLLM([make_text_turn("done", model="anthropic/claude-haiku-5.5")] * 12)
    c1_state = await run_investigation(ALERT, thread_id="thr-rt-c1", llm_client=c1_fake)
    assert c1_fake.calls and all(c["model"] == "anthropic/claude-haiku-5.5" for c in c1_fake.calls)
    assert c1_state.worksheet is not None
    assert "anthropic/claude-haiku-5.5" in c1_state.worksheet.investigator_agent

    def _ho(task_id: str, agent: str, obj: str) -> dict[str, object]:
        return {"task_id": task_id, "target_agent": agent, "objective": obj, "allowed_tool_budget": 2}

    plan_json = json.dumps(
        {
            "steps": ["trace", "benign", "reg", "critic"],
            "handoffs": [
                _ho("HO-FLOW", "flow_tracer", "trace"),
                _ho("HO-BENIGN", "benign_investigator", "kyc"),
                _ho("HO-REG", "regulatory_analyst", "reg"),
                _ho("HO-CRITIC", "reporter_critic", "draft"),
            ],
        }
    )
    c2_fake = FakeLLM(
        role_scripts={
            "C2 Investigation Supervisor": [make_text_turn(plan_json, model="google/gemini-3.1-flash-lite")] * 2,
            "C2 Specialist `flow_tracer`": [make_text_turn("flow done", model="anthropic/claude-haiku-5.5")] * 4,
            "C2 Specialist `benign_investigator`": [
                make_text_turn("benign done", model="anthropic/claude-haiku-5.5")
            ]
            * 4,
            "C2 Specialist `regulatory_analyst`": [make_text_turn("reg done", model="anthropic/claude-haiku-5.5")] * 4,
            "C2 Specialist `reporter_critic`": [make_text_turn("critic done", model="anthropic/claude-haiku-5.5")] * 4,
        }
    )
    c2_state = await run_multi_agent(ALERT, thread_id="thr-rt-c2", llm_client=c2_fake)
    assert c2_state.worksheet is not None
    assert "anthropic/claude-haiku-5.5" in c2_state.worksheet.investigator_agent
    models_seen = {c["model"] for c in c2_fake.calls}
    assert models_seen == {"google/gemini-3.1-flash-lite", "anthropic/claude-haiku-5.5"}
