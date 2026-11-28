"""
What the LLM loops put in front of the model besides their own turns (audit AG-05 / AG-06 / AG-15):
the alert message with scoped subject history, observation-gated Reflexion lessons, and tool messages.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from src.agent.planning import RunContext
from src.agent.prompts import render_alert_user_message
from src.guardrails.hooks import llm_tool_content
from src.llm.schemas import ToolCallRequest
from src.memory.store import memory_store
from src.memory.subject_history import render_subject_history, subject_history
from src.models import InvestigationState
from src.reflexion.retrieval import observed_feature_text, select_lessons


async def retrieve_frozen_lessons(state: InvestigationState, ctx: RunContext) -> list[str]:
    """Lessons whose preconditions match what is already known (usually nothing before the first scan)."""
    if not (ctx.reflexion_enabled and ctx.memory_enabled):
        return []
    text = observed_feature_text(state.alert, state.fund_flow_paths, state.transactions)
    return await asyncio.to_thread(select_lessons, memory_store, text, ctx.policy)


async def offer_observed_lessons(ctx: RunContext, runtime: Any) -> Optional[dict[str, Any]]:
    """After tool results arrive, offer each newly matching lesson once, as a single user message."""
    if not (ctx.reflexion_enabled and ctx.memory_enabled):
        return None
    text = observed_feature_text(runtime.alert, runtime.fund_flow_paths, runtime.transactions)
    found = await asyncio.to_thread(select_lessons, memory_store, text, ctx.policy)
    new = [les for les in found if les not in ctx.offered_lessons]
    if not new:
        return None
    ctx.offered_lessons.extend(new)
    body = "\n".join(f"- {les}" for les in new)
    return {"role": "user", "content": f"Reviewed playbook lessons matching what you have observed so far:\n{body}"}


async def alert_user_message(state: InvestigationState, ctx: RunContext) -> str:
    history = await asyncio.to_thread(subject_history, state.alert, memory_enabled=ctx.memory_enabled)
    return render_alert_user_message(state.alert) + render_subject_history(history)


def tool_message(tc: ToolCallRequest, result: dict[str, Any], *, defenses_enabled: bool = True) -> dict[str, Any]:
    return {
        "role": "tool",
        "tool_call_id": tc.id,
        "name": tc.name,
        "content": llm_tool_content(tc.name, result, defenses_enabled=defenses_enabled),
    }
