"""
AuditGuard v3 Strong Deterministic Rule-Engine Baseline (`src/agent/rule_engine.py`).

Executes the multi-node evidence-weighted rubric & bounded replanning `StateGraph`
(`plan -> gather_evidence -> form_hypotheses -> critique -> [replan]* -> draft -> human_gate`)
with `allow_llm=False` (zero LLM calls, zero token spend, exact `Decimal` math).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, Optional

from src.agent.graph import run_graph
from src.models import Alert, InvestigationState

ROLE = "rule_engine"

__all__ = ["ROLE", "run_rule_engine"]


async def run_rule_engine(
    alert: Alert,
    thread_id: Optional[str] = None,
    resume: bool = False,
    stop_after_node: Optional[str] = None,
    configurable_graph: bool = True,
    replanning_enabled: bool = True,
    deterministic_verifier: bool = True,
    reflexion_enabled: bool = False,
    memory_enabled: bool = True,
    budget_overrides: Optional[dict[str, Any]] = None,
    on_event: Optional[Callable[[str, dict[str, Any]], None]] = None,
) -> InvestigationState:
    """Execute the deterministic rule-engine baseline (`allow_llm=False` strictly enforced)."""
    return await run_graph(
        alert=alert,
        mode=ROLE,
        thread_id=thread_id or f"thr-{uuid.uuid4().hex[:12]}",
        resume=resume,
        stop_after_node=stop_after_node,
        configurable_graph=configurable_graph,
        replanning_enabled=replanning_enabled,
        deterministic_verifier=deterministic_verifier,
        reflexion_enabled=reflexion_enabled,
        memory_enabled=memory_enabled,
        allow_llm=False,
        llm_mode="offline",
        budget_overrides=budget_overrides,
        emit=on_event,
    )
