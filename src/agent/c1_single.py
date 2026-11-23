"""
AuditGuard C1 single-agent investigator: one LLM-driven agent running the compiled LangGraph (`src/agent/graph.py`).

`plan -> gather_evidence -> form_hypotheses -> critique -> [replan -> gather_evidence]* -> draft -> human_gate(interrupt)`
Every tool call is RBAC-checked, bounds-checked and budget-enforced by `GuardedToolbox`; all money flows through `Decimal`.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, Optional

from src.agent.graph import SimulatedCrashInterrupt, run_graph
from src.agent.nodes import decide_disposition, widened_params
from src.models import Alert, InvestigationState

__all__ = ["SimulatedCrashInterrupt", "decide_disposition", "run_investigation", "widened_params"]


async def run_investigation(
    alert: Alert,
    mode: str = "c1_single",
    thread_id: Optional[str] = None,
    resume: bool = False,
    stop_after_node: Optional[str] = None,
    replanning_enabled: bool = True,
    deterministic_verifier: bool = True,
    reflexion_enabled: bool = False,
    memory_enabled: bool = True,
    on_event: Optional[Callable[[str, dict[str, Any]], None]] = None,
) -> InvestigationState:
    """Execute C1; `resume=True` continues from the durable LangGraph checkpoint of `thread_id`."""
    return await run_graph(
        alert=alert, mode="c1_single", thread_id=thread_id or f"thr-{uuid.uuid4().hex[:12]}", resume=resume,
        stop_after_node=stop_after_node, replanning_enabled=replanning_enabled, deterministic_verifier=deterministic_verifier,
        reflexion_enabled=reflexion_enabled, memory_enabled=memory_enabled, emit=on_event,
    )
