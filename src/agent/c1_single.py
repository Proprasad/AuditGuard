"""
AuditGuard C1 single-agent investigator: one LLM-driven agent running the OpenAI tool-calling loop
(`src/agent/loop.py`) inside the compiled LangGraph (`src/agent/graph.py`), with deterministic
offline fallback when `LLM_ENABLED=false` and no `llm_client` / `llm_mode` is configured.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, Optional

from src.agent.graph import SimulatedCrashInterrupt, run_graph
from src.agent.nodes import decide_disposition, widened_params
from src.llm.client import LLMClientProtocol
from src.models import Alert, InvestigationState

__all__ = ["SimulatedCrashInterrupt", "decide_disposition", "run_investigation", "widened_params"]


async def run_investigation(
    alert: Alert,
    mode: str = "c1_single",
    thread_id: Optional[str] = None,
    resume: bool = False,
    stop_after_node: Optional[str] = None,
    configurable_graph: bool = True,
    replanning_enabled: bool = True,
    deterministic_verifier: bool = True,
    allow_calc: bool = True,
    allow_registry: bool = True,
    allow_rag: bool = True,
    defenses_enabled: bool = True,
    reflexion_enabled: bool = False,
    memory_enabled: bool = True,
    budget_overrides: Optional[dict[str, Any]] = None,
    llm_client: Optional[LLMClientProtocol] = None,
    llm_mode: Optional[str] = None,
    cassette_path: Optional[str] = None,
    run_id: Optional[str] = None,
    seed: Optional[int] = None,
    on_event: Optional[Callable[[str, dict[str, Any]], None]] = None,
) -> InvestigationState:
    """Execute C1; `resume=True` continues from the durable LangGraph checkpoint of `thread_id`."""
    return await run_graph(
        alert=alert,
        mode="rule_engine" if mode == "rule_engine" else "c1_single",
        thread_id=thread_id or f"thr-{uuid.uuid4().hex[:12]}",
        resume=resume,
        stop_after_node=stop_after_node,
        configurable_graph=configurable_graph,
        replanning_enabled=replanning_enabled,
        deterministic_verifier=deterministic_verifier,
        allow_calc=allow_calc,
        allow_registry=allow_registry,
        allow_rag=allow_rag,
        defenses_enabled=defenses_enabled,
        reflexion_enabled=reflexion_enabled,
        memory_enabled=memory_enabled,
        budget_overrides=budget_overrides,
        llm_client=llm_client,
        llm_mode=llm_mode,
        cassette_path=cassette_path,
        run_id=run_id,
        seed=seed,
        emit=on_event,
    )
