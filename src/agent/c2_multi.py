"""
AuditGuard C2 multi-agent team: supervisor + 4 RBAC-scoped specialist LLMs (`src/agent/c2_loop.py`)
running under a shared `BudgetLedger` inside the compiled LangGraph (`src/agent/graph.py`).

  flow_tracer          : exclusive owner of graph-engine + transaction reads + bounded replan_graph
  benign_investigator  : KYC + commercial registry + counterparty history (parallel with regulatory_analyst)
  regulatory_analyst   : exclusive owner of compliance-kb
  reporter_critic      : deterministic verifier + structured finish / gated case-actions drafting
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, Optional

from src.agent.graph import run_graph
from src.llm.client import LLMClientProtocol
from src.models import Alert, InvestigationState, SpecialistFinding, SpecialistHandOff

__all__ = ["SpecialistFinding", "SpecialistHandOff", "run_multi_agent"]


async def run_multi_agent(
    alert: Alert,
    thread_id: Optional[str] = None,
    reflexion_enabled: bool = False,
    memory_enabled: bool = True,
    replanning_enabled: bool = True,
    deterministic_verifier: bool = True,
    budget_overrides: Optional[dict[str, Any]] = None,
    llm_client: Optional[LLMClientProtocol] = None,
    llm_mode: Optional[str] = None,
    cassette_path: Optional[str] = None,
    run_id: Optional[str] = None,
    seed: Optional[int] = None,
    resume: bool = False,
    stop_after_node: Optional[str] = None,
    on_event: Optional[Callable[[str, dict[str, Any]], None]] = None,
) -> InvestigationState:
    """C2 supervisor coordinating 4 RBAC specialists under a shared BudgetLedger."""
    return await run_graph(
        alert=alert,
        mode="c2_multi",
        thread_id=thread_id or f"thr-{uuid.uuid4().hex[:12]}",
        resume=resume,
        stop_after_node=stop_after_node,
        replanning_enabled=replanning_enabled,
        deterministic_verifier=deterministic_verifier,
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
