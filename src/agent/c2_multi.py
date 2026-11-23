"""
AuditGuard C2 multi-agent team: supervisor + 4 RBAC-scoped specialists running the same compiled LangGraph.

  flow_tracer          : exclusive owner of graph-engine + transaction reads
  benign_investigator  : KYC + commercial registry (runs in parallel with regulatory_analyst)
  regulatory_analyst   : exclusive owner of compliance-kb
  reporter_critic      : deterministic verifier + gated case-actions drafting

All specialists share one per-run BudgetLedger; the supervisor model plans, scores competing hypotheses and critiques.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, Optional

from src.agent.graph import run_graph
from src.models import Alert, InvestigationState, SpecialistFinding, SpecialistHandOff

__all__ = ["SpecialistFinding", "SpecialistHandOff", "run_multi_agent"]


async def run_multi_agent(
    alert: Alert,
    thread_id: Optional[str] = None,
    reflexion_enabled: bool = False,
    memory_enabled: bool = True,
    budget_overrides: Optional[dict[str, Any]] = None,
    resume: bool = False,
    stop_after_node: Optional[str] = None,
    on_event: Optional[Callable[[str, dict[str, Any]], None]] = None,
) -> InvestigationState:
    """C2 supervisor coordinating specialists under a shared BudgetLedger with critique-driven replanning."""
    return await run_graph(
        alert=alert,
        mode="c2_multi",
        thread_id=thread_id or f"thr-{uuid.uuid4().hex[:12]}",
        resume=resume,
        stop_after_node=stop_after_node,
        reflexion_enabled=reflexion_enabled,
        memory_enabled=memory_enabled,
        budget_overrides=budget_overrides,
        emit=on_event,
    )
