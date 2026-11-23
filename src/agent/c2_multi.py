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
from src.models import Alert, InvestigationState


async def run_multi_agent(
    alert: Alert, thread_id: Optional[str] = None, reflexion_enabled: bool = False, memory_enabled: bool = True,
    resume: bool = False,
    on_event: Optional[Callable[[str, dict[str, Any]], None]] = None,
) -> InvestigationState:
    """C2 supervisor coordinating the specialists under one shared BudgetLedger with bounded, critique-driven replanning."""
    return await run_graph(
        alert=alert, mode="c2_multi", thread_id=thread_id or f"thr-{uuid.uuid4().hex[:12]}", resume=resume,
        reflexion_enabled=reflexion_enabled, memory_enabled=memory_enabled, emit=on_event,
    )
