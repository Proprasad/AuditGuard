"""
Compiled LangGraph `StateGraph` runtime shared by C1 and C2.

Topology:  START -> plan -> gather_evidence -> form_hypotheses -> critique --(contradiction & budget)--> replan ->
gather_evidence
                                                                   \\--(otherwise)--> draft -> human_gate (interrupt)
                                                                   -> END

* Durable checkpointing: `AsyncSqliteSaver` locally / `AsyncPostgresSaver` when `USE_POSTGRES=true`.
* Native `interrupt()` pauses the run at `human_gate`; the API resumes it with `Command(resume=...)` after the human
decision.
* `recursion_limit` is derived from the replan budget so the loop always terminates (replan edge is budget-gated).
* State reducers: `evidence_registry` merges by key; `degraded_evidence` / `regulatory_snippets` / `retrieved_lessons`
union with
  de-duplication (safe across retries and resumes); every other field is last-writer-wins.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Optional, TypedDict

from langchain_core.runnables import RunnableConfig
from langchain_core.runnables.config import var_child_runnable_config
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from pydantic_core import to_jsonable_python

from src.agent import nodes
from src.agent.nodes import RunContext
from src.agent.tooling import GuardedToolbox
from src.config import get_policy, settings
from src.core.policy import PolicyConfig
from src.db.database import get_sqlite_path, save_checkpoint
from src.models import Alert, InvestigationState

logger = logging.getLogger("auditguard.graph")

DICT_MERGE_KEYS = frozenset({"evidence_registry"})
LIST_UNION_KEYS = frozenset({"degraded_evidence", "regulatory_snippets", "retrieved_lessons"})
C2_ROLES = ("flow_tracer", "benign_investigator", "regulatory_analyst", "reporter_critic")


class SimulatedCrashInterrupt(RuntimeError):
    """Raised intentionally by crash/resume tests after a node's checkpoint is committed."""


def merge_investigation(old: Optional[dict[str, Any]], new: Optional[dict[str, Any]]) -> dict[str, Any]:
    """LangGraph reducer for the `inv` channel (see module docstring for the per-key policy)."""
    if not old:
        return dict(new or {})
    out = dict(old)
    for key, value in (new or {}).items():
        if key in DICT_MERGE_KEYS and isinstance(value, dict):
            out[key] = {**old.get(key, {}), **value}
        elif key == "regulatory_clauses" and isinstance(value, list):
            by_id = {
                c["clause_id"]: c for c in [*old.get(key, []), *value] if isinstance(c, dict) and c.get("clause_id")
            }
            out[key] = list(by_id.values())
        elif key in LIST_UNION_KEYS and isinstance(value, list):
            out[key] = list(dict.fromkeys([*old.get(key, []), *value]))
        else:
            out[key] = value
    return out


class GState(TypedDict, total=False):
    inv: Annotated[dict[str, Any], merge_investigation]
    gate: dict[str, Any]


def as_state(raw: dict[str, Any]) -> InvestigationState:
    return InvestigationState(**{k: v for k, v in raw.items() if k in InvestigationState.model_fields})


def recursion_limit(policy: PolicyConfig) -> int:
    """One pass is 4 nodes (+replan); allow max_replans+1 passes plus draft/gate headroom."""
    return (policy.budgets.max_replans + 1) * 4 + 8


def make_context(mode: str, thread_id: str, **flags: Any) -> RunContext:
    policy = get_policy()
    ledger = policy.new_ledger()
    if mode == "c2_multi":
        boxes = {role: GuardedToolbox(role, ledger, thread_id) for role in C2_ROLES}
        boxes["primary"] = boxes["reporter_critic"]
        return RunContext(
            mode=mode,
            policy=policy,
            ledger=ledger,
            boxes=boxes,
            label="auditguard-c2",
            role="c2_supervisor",
            strong=True,
            parallel=True,
            **flags,
        )
    if mode == "c0_fixed":
        box = GuardedToolbox("c0_fixed", ledger, thread_id)
        return RunContext(
            mode=mode,
            policy=policy,
            ledger=ledger,
            boxes={"primary": box},
            label="auditguard-c0-fixed",
            role="c1_investigator",
            **flags,
        )
    box = GuardedToolbox("c1_single", ledger, thread_id)
    return RunContext(
        mode=mode,
        policy=policy,
        ledger=ledger,
        boxes={"primary": box},
        label="auditguard-c1",
        role="c1_investigator",
        **flags,
    )


# ---------------------------------------------------------------------------------------------------
# Checkpointer
# ---------------------------------------------------------------------------------------------------
def checkpoint_db_path() -> Path:
    return Path(get_sqlite_path()).with_suffix(".langgraph.sqlite")


@asynccontextmanager
async def open_saver() -> AsyncIterator[Any]:
    if settings.use_postgres:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        async with AsyncPostgresSaver.from_conn_string(settings.sync_database_url) as saver:
            await saver.setup()
            yield saver
    else:
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

        async with AsyncSqliteSaver.from_conn_string(str(checkpoint_db_path())) as saver:
            yield saver


# ---------------------------------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------------------------------
NodeFn = Callable[[InvestigationState, RunContext], Awaitable[dict[str, Any]]]


def _persist(thread_id: str, mode: str, inv: dict[str, Any], status: str = "running") -> None:
    ws = inv.get("worksheet") or {}
    alert_id = (inv.get("alert") or {}).get("alert_id", "")
    save_checkpoint(
        thread_id=thread_id,
        alert_id=alert_id,
        mode=mode,
        current_node=str(inv.get("current_node", "")),
        status=status,
        state_dict=inv,
        worksheet_id=ws.get("worksheet_id"),
        payload_hash=ws.get("payload_hash"),
    )


def _wrap(name: str, fn: NodeFn, ctx: RunContext, thread_id: str) -> Callable[[GState], Awaitable[GState]]:
    async def run(gs: GState) -> GState:
        out = await fn(as_state(gs["inv"]), ctx)
        update = to_jsonable_python(out)
        merged = merge_investigation(gs["inv"], update)
        _persist(thread_id, ctx.mode, merged)
        if ctx.emit is not None:
            ctx.emit(name, merged)  # live progress for the SSE log (read-only subscribers)
        return {"inv": update}

    return run


async def _human_gate(gs: GState, config: RunnableConfig) -> GState:
    inv = gs["inv"]
    ws = inv.get("worksheet") or {}
    # Python < 3.11 does not propagate the runnable context into async nodes, so bind it explicitly for `interrupt()`.
    token = var_child_runnable_config.set(config)
    try:
        decision = interrupt(
            {
                "thread_id": inv.get("thread_id"),
                "worksheet_id": ws.get("worksheet_id"),
                "payload_hash": ws.get("payload_hash"),
                "recommended_disposition": ws.get("recommended_disposition"),
                "verification_failed": inv.get("error") == "verification_failed",
            }
        )
    finally:
        var_child_runnable_config.reset(token)
    approved = isinstance(decision, dict) and decision.get("action") == "approve"
    return {
        "inv": {
            "current_node": "committed" if approved else "rejected",
            "human_decision": decision.get("disposition") if approved else None,
        },
        "gate": decision if isinstance(decision, dict) else {},
    }


def build_graph(ctx: RunContext, thread_id: str) -> StateGraph:
    graph = StateGraph(GState)
    graph.add_node("plan", _wrap("plan", nodes.plan_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("gather_evidence", _wrap("gather_evidence", nodes.gather_evidence_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("form_hypotheses", _wrap("form_hypotheses", nodes.hypothesis_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("critique", _wrap("critique", nodes.critique_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("replan", _wrap("replan", nodes.replan_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("draft", _wrap("draft", nodes.draft_worksheet_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("human_gate", _human_gate)  # type: ignore[call-overload]
    graph.add_edge(START, "plan")
    graph.add_edge("plan", "gather_evidence")
    graph.add_edge("gather_evidence", "form_hypotheses")
    graph.add_edge("form_hypotheses", "critique")
    graph.add_conditional_edges(
        "critique",
        lambda gs: nodes.should_replan(as_state(gs["inv"]), ctx),
        {"replan": "replan", "draft": "draft"},
    )
    graph.add_edge("replan", "gather_evidence")
    graph.add_edge("draft", "human_gate")
    graph.add_edge("human_gate", END)
    return graph


def build_c0_graph(ctx: RunContext, thread_id: str, scan_fn: NodeFn, draft_fn: NodeFn) -> StateGraph:
    """Fixed linear StateGraph for C0 baseline (`scan -> draft -> human_gate(interrupt) -> END`)."""
    graph = StateGraph(GState)
    graph.add_node("gather_evidence", _wrap("gather_evidence", scan_fn, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("draft", _wrap("draft", draft_fn, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("human_gate", _human_gate)  # type: ignore[call-overload]
    graph.add_edge(START, "gather_evidence")
    graph.add_edge("gather_evidence", "draft")
    graph.add_edge("draft", "human_gate")
    graph.add_edge("human_gate", END)
    return graph


def _config(thread_id: str, policy: PolicyConfig) -> RunnableConfig:
    return {"configurable": {"thread_id": thread_id}, "recursion_limit": recursion_limit(policy)}


def _is_paused(snapshot: Any) -> bool:
    return bool(snapshot.values) and any(getattr(t, "interrupts", None) for t in snapshot.tasks)


async def run_graph(
    *,
    alert: Alert,
    mode: str,
    thread_id: str,
    resume: bool = False,
    stop_after_node: Optional[str] = None,
    **flags: Any,
) -> InvestigationState:
    """Run (or resume) the compiled graph until the human-approval `interrupt()`; returns the paused state."""
    ctx = make_context(mode, thread_id, **flags)
    config = _config(thread_id, ctx.policy)
    async with open_saver() as saver:
        from src.agent import c0_fixed

        sg = (
            build_c0_graph(ctx, thread_id, c0_fixed.scan_node, c0_fixed.draft_node)
            if mode == "c0_fixed"
            else build_graph(ctx, thread_id)
        )
        compiled = sg.compile(checkpointer=saver)
        snapshot = await compiled.aget_state(config)
        graph_input: Optional[dict[str, Any]]
        if resume and snapshot.values:
            if _is_paused(snapshot):
                return as_state(snapshot.values["inv"])
            saved = as_state(snapshot.values["inv"])
            ctx.ledger.preload(
                calls=saved.tool_calls_used, cost_usd=saved.estimated_cost_usd, replans=saved.replan_count
            )
            graph_input = None
        else:
            initial = InvestigationState(thread_id=thread_id, alert=alert)
            graph_input = {"inv": to_jsonable_python(initial.model_dump(mode="json"))}
        async for chunk in compiled.astream(graph_input, config, stream_mode="values", durability="sync"):
            inv = chunk.get("inv") if isinstance(chunk, dict) else None
            if inv and stop_after_node and inv.get("current_node") == stop_after_node:
                raise SimulatedCrashInterrupt(f"Simulated crash after {stop_after_node}")
        final = await compiled.aget_state(config)
    if not final.values:
        raise RuntimeError("graph finished without state")
    state = as_state(final.values["inv"])
    _persist(thread_id, mode, final.values["inv"], status="interrupt_required")
    return state


async def resume_gate(thread_id: str, mode: str, decision: dict[str, Any]) -> bool:
    """Resume the paused `human_gate` interrupt with the human decision. Returns False if no interrupt is pending."""
    ctx = make_context(mode, thread_id)
    config = _config(thread_id, ctx.policy)
    async with open_saver() as saver:
        from src.agent import c0_fixed

        sg = (
            build_c0_graph(ctx, thread_id, c0_fixed.scan_node, c0_fixed.draft_node)
            if mode == "c0_fixed"
            else build_graph(ctx, thread_id)
        )
        compiled = sg.compile(checkpointer=saver)
        if not _is_paused(await compiled.aget_state(config)):
            return False
        await compiled.ainvoke(Command(resume=decision), config)
    return True
