"""
Compiled LangGraph `StateGraph` runtime shared by C0, C1, and C2.

Topology:
  START -> plan -> gather_evidence -> form_hypotheses -> critique --(contradiction)--> replan -> gather_evidence
                                                                   \\--(otherwise)--> draft -> human_gate (interrupt)
                                                                   --(approve + token)--> commit_disposition -> END

* Durable checkpointing: `AsyncSqliteSaver` locally / `AsyncPostgresSaver` when `USE_POSTGRES=true`.
* Native `interrupt()` pauses the run at `human_gate`; resuming with an `approval_token` executes `commit_disposition`
  through `GuardedToolbox` (`has_human_approval_token=True`). If `submit_case_disposition` fails validation, the graph
  loops back to `human_gate` (`interrupt()`) so a subsequent valid token can still commit.
* `recursion_limit` is derived from the replan budget so the loop always terminates (replan edge is budget-gated).
* State reducers: `evidence_registry` merges by key; `regulatory_clauses` merges by `clause_id`; `specialist_findings`
  merges by `task_id`; `degraded_evidence` / `regulatory_snippets` / `retrieved_lessons` union with de-duplication.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path
from typing import Annotated, Any, Optional, TypedDict, cast

from langchain_core.runnables import RunnableConfig
from langchain_core.runnables.config import var_child_runnable_config
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from pydantic_core import to_jsonable_python

from src.agent import c0_fixed, nodes
from src.agent.c2_loop import run_c2_agent_team
from src.agent.llm_client import is_live_llm_active
from src.agent.loop import run_c1_agent_loop
from src.agent.nodes import RunContext
from src.agent.tooling import GuardedToolbox
from src.config import get_policy, settings
from src.core.policy import PolicyConfig
from src.db.database import get_sqlite_path, load_checkpoint, save_checkpoint
from src.llm.client import LLMClient, LLMClientProtocol
from src.llm.replay import LLMMode
from src.llm.schemas import ChatResponse
from src.models import Alert, InvestigationState

logger = logging.getLogger("auditguard.graph")

DICT_MERGE_KEYS = frozenset({"evidence_registry"})
LIST_UNION_KEYS = frozenset({"degraded_evidence", "regulatory_snippets", "retrieved_lessons"})
C2_ROLES = ("flow_tracer", "benign_investigator", "regulatory_analyst", "reporter_critic")
_THREAD_LOCKS: dict[str, asyncio.Lock] = {}
_SAVER_INIT_LOCKS: dict[int, asyncio.Lock] = {}
_INITIALIZED_SAVER_PATHS: set[str] = set()
_MAX_THREAD_LOCKS = 2048


class SimulatedCrashInterrupt(RuntimeError):
    """Raised intentionally by crash/resume tests after a node's checkpoint is committed."""


def _lock_for_thread(thread_id: str) -> asyncio.Lock:
    lock = _THREAD_LOCKS.get(thread_id)
    if lock is None:
        if len(_THREAD_LOCKS) >= _MAX_THREAD_LOCKS:
            for stale_id in list(_THREAD_LOCKS.keys())[: _MAX_THREAD_LOCKS // 2]:
                if not _THREAD_LOCKS[stale_id].locked():
                    _THREAD_LOCKS.pop(stale_id, None)
        lock = asyncio.Lock()
        _THREAD_LOCKS[thread_id] = lock
    return lock


def _merge_field(old: dict[str, Any], key: str, value: Any) -> Any:
    if key in DICT_MERGE_KEYS and isinstance(value, dict):
        return {**old.get(key, {}), **value}
    if key == "regulatory_clauses" and isinstance(value, list):
        by_id = {c["clause_id"]: c for c in [*old.get(key, []), *value] if isinstance(c, dict) and c.get("clause_id")}
        return list(by_id.values())
    if key == "specialist_findings" and isinstance(value, list):
        by_task = {f["task_id"]: f for f in [*old.get(key, []), *value] if isinstance(f, dict) and f.get("task_id")}
        return list(by_task.values())
    if key == "tool_errors" and isinstance(value, list):
        seen: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for item in [*old.get(key, []), *value]:
            if isinstance(item, dict):
                ek = (
                    str(item.get("server", "")),
                    str(item.get("tool", "")),
                    str(item.get("error_code", "")),
                    str(item.get("message", "")),
                )
                seen[ek] = item
        return list(seen.values())
    if key in LIST_UNION_KEYS and isinstance(value, list):
        return list(dict.fromkeys([*old.get(key, []), *value]))
    return value


def merge_investigation(old: Optional[dict[str, Any]], new: Optional[dict[str, Any]]) -> dict[str, Any]:
    """LangGraph reducer for the `inv` channel (see module docstring for the per-key policy)."""
    if not old:
        return dict(new or {})
    out = dict(old)
    for key, value in (new or {}).items():
        out[key] = _merge_field(old, key, value)
    return out


class GState(TypedDict, total=False):
    inv: Annotated[dict[str, Any], merge_investigation]
    gate: dict[str, Any]


def as_state(raw: dict[str, Any]) -> InvestigationState:
    return InvestigationState(**{k: v for k, v in raw.items() if k in InvestigationState.model_fields})


def recursion_limit(policy: PolicyConfig) -> int:
    """One pass is 4 nodes (+replan); allow max_replans+1 passes plus draft/gate/commit headroom."""
    return (policy.budgets.max_replans + 1) * 4 + 8


def make_context(mode: str, thread_id: str, **flags: Any) -> RunContext:
    budget_overrides = flags.pop("budget_overrides", None)
    policy = get_policy()
    if isinstance(budget_overrides, dict) and budget_overrides:
        policy = policy.model_copy(
            update={"budgets": policy.budgets.model_copy(update=budget_overrides)}
        )
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
        flags.setdefault("allow_llm", False)
        flags.setdefault("llm_mode", "offline")
        return RunContext(
            mode=mode,
            policy=policy,
            ledger=ledger,
            boxes={"primary": box},
            label="auditguard-c0-fixed",
            role="c1_investigator",
            **flags,
        )
    if mode == "rule_engine":
        box = GuardedToolbox("rule_engine", ledger, thread_id)
        flags["allow_llm"] = False
        flags["llm_mode"] = "offline"
        return RunContext(
            mode=mode,
            policy=policy,
            ledger=ledger,
            boxes={"primary": box},
            label="auditguard-rule-engine",
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


def checkpoint_db_path() -> Path:
    return Path(get_sqlite_path()).with_suffix(".langgraph.sqlite")


def _saver_lock(db_str: str) -> asyncio.Lock:
    loop_id = id(asyncio.get_running_loop())
    key = hash((loop_id, db_str))
    lock = _SAVER_INIT_LOCKS.get(key)
    if lock is None:
        if len(_SAVER_INIT_LOCKS) > 64:
            _SAVER_INIT_LOCKS.clear()
        lock = asyncio.Lock()
        _SAVER_INIT_LOCKS[key] = lock
    return lock


@asynccontextmanager
async def open_saver() -> AsyncIterator[Any]:
    if settings.use_postgres:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        async with AsyncPostgresSaver.from_conn_string(settings.sync_database_url) as saver:
            await saver.setup()
            yield saver
    else:
        import aiosqlite
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

        db_file = checkpoint_db_path()
        db_str = str(db_file.resolve())
        db_file.parent.mkdir(parents=True, exist_ok=True)
        shared_lock = _saver_lock(db_str)
        async with shared_lock:
            if db_str not in _INITIALIZED_SAVER_PATHS or not db_file.exists() or db_file.stat().st_size == 0:
                async with aiosqlite.connect(db_str, timeout=30.0) as init_conn:
                    await init_conn.execute("PRAGMA busy_timeout = 30000;")
                    await AsyncSqliteSaver(init_conn).setup()
                _INITIALIZED_SAVER_PATHS.add(db_str)
        async with aiosqlite.connect(db_str, timeout=30.0) as conn:
            await conn.execute("PRAGMA busy_timeout = 30000;")
            sq_saver = AsyncSqliteSaver(conn)
            sq_saver.lock = shared_lock
            sq_saver.is_setup = True
            yield sq_saver


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
        await asyncio.to_thread(_persist, thread_id, ctx.mode, merged)
        if ctx.emit is not None:
            await asyncio.to_thread(ctx.emit, name, merged)
        return {"inv": update}

    return run


async def _human_gate(gs: GState, config: RunnableConfig) -> GState:
    inv = gs["inv"]
    ws = inv.get("worksheet") or {}
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
    payload = decision if isinstance(decision, dict) else {}
    approved = payload.get("action") == "approve"
    has_token = bool(payload.get("approval_token"))
    return {
        "inv": {
            "current_node": "committing" if (approved and has_token) else ("committed" if approved else "rejected"),
            "human_decision": payload.get("disposition") if approved else None,
        },
        "gate": payload,
    }


def _make_commit_node(ctx: RunContext) -> Callable[[GState], Awaitable[GState]]:
    async def _commit_disposition(gs: GState) -> GState:
        gate = dict(gs.get("gate") or {})
        res = await ctx.box("primary").call(
            "case-actions",
            "submit_case_disposition",
            {
                "worksheet_id": str(gate.get("worksheet_id") or ""),
                "approval_token": str(gate.get("approval_token") or ""),
                "reviewer_id": str(gate.get("reviewer") or ""),
                "reviewer_notes": str(gate.get("reviewer_notes") or ""),
                "thread_id": str(gate.get("thread_id") or ""),
            },
            has_human_approval_token=True,
        )
        ok = bool(res.get("success"))
        return {
            "inv": {
                "current_node": "committed" if ok else "interrupt_required",
                "human_decision": res.get("final_disposition") if ok else None,
            },
            "gate": {**gate, "commit_result": res},
        }

    return _commit_disposition


def _route_after_gate(gs: GState) -> str:
    gate = gs.get("gate") or {}
    if gate.get("action") == "approve" and gate.get("approval_token"):
        return "commit_disposition"
    return "__end__"


def _route_after_commit(gs: GState) -> str:
    commit_res = (gs.get("gate") or {}).get("commit_result") or {}
    return "__end__" if commit_res.get("success") else "human_gate"


def _attach_gate_and_commit(graph: StateGraph[Any, Any, Any, Any], ctx: RunContext, draft_node_name: str) -> None:
    graph.add_node("human_gate", _human_gate)  # type: ignore[call-overload]
    graph.add_node("commit_disposition", _make_commit_node(ctx))  # type: ignore[call-overload]
    graph.add_edge(draft_node_name, "human_gate")
    graph.add_conditional_edges(
        "human_gate",
        _route_after_gate,
        {"commit_disposition": "commit_disposition", "__end__": END},
    )
    graph.add_conditional_edges(
        "commit_disposition",
        _route_after_commit,
        {"__end__": END, "human_gate": "human_gate"},
    )


def build_graph(ctx: RunContext, thread_id: str) -> StateGraph[Any, Any, Any, Any]:
    graph: StateGraph[Any, Any, Any, Any] = StateGraph(GState)
    graph.add_node("plan", _wrap("plan", nodes.plan_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("gather_evidence", _wrap("gather_evidence", nodes.gather_evidence_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("form_hypotheses", _wrap("form_hypotheses", nodes.hypothesis_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("critique", _wrap("critique", nodes.critique_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("replan", _wrap("replan", nodes.replan_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("draft", _wrap("draft", nodes.draft_worksheet_node, ctx, thread_id))  # type: ignore[call-overload]
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
    _attach_gate_and_commit(graph, ctx, "draft")
    return graph


def build_c2_graph(ctx: RunContext, thread_id: str) -> StateGraph[Any, Any, Any, Any]:
    """Supervisor + 4 RBAC Specialists StateGraph with per-specialist durable checkpointing."""
    graph: StateGraph[Any, Any, Any, Any] = StateGraph(GState)
    graph.add_node("supervisor_plan", _wrap("supervisor_plan", nodes.plan_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("flow_tracer", _wrap("flow_tracer", nodes.flow_tracer_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node(
        "parallel_specialists", _wrap("parallel_specialists", nodes.parallel_specialists_node, ctx, thread_id)
    )  # type: ignore[call-overload]
    graph.add_node("supervisor_hypotheses", _wrap("supervisor_hypotheses", nodes.hypothesis_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("supervisor_critique", _wrap("supervisor_critique", nodes.critique_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("supervisor_replan", _wrap("supervisor_replan", nodes.replan_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("reporter_critic", _wrap("reporter_critic", nodes.draft_worksheet_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_edge(START, "supervisor_plan")
    graph.add_edge("supervisor_plan", "flow_tracer")
    graph.add_edge("flow_tracer", "parallel_specialists")
    graph.add_edge("parallel_specialists", "supervisor_hypotheses")
    graph.add_edge("supervisor_hypotheses", "supervisor_critique")
    graph.add_conditional_edges(
        "supervisor_critique",
        lambda gs: nodes.should_replan(as_state(gs["inv"]), ctx),
        {"replan": "supervisor_replan", "draft": "reporter_critic"},
    )
    graph.add_edge("supervisor_replan", "flow_tracer")
    _attach_gate_and_commit(graph, ctx, "reporter_critic")
    return graph


def build_c0_graph(
    ctx: RunContext, thread_id: str, scan_fn: NodeFn, draft_fn: NodeFn
) -> StateGraph[Any, Any, Any, Any]:
    """Fixed linear StateGraph for C0 (`scan -> draft -> human_gate(interrupt) -> commit_disposition -> END`)."""
    graph: StateGraph[Any, Any, Any, Any] = StateGraph(GState)
    graph.add_node("gather_evidence", _wrap("gather_evidence", scan_fn, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_node("draft", _wrap("draft", draft_fn, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_edge(START, "gather_evidence")
    graph.add_edge("gather_evidence", "draft")
    _attach_gate_and_commit(graph, ctx, "draft")
    return graph


class _GateOnlyLLM:
    """Placeholder satisfying `LLMClientProtocol` when resuming an already-drafted LLM thread at `human_gate`."""

    @property
    def transcript_path(self) -> Optional[Path]:
        return None

    async def chat(self, messages: list[dict[str, Any]], **_: Any) -> ChatResponse:
        raise RuntimeError("_GateOnlyLLM cannot execute chat turns during post-interrupt gate resume")


def _resolve_llm_client(ctx: RunContext) -> Optional[LLMClientProtocol]:
    if not ctx.allow_llm or ctx.mode in ("c0_fixed", "rule_engine"):
        return None
    if ctx.llm_client is not None:
        return cast(LLMClientProtocol, ctx.llm_client)
    raw_mode = (ctx.llm_mode or os.getenv("LLM_MODE") or "").strip().lower()
    if raw_mode == "offline":
        return None
    if raw_mode in ("live", "record", "replay"):
        return LLMClient(
            mode=cast(LLMMode, raw_mode),
            cassette_path=ctx.cassette_path or os.getenv("LLM_CASSETTE_PATH"),
            run_id=ctx.run_id or os.getenv("LLM_RUN_ID"),
        )
    if is_live_llm_active():
        return LLMClient(mode="live", run_id=ctx.run_id or os.getenv("LLM_RUN_ID"))
    return None


def build_llm_c1_graph(
    ctx: RunContext, thread_id: str, llm_client: LLMClientProtocol
) -> StateGraph[Any, Any, Any, Any]:
    """Single-agent LLM ReAct tool-calling loop wrapped with `human_gate(interrupt)` and `commit_disposition`."""
    graph: StateGraph[Any, Any, Any, Any] = StateGraph(GState)

    async def _loop_node(state: InvestigationState, c: RunContext) -> dict[str, Any]:
        return await run_c1_agent_loop(state, c, llm_client)

    graph.add_node("agent_loop", _wrap("agent_loop", _loop_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_edge(START, "agent_loop")
    _attach_gate_and_commit(graph, ctx, "agent_loop")
    return graph


def build_llm_c2_graph(
    ctx: RunContext, thread_id: str, llm_client: LLMClientProtocol
) -> StateGraph[Any, Any, Any, Any]:
    """Supervisor + 4 RBAC Specialist LLMs wrapped with `human_gate(interrupt)` and `commit_disposition`."""
    graph: StateGraph[Any, Any, Any, Any] = StateGraph(GState)

    async def _team_node(state: InvestigationState, c: RunContext) -> dict[str, Any]:
        return await run_c2_agent_team(state, c, llm_client)

    graph.add_node("c2_agent_team", _wrap("c2_agent_team", _team_node, ctx, thread_id))  # type: ignore[call-overload]
    graph.add_edge(START, "c2_agent_team")
    _attach_gate_and_commit(graph, ctx, "c2_agent_team")
    return graph


def select_graph(ctx: RunContext, thread_id: str) -> StateGraph[Any, Any, Any, Any]:
    if ctx.mode == "c0_fixed":
        return build_c0_graph(ctx, thread_id, c0_fixed.scan_node, c0_fixed.draft_node)
    if ctx.mode == "rule_engine":
        return build_graph(ctx, thread_id)
    llm_client = _resolve_llm_client(ctx)
    if llm_client is not None:
        ctx.llm_client = llm_client
        if ctx.mode == "c2_multi":
            return build_llm_c2_graph(ctx, thread_id, llm_client)
        return build_llm_c1_graph(ctx, thread_id, llm_client)
    if ctx.mode == "c2_multi":
        return build_c2_graph(ctx, thread_id)
    return build_graph(ctx, thread_id)


def _config(thread_id: str, policy: PolicyConfig) -> RunnableConfig:
    return {"configurable": {"thread_id": thread_id}, "recursion_limit": recursion_limit(policy)}


def _is_paused(snapshot: Any) -> bool:
    return bool(snapshot.values) and any(getattr(t, "interrupts", None) for t in snapshot.tasks)


_MULTI_NODE_STAGES = frozenset(
    {
        "plan",
        "gather_evidence",
        "form_hypotheses",
        "critique",
        "replan",
        "draft",
        "supervisor_plan",
        "flow_tracer",
        "parallel_specialists",
        "supervisor_hypotheses",
        "supervisor_critique",
        "supervisor_replan",
        "reporter_critic",
    }
)


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
    if stop_after_node in _MULTI_NODE_STAGES and flags.get("llm_mode") is None and flags.get("llm_client") is None:
        flags["llm_mode"] = "offline"
    elif resume and flags.get("llm_client") is None and flags.get("llm_mode") is None:
        cp = await asyncio.to_thread(load_checkpoint, thread_id)
        cp_state = (cp or {}).get("state") or {}
        if isinstance(cp_state, dict) and cp_state.get("reasoning_mode") != "llm_tool_loop":
            flags["llm_mode"] = "offline"
    ctx = make_context(mode, thread_id, **flags)
    config = _config(thread_id, ctx.policy)
    async with _lock_for_thread(thread_id), open_saver() as saver:
        compiled = select_graph(ctx, thread_id).compile(checkpointer=saver)
        snapshot = await compiled.aget_state(config)
        graph_input: Optional[dict[str, Any]]
        if resume and snapshot.values:
            if _is_paused(snapshot):
                return as_state(snapshot.values["inv"])
            saved = as_state(snapshot.values["inv"])
            ctx.ledger.preload(
                calls=saved.tool_calls_used,
                cost_usd=saved.estimated_cost_usd,
                replans=saved.replan_count,
                critique_retries=saved.critique_retries_used,
                tokens_used=saved.total_tokens_used,
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
    await asyncio.to_thread(_persist, thread_id, mode, final.values["inv"], "interrupt_required")
    return state


async def _context_for_gate_resume(mode: str, thread_id: str) -> RunContext:
    cp = await asyncio.to_thread(load_checkpoint, thread_id)
    saved_state = (cp or {}).get("state") or {}
    if isinstance(saved_state, dict) and saved_state.get("reasoning_mode") == "llm_tool_loop":
        return make_context(mode, thread_id, llm_client=_GateOnlyLLM())
    return make_context(mode, thread_id, llm_mode="offline")


async def resume_gate(thread_id: str, mode: str, decision: dict[str, Any]) -> bool:
    """Resume the paused `human_gate` interrupt with the human decision. Returns False if no interrupt is pending."""
    ctx = await _context_for_gate_resume(mode, thread_id)
    config = _config(thread_id, ctx.policy)
    async with _lock_for_thread(thread_id), open_saver() as saver:
        compiled = select_graph(ctx, thread_id).compile(checkpointer=saver)
        if not _is_paused(await compiled.aget_state(config)):
            return False
        await compiled.ainvoke(Command(resume=decision), config)
    return True


async def resume_and_commit_gate(thread_id: str, mode: str, decision: dict[str, Any]) -> Optional[dict[str, Any]]:
    """
    Resume `human_gate` and execute `commit_disposition` through the guarded MCP tool gate.
    Returns `None` if no LangGraph `interrupt()` is currently active on `thread_id`.
    """
    ctx = await _context_for_gate_resume(mode, thread_id)
    config = _config(thread_id, ctx.policy)
    async with _lock_for_thread(thread_id), open_saver() as saver:
        compiled = select_graph(ctx, thread_id).compile(checkpointer=saver)
        if not _is_paused(await compiled.aget_state(config)):
            return None
        out = await compiled.ainvoke(Command(resume=decision), config)
    gate = out.get("gate") if isinstance(out, dict) else None
    commit_result = gate.get("commit_result") if isinstance(gate, dict) else None
    return dict(commit_result) if isinstance(commit_result, dict) else {"success": False, "error_code": "COMMIT_FAILED"}
