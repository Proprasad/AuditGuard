"""
Guarded tool execution runtime (`AgentToolRuntime`) and public re-exports for OpenAI
tool schemas, `calc` (`Decimal`), `replan_graph`, and `finish`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, Optional

from pydantic import ValidationError

from src.agent.drafting import security_notes
from src.agent.replanning import build_replan_comparison, build_replan_record, capture_replan_snapshot
from src.agent.tool_schemas import (
    TOOL_SPECS,
    CalcInput,
    FinishInvestigationInput,
    HypothesisDraft,
    LLMCompareRunsInput,
    LLMConservationInput,
    LLMFindFlowsInput,
    ReplanGraphInput,
    build_hypotheses_from_finish,
    build_openai_tools,
    execute_decimal_calc,
    format_rationale_with_missing,
)
from src.agent.tooling import GuardedToolbox, error_envelope, is_error
from src.core.adapters import flow_paths_from_result, graph_tx_payload
from src.core.canonical import NumericError, to_ratio
from src.db.database import append_audit_log
from src.guardrails.hooks import AGENT_TOOL_ALLOWLIST, post_tool_hook, pre_tool_hook
from src.mcp_servers.client import call_mcp_tool
from src.models import Alert, FundFlowPath, GraphParams, InvestigationPlan

__all__ = [
    "TOOL_SPECS",
    "AgentToolRuntime",
    "CalcInput",
    "FinishInvestigationInput",
    "HypothesisDraft",
    "LLMCompareRunsInput",
    "LLMConservationInput",
    "LLMFindFlowsInput",
    "ReplanGraphInput",
    "build_hypotheses_from_finish",
    "build_openai_tools",
    "execute_decimal_calc",
    "format_rationale_with_missing",
]


def _ingest_txs(rt: AgentToolRuntime, items: list[Any]) -> None:
    seen = {t.get("tx_id") for t in rt.transactions}
    for tx in items:
        if isinstance(tx, dict) and tx.get("tx_id") and tx["tx_id"] not in seen:
            rt.transactions.append(tx)
            seen.add(tx["tx_id"])
            rt.evidence_registry[str(tx["tx_id"])] = tx


def _on_alert_ctx(rt: AgentToolRuntime, res: dict[str, Any]) -> None:
    rt.root_account = str(res.get("root_account") or rt.root_account)
    rt.network_accounts = list(res.get("network_accounts") or rt.network_accounts)
    _ingest_txs(rt, list(res.get("transactions") or []))


def _on_account_txs(rt: AgentToolRuntime, res: dict[str, Any]) -> None:
    _ingest_txs(rt, list(res.get("transactions") or []))


def _on_kyc(rt: AgentToolRuntime, res: dict[str, Any]) -> None:
    acc = str(res.get("account_id", ""))
    rt.evidence_registry[str(res.get("evidence_id") or f"KYC-{acc}")] = res
    if all(str(k.get("account_id", "")) != acc for k in rt.kyc_profiles):
        rt.kyc_profiles.append(res)


def _on_registry(rt: AgentToolRuntime, res: dict[str, Any]) -> None:
    if res.get("evidence_id"):
        rt.evidence_registry[str(res["evidence_id"])] = res
    acc = str(res.get("account_id") or "")
    for kyc in rt.kyc_profiles:
        if acc and str(kyc.get("account_id", "")) == acc:
            kyc["registry_check"] = res


def _on_counterparty(rt: AgentToolRuntime, res: dict[str, Any]) -> None:
    ev_id = str(res.get("evidence_id") or f"CP-{res.get('account_id')}-{res.get('counterparty_id')}")
    rt.evidence_registry[ev_id] = res


def _on_flows(rt: AgentToolRuntime, res: dict[str, Any]) -> None:
    if res.get("calc_id"):
        rt.evidence_registry[str(res["calc_id"])] = res.get("graph_stats", {})
        rt.calc_log.append({"calc_id": res["calc_id"], **dict(res.get("graph_stats") or {})})
    paths = flow_paths_from_result(res, limit=5)
    if not rt.initial_fund_flow_paths and not rt.graph_runs:
        rt.initial_fund_flow_paths = list(paths)
    rt.fund_flow_paths = paths
    for p in paths:
        rt.evidence_registry[p.path_id] = p.model_dump(mode="json")
    rt.graph_runs.append(res)


def _on_conservation(rt: AgentToolRuntime, res: dict[str, Any]) -> None:
    cid = f"CALC-CONS-{len(rt.calc_log) + 1:02d}"
    rt.evidence_registry[cid] = res
    rt.calc_log.append({"calc_id": cid, **res})


def _on_regulations(rt: AgentToolRuntime, res: dict[str, Any]) -> None:
    raw_list = res.get("clauses")
    clauses = raw_list if isinstance(raw_list, list) else ([res] if res.get("clause_id") else [])
    known = {c["clause_id"] for c in rt.regulatory_clauses if c.get("clause_id")}
    for c in clauses:
        if isinstance(c, dict) and c.get("clause_id"):
            cid = str(c["clause_id"])
            rt.evidence_registry[cid] = c
            if cid not in known:
                rt.regulatory_clauses.append(c)
                known.add(cid)
                rt.regulatory_snippets.append(f"[{cid}] {c.get('title', '')}: {c.get('text', '')}")


_INGEST_HANDLERS: dict[str, Callable[[AgentToolRuntime, dict[str, Any]], None]] = {
    "get_alert_context": _on_alert_ctx,
    "get_account_transactions": _on_account_txs,
    "get_kyc_profile": _on_kyc,
    "check_commercial_registry": _on_registry,
    "get_counterparty_history": _on_counterparty,
    "find_candidate_fund_flows": _on_flows,
    "replan_graph": _on_flows,
    "compute_flow_conservation": _on_conservation,
    "search_regulations": _on_regulations,
    "get_clause_by_id": _on_regulations,
}


class AgentToolRuntime:
    """Stateful guarded tool dispatcher for a single agent or C2 specialist run."""

    def __init__(
        self,
        *,
        role: str,
        box: GuardedToolbox,
        alert: Alert,
        configurable_graph: bool = True,
        replanning_enabled: bool = True,
        allow_calc: bool = True,
        allow_registry: bool = True,
        allow_rag: bool = True,
        initial_transactions: Optional[list[dict[str, Any]]] = None,
        initial_paths: Optional[list[FundFlowPath]] = None,
        initial_registry: Optional[dict[str, Any]] = None,
        initial_baseline_paths: Optional[list[FundFlowPath]] = None,
    ) -> None:
        self.role = role
        self.box = box
        self.alert = alert
        self.configurable_graph = configurable_graph
        self.replanning_enabled = replanning_enabled
        self.allow_calc = allow_calc
        self.allow_registry = allow_registry
        self.allow_rag = allow_rag
        self.root_account = alert.root_account
        self.network_accounts = list(alert.network_accounts)
        self.transactions: list[dict[str, Any]] = list(initial_transactions or [])
        self.fund_flow_paths: list[FundFlowPath] = list(initial_paths or [])
        self.initial_fund_flow_paths: list[FundFlowPath] = list(initial_baseline_paths or initial_paths or [])
        self.kyc_profiles: list[dict[str, Any]] = []
        self.regulatory_clauses: list[dict[str, Any]] = []
        self.regulatory_snippets: list[str] = []
        self.evidence_registry: dict[str, Any] = dict(initial_registry or {})
        self.calc_log: list[dict[str, Any]] = []
        self.degraded_evidence: list[str] = []
        self.graph_runs: list[dict[str, Any]] = []
        self.replan_records: list[dict[str, Any]] = []
        self.tool_execution_log: list[dict[str, Any]] = []
        self.replan_count = 0
        self.last_replan_reason: Optional[str] = None
        self.current_graph_params = GraphParams.policy_default()
        self.finish_submission: Optional[FinishInvestigationInput] = None

    def plan_snapshot(self, steps: Optional[list[str]] = None) -> InvestigationPlan:
        return InvestigationPlan(
            steps=steps or ["LLM ReAct tool-calling investigation"],
            graph_params=self.current_graph_params,
            focus_accounts=list(dict.fromkeys([self.root_account, *self.network_accounts[:5]])),
            regulatory_queries=[],
            clause_ids=[c["clause_id"] for c in self.regulatory_clauses if c.get("clause_id")],
            replan_count=self.replan_count,
            replan_reason=self.last_replan_reason,
        )

    async def _record_local_error(self, tool: str, code: str, message: str) -> dict[str, Any]:
        entry = {"server": "agent-tools", "tool": tool, "error_code": code, "message": message}
        self.box.tool_errors.append(entry)
        await asyncio.to_thread(append_audit_log, self.box.thread_id, "tool_error_recorded", self.role, entry)
        return error_envelope(code, message)

    def _sub_budget_exceeded(self) -> bool:
        return self.box.allowed_tool_budget is not None and self.box.calls >= self.box.allowed_tool_budget

    async def _run_calc_tool(self, args: dict[str, Any]) -> dict[str, Any]:
        if not self.allow_calc:
            return await self._record_local_error("calc", "ABLATION_DISABLED", "calc tool disabled in llm_math mode")
        if self._sub_budget_exceeded():
            msg = f"Specialist '{self.role}' exhausted handoff tool budget ({self.box.calls})"
            return await self._record_local_error("calc", "SPECIALIST_BUDGET_EXCEEDED", msg)
        hook = pre_tool_hook(self.role, "calc", args, ledger=self.box.ledger)
        if not hook.allowed:
            return await self._record_local_error("calc", hook.error_code, hook.message)
        try:
            parsed = CalcInput.model_validate(args)
            raw = execute_decimal_calc(parsed)
        except (ValidationError, NumericError, ValueError) as exc:
            return await self._record_local_error("calc", "CALC_INPUT_ERROR", str(exc)[:240])
        self.box.calls += 1
        sanitized = dict(post_tool_hook("calc", raw))
        self.evidence_registry[str(sanitized["calc_id"])] = sanitized
        self.calc_log.append(sanitized)
        return sanitized

    def _proposed_params_from_raw(self, args: dict[str, Any]) -> GraphParams:
        try:
            return GraphParams(
                time_window_days=int(args.get("time_window_days", self.current_graph_params.time_window_days)),
                max_hops=int(args.get("max_hops", self.current_graph_params.max_hops)),
                amount_tolerance=to_ratio(args.get("amount_tolerance", self.current_graph_params.amount_tolerance)),
                min_intermediaries=self.current_graph_params.min_intermediaries,
            )
        except (TypeError, ValueError, NumericError):
            return self.current_graph_params

    def _record_rejected_replan(
        self, args: dict[str, Any], status: Any, detail: str
    ) -> None:
        before = capture_replan_snapshot(self.current_graph_params, self.fund_flow_paths, self.evidence_registry)
        rec = build_replan_record(
            seq=len(self.replan_records) + 1,
            original_params=self.current_graph_params,
            proposed_params=self._proposed_params_from_raw(args),
            reason=str(args.get("reason") or detail),
            evidence_ids=list(self.evidence_registry.keys())[:8],
            before=before,
            validation_result=status,
            validation_detail=detail,
            execution_status="skipped",
        )
        self.replan_records.append(rec.model_dump(mode="json"))

    async def _run_replan_tool(self, args: dict[str, Any]) -> dict[str, Any]:
        if not self.replanning_enabled:
            self._record_rejected_replan(args, "rejected_disabled", "Replanning is disabled")
            return await self._record_local_error("replan_graph", "REPLAN_DISABLED", "Replanning is disabled")
        if self._sub_budget_exceeded():
            msg = f"Specialist '{self.role}' exhausted handoff budget"
            self._record_rejected_replan(args, "rejected_budget", msg)
            return await self._record_local_error("replan_graph", "SPECIALIST_BUDGET_EXCEEDED", msg)
        bounds_check = pre_tool_hook(self.role, "replan_graph", args, ledger=None)
        if not bounds_check.allowed:
            self._record_rejected_replan(args, "rejected_bounds", bounds_check.message)
            return await self._record_local_error("replan_graph", bounds_check.error_code, bounds_check.message)
        try:
            parsed = ReplanGraphInput.model_validate(args)
        except ValidationError as exc:
            self._record_rejected_replan(args, "rejected_bounds", str(exc)[:240])
            return await self._record_local_error("replan_graph", "INVALID_TOOL_ARGS", str(exc)[:240])
        if not self.transactions:
            return await self._record_local_error(
                "replan_graph", "NO_TRANSACTIONS", "Call get_alert_context before replan_graph"
            )
        replan_verdict = self.box.ledger.try_replan()
        if not replan_verdict.allowed:
            self._record_rejected_replan(args, "rejected_budget", replan_verdict.message)
            return await self._record_local_error("replan_graph", replan_verdict.error_code, replan_verdict.message)
        budget_hook = pre_tool_hook(self.role, "replan_graph", args, ledger=self.box.ledger)
        if not budget_hook.allowed:
            self._record_rejected_replan(args, "rejected_budget", budget_hook.message)
            return await self._record_local_error("replan_graph", budget_hook.error_code, budget_hook.message)

        orig_params = self.current_graph_params
        old_path_ids = {p.path_id for p in self.fund_flow_paths}
        before_snap = capture_replan_snapshot(orig_params, self.fund_flow_paths, self.evidence_registry)
        new_params = GraphParams(
            time_window_days=parsed.time_window_days,
            max_hops=parsed.max_hops,
            amount_tolerance=parsed.amount_tolerance,
            min_intermediaries=orig_params.min_intermediaries,
        )
        self.box.calls += 1
        self.replan_count += 1
        self.last_replan_reason = parsed.reason
        self.current_graph_params = new_params
        mcp_params = {
            "root_account": self.root_account,
            "transactions": graph_tx_payload(self.transactions),
            **new_params.model_dump(mode="json"),
        }
        raw = await call_mcp_tool("graph-engine", "find_candidate_fund_flows", mcp_params)
        if is_error(raw):
            code = str(raw.get("error_code") or "MCP_TOOL_ERROR")
            msg = str(raw.get("message") or "failed")
            rec_fail = build_replan_record(
                seq=len(self.replan_records) + 1,
                original_params=orig_params,
                proposed_params=new_params,
                reason=parsed.reason,
                evidence_ids=list(self.evidence_registry.keys())[:8],
                before=before_snap,
                validation_result="approved",
                validation_detail=f"MCP error: {code}",
                execution_status="failed",
            )
            self.replan_records.append(rec_fail.model_dump(mode="json"))
            return await self._record_local_error("replan_graph", code, msg)
        sanitized = dict(post_tool_hook("replan_graph", raw))
        _on_flows(self, sanitized)
        after_snap = capture_replan_snapshot(new_params, self.fund_flow_paths, self.evidence_registry)
        comp = build_replan_comparison(before_snap, after_snap, old_path_ids, self.fund_flow_paths)
        rec = build_replan_record(
            seq=len(self.replan_records) + 1,
            original_params=orig_params,
            proposed_params=new_params,
            reason=parsed.reason,
            evidence_ids=list(self.evidence_registry.keys())[:8],
            before=before_snap,
            validation_result="approved",
            validation_detail="Within policy bounds and budget",
            execution_status="executed",
            comparison=comp,
        )
        self.replan_records.append(rec.model_dump(mode="json"))
        return {**sanitized, "replan_count": self.replan_count, "replan_reason": parsed.reason}

    async def _run_finish_tool(self, args: dict[str, Any]) -> dict[str, Any]:
        hook = pre_tool_hook(self.role, "finish", args, ledger=self.box.ledger)
        if not hook.allowed:
            return await self._record_local_error("finish", hook.error_code, hook.message)
        try:
            self.finish_submission = FinishInvestigationInput.model_validate(args)
        except ValidationError as exc:
            return error_envelope("FINISH_VALIDATION_ERROR", str(exc)[:600])
        return {"status": "ok", "accepted_for_verification": True}

    def _hydrate_graph_args(
        self, tool_name: str, mcp_args: dict[str, Any]
    ) -> tuple[Optional[dict[str, Any]], str, str]:
        if tool_name == "find_candidate_fund_flows":
            if not mcp_args.get("transactions"):
                if not self.transactions:
                    return None, "NO_TRANSACTIONS", "Call get_alert_context before find_candidate_fund_flows"
                mcp_args["transactions"] = graph_tx_payload(self.transactions)
            if not self.configurable_graph:
                fixed_p = GraphParams.policy_default()
                self.current_graph_params = fixed_p
                return {**mcp_args, **fixed_p.model_dump(mode="json")}, "", ""
            self.current_graph_params = GraphParams(
                time_window_days=int(mcp_args.get("time_window_days", self.current_graph_params.time_window_days)),
                max_hops=int(mcp_args.get("max_hops", self.current_graph_params.max_hops)),
                amount_tolerance=to_ratio(mcp_args.get("amount_tolerance", self.current_graph_params.amount_tolerance)),
                min_intermediaries=int(
                    mcp_args.get("min_intermediaries", self.current_graph_params.min_intermediaries)
                ),
            )
            return mcp_args, "", ""
        if tool_name == "compute_flow_conservation":
            wanted = set(mcp_args.pop("path_ids", []) or [])
            chosen = [p for p in self.fund_flow_paths if not wanted or p.path_id in wanted][:3]
            if not chosen:
                return None, "NO_PATHS", "No candidate paths available to check"
            mcp_args["paths"] = [p.model_dump(mode="json") for p in chosen]
            return mcp_args, "", ""
        if tool_name == "compare_graph_runs":
            if len(self.graph_runs) < 2:
                return None, "INSUFFICIENT_RUNS", "At least 2 graph scans are required for compare_graph_runs"
            return {"run_a": self.graph_runs[-2], "run_b": self.graph_runs[-1]}, "", ""
        return mcp_args, "", ""

    async def _dispatch_local_tool(self, tool_name: str, arguments: dict[str, Any]) -> Optional[dict[str, Any]]:
        if tool_name == "calc":
            return await self._run_calc_tool(arguments)
        if tool_name == "replan_graph":
            return await self._run_replan_tool(arguments)
        if tool_name == "finish":
            return await self._run_finish_tool(arguments)
        return None

    def _ablation_reason(self, tool_name: str) -> Optional[str]:
        if tool_name == "check_commercial_registry" and not self.allow_registry:
            return "registry check disabled"
        if tool_name in ("search_regulations", "get_clause_by_id") and not self.allow_rag:
            return "RAG retrieval disabled"
        return None

    def _log_tool_call(self, tool_name: str, res: dict[str, Any]) -> dict[str, Any]:
        self.tool_execution_log.append(
            {
                "role": self.role,
                "tool": tool_name,
                "status": "error" if is_error(res) else "ok",
                "error_code": res.get("error_code") if is_error(res) else None,
            }
        )
        return res

    async def execute(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a single tool call through RBAC, bounds, BudgetLedger, MCP, and `post_tool_hook`."""
        if "_invalid_json" in arguments:
            msg = f"Tool arguments were not valid JSON: {arguments['_invalid_json']!r}"
            return self._log_tool_call(tool_name, await self._record_local_error(tool_name, "INVALID_TOOL_JSON", msg))
        if tool_name not in AGENT_TOOL_ALLOWLIST.get(self.role, set()):
            return self._log_tool_call(
                tool_name,
                await self._record_local_error(
                    tool_name, "RBAC_DENIED", f"Agent '{self.role}' is not permitted to invoke '{tool_name}'"
                ),
            )
        local_res = await self._dispatch_local_tool(tool_name, arguments)
        if local_res is not None:
            return self._log_tool_call(tool_name, local_res)
        if tool_name not in TOOL_SPECS:
            err = await self._record_local_error(tool_name, "UNKNOWN_TOOL", f"Tool {tool_name!r} is not callable")
            return self._log_tool_call(tool_name, err)
        if abl_msg := self._ablation_reason(tool_name):
            err = await self._record_local_error(tool_name, "ABLATION_DISABLED", abl_msg)
            return self._log_tool_call(tool_name, err)
        server, model_cls, _ = TOOL_SPECS[tool_name]
        if tool_name == "find_candidate_fund_flows":
            pre_bounds = pre_tool_hook(self.role, tool_name, arguments, ledger=None)
            if not pre_bounds.allowed:
                return self._log_tool_call(
                    tool_name, await self._record_local_error(tool_name, pre_bounds.error_code, pre_bounds.message)
                )

        try:
            validated = model_cls.model_validate(arguments)
        except ValidationError as exc:
            return self._log_tool_call(
                tool_name, await self._record_local_error(tool_name, "INVALID_TOOL_ARGS", str(exc)[:300])
            )

        hydrated, err_code, err_msg = self._hydrate_graph_args(
            tool_name, validated.model_dump(mode="json", exclude_none=True)
        )
        if hydrated is None:
            return self._log_tool_call(tool_name, await self._record_local_error(tool_name, err_code, err_msg))

        res = await self.box.call(server, tool_name, hydrated)
        if is_error(res):
            self.degraded_evidence.append(f"Tool error [{server}.{tool_name}]: {res.get('error_code')}")
            return self._log_tool_call(tool_name, res)
        if handler := _INGEST_HANDLERS.get(tool_name):
            handler(self, res)
        self.degraded_evidence = sorted({*self.degraded_evidence, *security_notes(self.box)})
        return self._log_tool_call(tool_name, res)
