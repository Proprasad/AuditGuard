"""
Dynamic evidence gathering helpers and `gather_evidence_node` (shared across C1 and C2 specialists).

Target accounts, transaction lookbacks, counterparty history checks, and regulatory queries/clause lookups
are driven dynamically from `InvestigationPlan`, reconstructed `FundFlowPath` beneficiaries, and remaining
tool budgets (reserving headroom for bounded replans and worksheet drafting).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from src.agent.planning import RunContext, all_security_notes, err_code, sync_budget
from src.agent.tooling import GuardedToolbox, is_error
from src.core.adapters import flow_paths_from_result, graph_tx_payload
from src.guardrails.guardrails import unwrap_untrusted_data
from src.memory.store import trim_messages_with_summary
from src.models import FundFlowPath, GraphParams, InvestigationState, SpecialistFinding

DEFAULT_REG_QUERY = "scatter gather staggered layering fee skimming and commercial registry benign verification"
_REPLAN_DRAFT_HEADROOM = 5


def _candidate_accounts(
    state: InvestigationState, root: str, network: list[str], paths: list[FundFlowPath]
) -> list[str]:
    plan_focus = state.plan.focus_accounts if state.plan else []
    path_terminals = [p.nodes[-1] for p in paths if len(p.nodes) >= 2]
    path_nodes = [n for p in paths for n in p.nodes]
    ordered = [root, *plan_focus, *path_terminals, *network, *path_nodes]
    return list(dict.fromkeys(a for a in ordered if a))


def _can_spend_calls(ctx: RunContext, needed: int, *, reserve_draft: int = 1) -> bool:
    return ctx.ledger.calls_used + needed + reserve_draft <= ctx.policy.budgets.max_tool_calls


async def _profile_single_account(
    box: GuardedToolbox,
    acc: str,
    registry: dict[str, Any],
    degraded: list[str],
    *,
    allow_registry: bool = True,
) -> dict[str, Any] | None:
    kyc = await box.call("bank-records", "get_kyc_profile", {"account_id": acc})
    if is_error(kyc):
        degraded.append(f"KYC unavailable for {acc}: {err_code(kyc)}")
        return None
    registry[kyc.get("evidence_id", f"KYC-{acc}")] = kyc
    if not allow_registry:
        return kyc
    reg = await box.call(
        "bank-records",
        "check_commercial_registry",
        {"entity_name": unwrap_untrusted_data(str(kyc.get("entity_name", acc))), "account_id": acc},
    )
    if is_error(reg):
        degraded.append(f"Commercial registry unavailable for {acc}: {err_code(reg)}")
    elif reg.get("evidence_id"):
        registry[reg["evidence_id"]] = reg
        kyc["registry_check"] = reg
    return kyc


async def _profile_accounts_batch(
    ctx: RunContext,
    box: GuardedToolbox,
    targets: list[str],
    existing: list[dict[str, Any]],
    profiled_ids: set[str],
    registry: dict[str, Any],
    degraded: list[str],
) -> None:
    per_acc_calls = 2 if ctx.allow_registry else 1
    for acc in targets:
        if not _can_spend_calls(ctx, per_acc_calls):
            break
        rec = await _profile_single_account(box, acc, registry, degraded, allow_registry=ctx.allow_registry)
        if rec is not None:
            existing.append(rec)
            profiled_ids.add(acc)


async def gather_identity(
    ctx: RunContext,
    state: InvestigationState,
    root: str,
    network: list[str],
    paths: list[FundFlowPath],
    registry: dict[str, Any],
    degraded: list[str],
) -> list[dict[str, Any]]:
    box = ctx.box("benign_investigator")
    existing = list(state.kyc_profiles)
    profiled_ids = {str(k.get("account_id", "")) for k in existing}
    candidates = _candidate_accounts(state, root, network, paths)

    if not existing or state.refresh_kyc:
        avail_pairs = max(
            1,
            (ctx.policy.budgets.max_tool_calls - ctx.ledger.calls_used - _REPLAN_DRAFT_HEADROOM) // 2,
        )
        targets = [a for a in candidates if a not in profiled_ids][:avail_pairs]
        await _profile_accounts_batch(ctx, box, targets, existing, profiled_ids, registry, degraded)
    elif state.replan_count > 0:
        new_beneficiaries = [p.nodes[-1] for p in paths if p.hop_count >= 2 and p.nodes[-1] not in profiled_ids]
        targets = list(dict.fromkeys(new_beneficiaries))[:1]
        await _profile_accounts_batch(ctx, box, targets, existing, profiled_ids, registry, degraded)

    if state.replan_count > 0 and not any(p.hop_count >= 2 for p in paths):
        await _record_counterparty_history(ctx, box, state, root, registry, degraded)
    return existing


async def _record_counterparty_history(
    ctx: RunContext,
    box: GuardedToolbox,
    state: InvestigationState,
    root: str,
    registry: dict[str, Any],
    degraded: list[str],
) -> None:
    counterparties = list(
        dict.fromkeys(
            str(t["receiver_account"])
            for t in state.transactions
            if t.get("sender_account") == root and t.get("receiver_account")
        )
    )
    if not counterparties or not _can_spend_calls(ctx, 1):
        return
    cp_id = counterparties[0]
    cp_key = f"CP-{root}-{cp_id}"
    if cp_key in registry:
        return
    days_back = max(30, state.plan.graph_params.time_window_days) if state.plan else 90
    cp_res = await box.call(
        "bank-records",
        "get_counterparty_history",
        {"account_id": root, "counterparty_id": cp_id, "days_back": days_back},
    )
    if is_error(cp_res):
        degraded.append(f"Counterparty history unavailable for {cp_id}: {err_code(cp_res)}")
    else:
        registry[str(cp_res.get("evidence_id") or cp_key)] = cp_res


async def gather_regulatory(
    ctx: RunContext,
    state: InvestigationState,
    registry: dict[str, Any],
    degraded: list[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    if not ctx.allow_rag:
        return [], []
    clauses = list(state.regulatory_clauses)
    snippets = list(state.regulatory_snippets)
    reg_box = ctx.box("regulatory_analyst")
    plan = state.plan

    if (not clauses or state.refresh_regulations) and _can_spend_calls(ctx, 1):
        queries = plan.regulatory_queries if (plan and plan.regulatory_queries) else [DEFAULT_REG_QUERY]
        res = await reg_box.call(
            "compliance-kb",
            "search_regulations",
            {
                "query": " ; ".join(queries[:2]),
                "top_k": ctx.policy.retrieval.top_k_final,
                "decompose": True,
            },
        )
        if is_error(res):
            degraded.append(f"Regulatory retrieval unavailable: {err_code(res)}")
        else:
            known_ids = {c["clause_id"] for c in clauses if c.get("clause_id")}
            for clause in res.get("clauses", []):
                if isinstance(clause, dict) and clause.get("clause_id") and clause["clause_id"] not in known_ids:
                    clauses.append(clause)
                    known_ids.add(clause["clause_id"])
                    registry[clause["clause_id"]] = clause
                    snippets.append(f"[{clause['clause_id']}] {clause.get('title', '')}: {clause.get('text', '')}")

    requested_ids = plan.clause_ids if plan else []
    known_ids = {c["clause_id"] for c in clauses if c.get("clause_id")}
    for cid in requested_ids[:2]:
        if cid in known_ids or not _can_spend_calls(ctx, 1):
            continue
        exact = await reg_box.call("compliance-kb", "get_clause_by_id", {"clause_id": cid})
        if not is_error(exact) and exact.get("clause_id"):
            clauses.append(exact)
            known_ids.add(exact["clause_id"])
            registry[exact["clause_id"]] = exact
            snippets.append(f"[{exact['clause_id']}] {exact.get('title', '')}: {exact.get('text', '')}")
    return clauses, snippets


async def enrich_graph_evidence(
    ctx: RunContext,
    flow_box: GuardedToolbox,
    graph_result: dict[str, Any],
    paths: list[FundFlowPath],
    params: GraphParams,
    registry: dict[str, Any],
) -> None:
    """Invoke conservation & replan-comparison MCP tools when multi-hop paths exist and budget permits."""
    multi = [p for p in paths if p.hop_count >= 2]
    if multi and _can_spend_calls(ctx, 1):
        cons = await flow_box.call(
            "graph-engine",
            "compute_flow_conservation",
            {
                "paths": [p.model_dump(mode="json") for p in multi[:3]],
                "amount_tolerance": str(params.amount_tolerance),
            },
        )
        if not is_error(cons):
            registry[f"{graph_result['calc_id']}-CONS"] = cons
    if multi and ctx.last_graph_output and _can_spend_calls(ctx, 1):
        diff = await flow_box.call(
            "graph-engine", "compare_graph_runs", {"run_a": ctx.last_graph_output, "run_b": graph_result}
        )
        if not is_error(diff):
            registry[f"{graph_result['calc_id']}-DIFF"] = diff
    ctx.last_graph_output = graph_result


async def fetch_flow_evidence(
    state: InvestigationState,
    ctx: RunContext,
    flow_box: GuardedToolbox,
    registry: dict[str, Any],
    degraded: list[str],
) -> tuple[str, list[str], list[dict[str, Any]], list[FundFlowPath], dict[str, Any] | None]:
    """Fetch alert context (plus any planned account transaction expansions) and run bounded graph search."""
    alert = state.alert
    params = state.plan.graph_params if state.plan else GraphParams.policy_default()
    txs = list(state.transactions)
    root, network = alert.root_account, list(alert.network_accounts)
    if not txs:
        alert_ctx = await flow_box.call("bank-records", "get_alert_context", {"alert_id": alert.alert_id})
        if is_error(alert_ctx):
            degraded.append(f"Alert context unavailable: {err_code(alert_ctx)}")
            return root, network, [], [], None
        txs = list(alert_ctx.get("transactions", []))
        root = str(alert_ctx.get("root_account", root))
        network = list(alert_ctx.get("network_accounts", network))
        registry.update({t["tx_id"]: t for t in txs if t.get("tx_id")})

    seen_tx_ids = {t.get("tx_id") for t in txs if t.get("tx_id")}
    seen_accounts = {root, *network}
    extra_focus = [a for a in (state.plan.focus_accounts if state.plan else []) if a not in seen_accounts]
    for acc in extra_focus[:1]:
        if not _can_spend_calls(ctx, 2):
            break
        extra = await flow_box.call(
            "bank-records",
            "get_account_transactions",
            {"account_id": acc, "days_back": params.time_window_days},
        )
        if is_error(extra):
            degraded.append(f"Account transactions unavailable for {acc}: {err_code(extra)}")
            continue
        for t in extra.get("transactions", []):
            if isinstance(t, dict) and t.get("tx_id") and t["tx_id"] not in seen_tx_ids:
                txs.append(t)
                seen_tx_ids.add(t["tx_id"])
                registry[t["tx_id"]] = t

    graph_result = await flow_box.call(
        "graph-engine",
        "find_candidate_fund_flows",
        {"root_account": root, "transactions": graph_tx_payload(txs), **params.model_dump()},
    )
    if is_error(graph_result):
        degraded.append(f"Graph analysis unavailable: {err_code(graph_result)}")
        return root, network, txs, [], graph_result
    registry[graph_result["calc_id"]] = graph_result.get("graph_stats", {})
    paths = flow_paths_from_result(graph_result, limit=5)
    registry.update({p.path_id: p.model_dump(mode="json") for p in paths})
    return root, network, txs, paths, graph_result


def build_specialist_findings(
    ctx: RunContext, paths: list[FundFlowPath], profiles: list[dict[str, Any]], clauses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not ctx.parallel:
        return []
    multi = sum(1 for p in paths if p.hop_count >= 2)
    items = [
        SpecialistFinding(
            task_id="HO-FLOW",
            agent_name="flow_tracer",
            summary=f"Reconstructed {len(paths)} path(s) ({multi} multi-hop)",
            tool_calls=ctx.box("flow_tracer").calls,
            evidence_ids_added=[p.path_id for p in paths],
            recommended_replan={"expand_window": True} if not multi else None,
        ),
        SpecialistFinding(
            task_id="HO-BENIGN",
            agent_name="benign_investigator",
            summary=f"Verified {len(profiles)} KYC/registry record(s)",
            tool_calls=ctx.box("benign_investigator").calls,
            evidence_ids_added=[str(k.get("evidence_id", "")) for k in profiles if k.get("evidence_id")],
        ),
        SpecialistFinding(
            task_id="HO-REG",
            agent_name="regulatory_analyst",
            summary=f"Retrieved {len(clauses)} regulatory clause(s)",
            tool_calls=ctx.box("regulatory_analyst").calls,
            evidence_ids_added=[c["clause_id"] for c in clauses],
        ),
    ]
    return [f.model_dump(mode="json") for f in items]


async def gather_evidence_node(state: InvestigationState, ctx: RunContext) -> dict[str, Any]:
    registry = dict(state.evidence_registry)
    degraded = list(state.degraded_evidence)
    params = state.plan.graph_params if state.plan else GraphParams.policy_default()
    flow_box = ctx.box("flow_tracer")

    t0 = time.perf_counter()
    root, network, txs, paths, graph_result = await fetch_flow_evidence(state, ctx, flow_box, registry, degraded)
    ctx.timings["flow_ms"] = ctx.timings.get("flow_ms", 0.0) + (time.perf_counter() - t0) * 1000
    if graph_result is None:
        return {
            "degraded_evidence": sorted({*degraded, *all_security_notes(ctx)}),
            "current_node": "gather_evidence",
            "current_step": state.current_step + 1,
            **sync_budget(ctx),
        }

    t1 = time.perf_counter()
    if ctx.parallel:
        profiles, (clauses, snippets) = await asyncio.gather(
            gather_identity(ctx, state, root, network, paths, registry, degraded),
            gather_regulatory(ctx, state, registry, degraded),
        )
    else:
        profiles = await gather_identity(ctx, state, root, network, paths, registry, degraded)
        clauses, snippets = await gather_regulatory(ctx, state, registry, degraded)
    if not is_error(graph_result):
        await enrich_graph_evidence(ctx, flow_box, graph_result, paths, params, registry)
    ctx.timings["evidence_ms"] = ctx.timings.get("evidence_ms", 0.0) + (time.perf_counter() - t1) * 1000

    msgs, summary = trim_messages_with_summary(
        [*state.messages, {"role": "tool", "content": f"Gathered {len(paths)} paths, {len(profiles)} KYC records"}],
        state.rolling_summary,
        window_size=ctx.policy.memory.short_term_window_messages,
    )
    return {
        "transactions": txs,
        "fund_flow_paths": paths,
        "kyc_profiles": profiles,
        "regulatory_clauses": clauses,
        "regulatory_snippets": snippets,
        "evidence_registry": registry,
        "degraded_evidence": sorted({*degraded, *all_security_notes(ctx)}),
        "specialist_findings": build_specialist_findings(ctx, paths, profiles, clauses),
        "refresh_kyc": False,
        "refresh_regulations": False,
        "messages": msgs,
        "rolling_summary": summary,
        "current_node": "gather_evidence",
        "current_step": state.current_step + 1,
        **sync_budget(ctx),
    }
