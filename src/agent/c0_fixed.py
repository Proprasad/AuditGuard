"""
AuditGuard C0 — Fixed Deterministic Workflow Baseline
Executes a rigid 5-step pipeline with fixed parameters (7d, 3 hops, 0.10 tolerance),
zero autonomous planning, zero replanning, and root-only KYC lookup.
Used as the fair baseline in Experiment E1 under identical tools and budgets.
"""
from __future__ import annotations

from src.db.database import utc_now_iso
from src.mcp_servers.client import call_mcp_tool
from src.models import (
    Alert,
    DispositionDecision,
    DispositionWorksheet,
    FundFlowPath,
    Hypothesis,
    HypothesisLabel,
    InvestigationState,
)


async def run_fixed_pipeline(alert: Alert) -> InvestigationState:
    """C0 Fixed Workflow Baseline."""
    state = InvestigationState(alert=alert)
    calls = 0

    # Step 1: Load alert context
    alert_ctx = await call_mcp_tool("bank-records", "get_alert_context", {"alert_id": alert.alert_id})
    calls += 1
    transactions_raw = alert_ctx.get("transactions", [])
    root_account = alert_ctx.get("root_account", alert.root_account)

    # Step 2: Fixed 7-day, 3-hop, 10%-tolerance graph scan (NEVER replans!)
    graph_result = await call_mcp_tool(
        "graph-engine",
        "find_candidate_fund_flows",
        {
            "root_account": root_account,
            "transactions": [
                {
                    "tx_id": tx.get("tx_id", f"TX{i}"),
                    "sender": tx.get("sender_account", tx.get("sender", root_account)),
                    "receiver": tx.get("receiver_account", tx.get("receiver", "")),
                    "amount_inr": tx.get("amount_inr", 0),
                    "timestamp": tx.get("timestamp", utc_now_iso()),
                    "memo": tx.get("memo"),
                }
                for i, tx in enumerate(transactions_raw)
            ],
            "time_window_days": 7,
            "max_hops": 3,
            "amount_tolerance": 0.10,
        },
    )
    calls += 1

    # Step 3: Root KYC only (does NOT check commercial registry or counterparties!)
    kyc = await call_mcp_tool("bank-records", "get_kyc_profile", {"account_id": root_account})
    calls += 1

    # Step 4: Single static regulatory lookup
    reg = await call_mcp_tool(
        "compliance-kb",
        "search_regulations",
        {"query": "scatter gather red flags", "top_k": 3, "decompose": False},
    )
    calls += 1

    paths = [
        FundFlowPath(
            path_id=p.get("path_id", ""),
            nodes=p.get("nodes", []),
            edge_tx_ids=p.get("edge_tx_ids", []),
            total_amount=p.get("total_amount", 0.0),
            total_outflow_inr=p.get("total_outflow_inr", "0.00"),
            total_consolidated_inr=p.get("total_consolidated_inr", "0.00"),
            net_difference_inr=p.get("net_difference_inr", "0.00"),
            retention_pct=p.get("retention_pct", "0.00"),
            hop_count=p.get("hop_count", 0),
            time_span_days=p.get("time_span_days", 0.0),
            amount_leaked_pct=p.get("amount_leaked_pct", 0.0),
        )
        for p in graph_result.get("paths", [])[:3]
    ]

    citations = [c["clause_id"] for c in reg.get("clauses", [])] or ["REG-FIU-RF-014"]
    multi_hop = [p for p in paths if p.hop_count >= 2]

    # Rigid static rule: flags any 2+ hop path within 7 days as ESCALATE_STR (causing false positives on benign!)
    # and misses staggered/two-tier paths outside 7d/3hop!
    if multi_hop:
        disposition = DispositionDecision.ESCALATE_STR
        confidence = 0.65
        rationale = f"C0 Fixed Pipeline: {len(multi_hop)} multi-hop path(s) in fixed 7d/3-hop scan."
    else:
        disposition = DispositionDecision.REQUEST_INFO
        confidence = 0.40
        rationale = "C0 Fixed Pipeline: 0 multi-hop consolidation paths in fixed 7d/3-hop scan."

    draft_res = await call_mcp_tool(
        "case-actions",
        "draft_disposition_report",
        {
            "alert_id": alert.alert_id,
            "recommended_disposition": disposition.value,
            "recommendation_rationale": rationale,
            "confidence_score": confidence,
            "candidate_paths": [p.model_dump() for p in paths],
            "regulatory_citations": citations,
            "kyc_summaries": [f"{root_account}: risk={kyc.get('risk_category', 'unknown')}"],
        },
    )
    calls += 1

    worksheet = DispositionWorksheet(
        worksheet_id=draft_res.get("worksheet_id", f"DWS-C0-{alert.alert_id[-6:]}"),
        alert_id=alert.alert_id,
        investigator_agent="auditguard-c0-fixed",
        candidate_paths=paths,
        hypotheses=[
            Hypothesis(
                label=HypothesisLabel.SUSPICIOUS,
                explanation="C0 static scatter-gather detector output",
                confidence=confidence,
                regulatory_citations=citations,
            )
        ],
        regulatory_citations=citations,
        kyc_summaries=[f"{root_account}: risk={kyc.get('risk_category', 'unknown')}"],
        recommended_disposition=disposition,
        recommendation_rationale=rationale,
        confidence_score=confidence,
    )

    state.fund_flow_paths = paths
    state.kyc_profiles = [kyc]
    state.worksheet = worksheet
    state.tool_calls_used = calls
    state.current_node = "completed"
    state.is_complete = True
    return state
