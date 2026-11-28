"""
Phase 2 offline unit & integration tests (`<= 600` lines):
  * `test_llm_client_replay_and_backoff` (`record`, `replay`, `CassetteMissError`, 429 retry, transcripts)
  * 6-slot prompt loader & pure `Decimal` `calc` tool (`sum`, `diff`, `pct`, `compare`)
  * `c1_single` ReAct tool-calling loop happy path + `replan_graph` + LangGraph `human_gate` resume
  * Hard budget/turn caps (`max_cost_usd`, `max_tool_calls`, `max_turns`) -> forced `INSUFFICIENT_DATA` finish
  * RBAC denial & policy bounds (`POLICY_BOUNDS_EXCEEDED`) inside `AgentToolRuntime`
  * 1-round verifier/schema repair retry on bad `finish`
  * `c2_multi` Supervisor + parallel RBAC specialists (`asyncio.gather`) + supervisor-requested replan
  * Fair 3-way `c0_fixed` (`escalate_str`, `close_benign`, `request_info`) & `rule_engine` (`0` LLM calls)
"""

from __future__ import annotations

from decimal import Decimal
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from src.agent.c0_fixed import run_fixed_pipeline
from src.agent.c1_single import run_investigation
from src.agent.c2_multi import run_multi_agent
from src.agent.graph import resume_gate
from src.agent.loop import run_c1_agent_loop
from src.agent.planning import RunContext
from src.agent.prompts import load_c1_prompt_spec, render_c1_system_prompt
from src.agent.rule_engine import run_rule_engine
from src.agent.tooling import GuardedToolbox
from src.agent.tools import AgentToolRuntime, CalcInput, build_openai_tools, execute_decimal_calc
from src.config import get_policy
from src.guardrails.hooks import decode_llm_tool_content
from src.llm import CassetteMissError, LLMClient, compute_call_cost_usd
from src.mcp_servers import bank_records
from src.models import Alert, DispositionDecision, InvestigationState, RiskLevel
from tests.fakes import FakeLLM, make_text_turn, make_tool_turn

ALERT = Alert(
    alert_id="ALT-2026-0412",
    rule_name="SCATTER_GATHER_900K",
    root_account="ACC-IND-1042",
    total_amount_inr="900000.00",
    risk_level=RiskLevel.HIGH,
)


def _extract_tool_outputs(messages: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_name: dict[str, list[dict[str, Any]]] = {}
    for m in messages:
        if m.get("role") == "tool" and m.get("name"):
            by_name.setdefault(str(m["name"]), []).append(decode_llm_tool_content(str(m["content"])))
    return by_name


@pytest.mark.asyncio
async def test_llm_client_replay_and_backoff(tmp_path: Path) -> None:
    attempts = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, json={"error": "rate_limited"})
        tc_fn = {"name": "get_alert_context", "arguments": '{"alert_id": "ALT-2026-0412"}'}
        msg = {
            "role": "assistant",
            "content": "Fetching alert context.",
            "tool_calls": [{"id": "call_abc", "type": "function", "function": tc_fn}],
        }
        return httpx.Response(
            200,
            json={
                "model": "openai/gpt-5-mini",
                "choices": [{"finish_reason": "tool_calls", "message": msg}],
                "usage": {"prompt_tokens": 1000, "completion_tokens": 250, "total_tokens": 1250},
            },
        )

    cassette_file, runs_dir = tmp_path / "cassettes" / "smoke.jsonl", tmp_path / "runs"
    recorder = LLMClient(
        mode="record", cassette_path=cassette_file, run_id="rec_test", runs_dir=runs_dir,
        api_key="sk-or-test-key", backoff_base_s=0.001, transport=httpx.MockTransport(handler),
    )
    prompt = [{"role": "user", "content": "Investigate ALT-2026-0412"}]
    recorded = await recorder.chat(prompt, model="openai/gpt-5-mini", temperature="0.1", max_tokens=512)

    assert attempts == 2 and recorded.from_cassette is False
    assert len(recorded.tool_calls) == 1 and recorded.tool_calls[0].name == "get_alert_context"
    expected_cost = compute_call_cost_usd("openai/gpt-5-mini", 1000, 250)
    assert recorded.cost_usd == expected_cost and expected_cost > Decimal("0")
    assert cassette_file.exists() and recorder.transcript_path is not None and recorder.transcript_path.exists()

    def forbid_network(_: httpx.Request) -> httpx.Response:
        raise AssertionError("Replay mode must never touch network")

    replayer = LLMClient(
        mode="replay", cassette_path=cassette_file, run_id="rep_test", runs_dir=runs_dir,
        api_key="", transport=httpx.MockTransport(forbid_network),
    )
    replayed = await replayer.chat(prompt, model="openai/gpt-5-mini", temperature="0.1", max_tokens=512)
    assert replayed.from_cassette is True
    assert replayed.tool_calls == recorded.tool_calls
    assert replayed.cost_usd == recorded.cost_usd
    assert replayer.transcript_path is not None and replayer.transcript_path.exists()

    with pytest.raises(CassetteMissError):
        await replayer.chat([{"role": "user", "content": "Unseen prompt"}], model="openai/gpt-5-mini")


def test_six_slot_prompt_and_decimal_calc_tool() -> None:
    spec = load_c1_prompt_spec()
    assert spec.version == "2.1.0" and spec.agent == "c1_investigator"
    rendered = render_c1_system_prompt(get_policy(), lessons=["[L-1] IF delayed THEN widen window"])
    for marker in ("1. ROLE:", "2. CONTEXT:", "3. TASK:", "4. CONSTRAINTS:", "5. FORMAT:", "6. EXAMPLES:", "[L-1]"):
        assert marker in rendered

    s_out = execute_decimal_calc(CalcInput(op="sum", values=["300000.10", "300000.20", "299999.70"]))
    assert s_out["result_inr"] == "900000.00" and s_out["calc_id"].startswith("CALC-")
    d_out = execute_decimal_calc(CalcInput(op="diff", values=["900000.00", "828000.00"]))
    assert d_out["result_inr"] == "72000.00" and d_out["signed_diff_inr"] == "72000.00"
    p_out = execute_decimal_calc(CalcInput(op="pct", values=["72000.00", "900000.00"]))
    assert p_out["result_pct"] == "8.00"
    c_out = execute_decimal_calc(CalcInput(op="compare", values=["900000.00", "450000.00"]))
    assert c_out["relation"] == "gt" and c_out["abs_diff_inr"] == "450000.00"


@pytest.mark.asyncio
async def test_agent_loop_happy_path_with_calc_replan_and_gate_resume(tmp_path: Path) -> None:
    def finish_turn(messages: list[dict[str, Any]], _: Any) -> Any:
        outputs = _extract_tool_outputs(messages)
        p0 = outputs["replan_graph"][-1]["paths"][0]
        calc_out = outputs["calc"][-1]
        clause_id = outputs["search_regulations"][-1]["clauses"][0]["clause_id"]
        kyc_id = outputs["get_kyc_profile"][0]["evidence_id"]
        return make_tool_turn(
            (
                "finish",
                {
                    "recommended_disposition": "escalate_str",
                    "confidence_score": "0.88",
                    "recommendation_rationale": (
                        f"Multi-hop path {p0['path_id']} dispersed INR {p0['total_outflow_inr']} and consolidated "
                        f"INR {p0['total_consolidated_inr']} with fee skim INR {calc_out['result_inr']} "
                        f"({calc_out['calc_id']}) under {clause_id}."
                    ),
                    "suspicious_hypothesis": {
                        "explanation": f"Staggered consolidation on {p0['path_id']} from unregistered {kyc_id}.",
                        "confidence": "0.88",
                        "supporting_evidence": [p0["path_id"], calc_out["calc_id"]],
                        "evidence_ids": [p0["path_id"], kyc_id, calc_out["calc_id"]],
                        "regulatory_citations": [clause_id],
                    },
                    "benign_hypothesis": {
                        "explanation": f"Commercial settlement considered for {kyc_id} but uncorroborated.",
                        "confidence": "0.12",
                        "contradicting_evidence": [p0["path_id"]],
                        "evidence_ids": [kyc_id],
                        "regulatory_citations": [clause_id],
                    },
                    "missing_evidence": ["Out-of-bank beneficiary source-of-funds statements"],
                    "regulatory_citations": [clause_id],
                },
            )
        )

    fake = FakeLLM(
        [
            make_tool_turn(("get_alert_context", {"alert_id": "ALT-2026-0412"})),
            make_tool_turn(("find_candidate_fund_flows", {"root_account": "ACC-IND-1042"})),
            make_tool_turn(
                (
                    "replan_graph",
                    {
                        "time_window_days": 18,
                        "max_hops": 4,
                        "amount_tolerance": "0.15",
                        "reason": "7-day scan missed delayed downstream aggregation",
                    },
                ),
                ("get_kyc_profile", {"account_id": "ACC-IND-1042"}),
                ("check_commercial_registry", {"entity_name": "Account Holder", "account_id": "ACC-IND-1042"}),
                ("search_regulations", {"query": "scatter gather layering red flags", "top_k": 3}),
            ),
            lambda msgs, _: make_tool_turn(
                (
                    "calc",
                    {
                        "op": "diff",
                        "values": [
                            _extract_tool_outputs(msgs)["replan_graph"][-1]["paths"][0]["total_outflow_inr"],
                            _extract_tool_outputs(msgs)["replan_graph"][-1]["paths"][0]["total_consolidated_inr"],
                        ],
                        "label": "intermediary retention",
                    },
                )
            ),
            finish_turn,
        ],
        runs_dir=tmp_path / "runs",
        run_id="c1_happy",
    )

    state = await run_investigation(ALERT, thread_id="thr-loop-happy", llm_client=fake)
    assert state.worksheet is not None and state.worksheet.verification_status == "passed"
    assert state.worksheet.recommended_disposition == DispositionDecision.ESCALATE_STR
    assert state.replan_count == 1
    assert state.total_tokens_used > 0 and state.estimated_cost_usd > Decimal("0")
    assert len(state.calc_log) >= 2
    assert fake.transcript_path is not None and fake.transcript_path.exists()
    assert await resume_gate("thr-loop-happy", "c1_single", {"action": "reject", "reviewer": "rev1"}) is True


@pytest.mark.asyncio
async def test_agent_loop_budget_and_turn_caps_trigger_forced_finish() -> None:
    expensive_fake = FakeLLM(
        [make_tool_turn(("get_alert_context", {"alert_id": "ALT-2026-0412"}), cost_usd="0.020000")]
    )
    st_cost = await run_investigation(
        ALERT,
        llm_client=expensive_fake,
        budget_overrides={"max_cost_usd_per_case": Decimal("0.010000")},
    )
    assert st_cost.worksheet is not None
    assert st_cost.worksheet.recommended_disposition == DispositionDecision.REQUEST_INFO
    assert "INSUFFICIENT_DATA" in st_cost.worksheet.recommendation_rationale
    assert len(expensive_fake.calls) == 1

    greedy_fake = FakeLLM(
        [
            make_tool_turn(
                ("get_alert_context", {"alert_id": "ALT-2026-0412"}),
                ("get_kyc_profile", {"account_id": "ACC-IND-1042"}),
                ("search_regulations", {"query": "pmla", "top_k": 2}),
            ),
            make_text_turn("Still thinking without calling finish"),
            make_text_turn("Still thinking"),
        ]
    )
    capped_policy = get_policy().model_copy(
        update={"budgets": get_policy().budgets.model_copy(update={"max_tool_calls": 3})}
    )
    ctx = RunContext(
        mode="c1_single",
        policy=capped_policy,
        ledger=capped_policy.new_ledger(),
        boxes={},
        label="auditguard-c1",
        role="c1_investigator",
    )
    ctx.boxes["primary"] = GuardedToolbox("c1_single", ctx.ledger, "thr-cap")
    out = await run_c1_agent_loop(InvestigationState(thread_id="thr-cap", alert=ALERT), ctx, greedy_fake, max_turns=2)
    assert out["worksheet"].recommended_disposition == DispositionDecision.REQUEST_INFO
    assert out["tool_calls_used"] <= 3


@pytest.mark.asyncio
async def test_agent_loop_rbac_and_bounds_enforced() -> None:
    flow_box = GuardedToolbox("flow_tracer", get_policy().new_ledger(), "thr-rbac")
    flow_rt = AgentToolRuntime(role="flow_tracer", box=flow_box, alert=ALERT)
    forbidden_tools = (
        "get_kyc_profile",
        "search_regulations",
        "finish",
        "draft_disposition_report",
        "submit_case_disposition",
    )
    for forbidden in forbidden_tools:
        res = await flow_rt.execute(forbidden, {"account_id": "ACC-IND-1042"})
        assert res["status"] == "error" and res["error_code"] == "RBAC_DENIED"
    assert len(flow_box.tool_errors) == 5

    c1_rt = AgentToolRuntime(
        role="c1_single", box=GuardedToolbox("c1_single", get_policy().new_ledger(), "thr-bounds"), alert=ALERT
    )
    await c1_rt.execute("get_alert_context", {"alert_id": "ALT-2026-0412"})
    bad_replan = await c1_rt.execute(
        "replan_graph",
        {"time_window_days": 90, "max_hops": 12, "amount_tolerance": "0.10", "reason": "unbounded scan"},
    )
    assert bad_replan["error_code"] == "POLICY_BOUNDS_EXCEEDED" and c1_rt.replan_count == 0
    bad_flows = await c1_rt.execute("find_candidate_fund_flows", {"root_account": "ACC-IND-1042", "max_hops": 25})
    assert bad_flows["error_code"] == "POLICY_BOUNDS_EXCEEDED"

    flow_tool_names = {t["function"]["name"] for t in build_openai_tools("flow_tracer")}
    assert "get_kyc_profile" not in flow_tool_names and "finish" not in flow_tool_names
    assert "find_candidate_fund_flows" in flow_tool_names and "calc" in flow_tool_names


@pytest.mark.asyncio
async def test_agent_loop_repair_retry_recovers_from_verifier_rejection() -> None:
    def bad_finish(messages: list[dict[str, Any]], _: Any) -> Any:
        clause_id = _extract_tool_outputs(messages)["search_regulations"][-1]["clauses"][0]["clause_id"]
        return make_tool_turn(
            (
                "finish",
                {
                    "recommended_disposition": "escalate_str",
                    "confidence_score": "0.85",
                    "recommendation_rationale": "Customer is guilty and moved INR 777,777.00 via TXN-FAKE-999.",
                    "suspicious_hypothesis": {
                        "explanation": "Fabricated claim.",
                        "confidence": "0.85",
                        "evidence_ids": ["TXN-FAKE-999"],
                        "regulatory_citations": [clause_id],
                    },
                    "benign_hypothesis": {
                        "explanation": "Benign check.",
                        "confidence": "0.15",
                        "evidence_ids": ["TXN-FAKE-999"],
                        "regulatory_citations": [clause_id],
                    },
                    "missing_evidence": ["Beneficiary invoice"],
                    "regulatory_citations": [clause_id],
                },
            )
        )

    def repaired_finish(messages: list[dict[str, Any]], _: Any) -> Any:
        outputs = _extract_tool_outputs(messages)
        assert outputs["finish"][-1]["error_code"] == "VERIFICATION_FAILED"
        clause_id = outputs["search_regulations"][-1]["clauses"][0]["clause_id"]
        kyc_id = outputs["get_kyc_profile"][-1]["evidence_id"]
        tx_id = outputs["get_alert_context"][-1]["transactions"][0]["tx_id"]
        return make_tool_turn(
            (
                "finish",
                {
                    "recommended_disposition": "request_info",
                    "confidence_score": "0.55",
                    "recommendation_rationale": (
                        f"Outbound transfer {tx_id} from {kyc_id} warrants counterparty invoices under {clause_id}."
                    ),
                    "suspicious_hypothesis": {
                        "explanation": f"Rapid outbound transfer {tx_id} from high-risk account {kyc_id}.",
                        "confidence": "0.55",
                        "evidence_ids": [tx_id, kyc_id],
                        "regulatory_citations": [clause_id],
                    },
                    "benign_hypothesis": {
                        "explanation": f"Possible vendor settlement from {kyc_id} pending invoice review.",
                        "confidence": "0.45",
                        "evidence_ids": [kyc_id],
                        "regulatory_citations": [clause_id],
                    },
                    "missing_evidence": ["Counterparty tax invoices and bank statements"],
                    "regulatory_citations": [clause_id],
                },
            )
        )

    fake = FakeLLM(
        [
            make_tool_turn(
                ("get_alert_context", {"alert_id": "ALT-2026-0412"}),
                ("get_kyc_profile", {"account_id": "ACC-IND-1042"}),
                ("search_regulations", {"query": "pmla due diligence", "top_k": 2}),
            ),
            bad_finish,
            repaired_finish,
        ]
    )
    state = await run_investigation(ALERT, llm_client=fake)
    assert state.critique_retries_used == 1
    assert state.worksheet is not None and state.worksheet.verification_status == "passed"
    assert state.worksheet.recommended_disposition == DispositionDecision.REQUEST_INFO


@pytest.mark.asyncio
async def test_c2_multi_agent_parallel_specialists_and_replan() -> None:
    def _ho(tid: str, target: str, obj: str, b: int) -> dict[str, Any]:
        return {"task_id": tid, "target_agent": target, "objective": obj, "allowed_tool_budget": b}

    sup_plan_json = json.dumps(
        {
            "steps": ["Trace flows", "Verify KYC & regulations in parallel", "Draft & verify"],
            "handoffs": [
                _ho("HO-FLOW", "flow_tracer", "Scan flows", 4),
                _ho("HO-BENIGN", "benign_investigator", "Check KYC", 4),
                _ho("HO-REG", "regulatory_analyst", "Fetch clauses", 2),
                _ho("HO-CRITIC", "reporter_critic", "Draft worksheet", 2),
            ],
        }
    )
    sup_replan_json = json.dumps(
        {
            "request_replan": True,
            "time_window_days": 18,
            "max_hops": 4,
            "amount_tolerance": "0.15",
            "reason": "Expand window to capture delayed consolidation",
        }
    )

    def critic_finish(messages: list[dict[str, Any]], _: Any) -> Any:
        sys_txt = messages[0]["content"]
        ctx_blob = json.loads(sys_txt.split("Current Investigation Context:\n", 1)[1].rsplit("\nUse your", 1)[0])
        known = ctx_blob["known_evidence_ids"]
        path_id = next(x for x in known if x.startswith("PATH-"))
        kyc_id = next(x for x in known if x.startswith("KYC-"))
        clause_pfx = ("REG-", "SOP-", "PMLA-", "PMLR-", "RBI-", "FIU-", "FATF-", "CHIT-")
        reg_id = next(x for x in known if x.startswith(clause_pfx))
        return make_tool_turn(
            (
                "finish",
                {
                    "recommended_disposition": "escalate_str",
                    "confidence_score": "0.86",
                    "recommendation_rationale": (
                        f"Consolidated multi-hop path {path_id} from {kyc_id} matches typology under {reg_id}."
                    ),
                    "suspicious_hypothesis": {
                        "explanation": f"Multi-hop aggregation {path_id} without commercial registration.",
                        "confidence": "0.86",
                        "evidence_ids": [path_id, kyc_id],
                        "regulatory_citations": [reg_id],
                    },
                    "benign_hypothesis": {
                        "explanation": f"Evaluated commercial payroll/vendor hypothesis on {kyc_id}.",
                        "confidence": "0.14",
                        "evidence_ids": [kyc_id],
                        "regulatory_citations": [reg_id],
                    },
                    "missing_evidence": ["Destination account beneficial ownership declaration"],
                    "regulatory_citations": [reg_id],
                },
            )
        )

    c2_fake = FakeLLM(
        role_scripts={
            "C2 Investigation Supervisor": [make_text_turn(sup_plan_json), make_text_turn(sup_replan_json)],
            "Specialist `flow_tracer`": [
                make_tool_turn(("get_alert_context", {"alert_id": "ALT-2026-0412"})),
                make_tool_turn(("find_candidate_fund_flows", {"root_account": "ACC-IND-1042"})),
                make_text_turn("Initial 7d scan returned 0 multi-hop paths."),
                make_tool_turn(
                    (
                        "replan_graph",
                        {
                            "time_window_days": 18,
                            "max_hops": 4,
                            "amount_tolerance": "0.15",
                            "reason": "Supervisor requested wider window",
                        },
                    )
                ),
                make_text_turn("Replan uncovered multi-hop scatter-gather path."),
            ],
            "Specialist `benign_investigator`": [
                make_tool_turn(
                    ("get_kyc_profile", {"account_id": "ACC-IND-1042"}),
                    ("check_commercial_registry", {"entity_name": "Root", "account_id": "ACC-IND-1042"}),
                ),
                make_text_turn("Seed account is high-risk and commercially unregistered."),
            ],
            "Specialist `regulatory_analyst`": [
                make_tool_turn(("search_regulations", {"query": "scatter gather layering", "top_k": 3})),
                make_text_turn("Retrieved FIU-IND scatter-gather indicators."),
            ],
            "Specialist `reporter_critic`": [critic_finish],
        }
    )

    state = await run_multi_agent(ALERT, thread_id="thr-c2-llm", llm_client=c2_fake)
    assert state.worksheet is not None and state.worksheet.verification_status == "passed"
    assert state.worksheet.recommended_disposition == DispositionDecision.ESCALATE_STR
    assert state.replan_count == 1
    assert {f["agent_name"] for f in state.specialist_findings} == {
        "flow_tracer",
        "benign_investigator",
        "regulatory_analyst",
        "reporter_critic",
    }
    assert state.tool_calls_used <= get_policy().budgets.max_tool_calls
    assert state.total_tokens_used > 0 and state.estimated_cost_usd > Decimal("0")


def _kyc_entry(acc: str, name: str, risk: str, reg: bool) -> dict[str, Any]:
    return {
        "account_id": acc,
        "entity_name": name,
        "entity_type": "private_limited" if reg else "individual",
        "risk_category": risk,
        "declared_annual_income_inr": "50000000.00" if reg else "400000.00",
        "is_commercially_registered": reg,
        "registry_type": "GST" if reg else "NONE",
        "registry_id": f"27AABC{acc[-4:]}F1Z5" if reg else "",
        "kyc_notes": "Account record",
    }


@pytest.mark.asyncio
async def test_fair_c0_three_way_and_rule_engine_zero_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_ENABLED", "true")
    re_state = await run_rule_engine(ALERT, thread_id="thr-re-0")
    assert re_state.worksheet is not None
    assert re_state.total_tokens_used == 0 and re_state.estimated_cost_usd == Decimal("0")

    c0_esc = await run_fixed_pipeline(ALERT, thread_id="thr-c0-esc")
    assert c0_esc.worksheet is not None
    assert c0_esc.worksheet.recommended_disposition == DispositionDecision.ESCALATE_STR
    assert len(c0_esc.kyc_profiles) >= 2

    txs = [
        {
            "tx_id": f"TXN-B{i}",
            "sender_account": "ACC-MKT-1",
            "receiver_account": f"ACC-SEL-{i}",
            "amount_inr": "150000.00",
            "timestamp": f"2026-03-01T1{i}:00:00Z",
            "channel": "NEFT",
            "memo": f"Seller payout {i}",
        }
        for i in (1, 2)
    ]
    benign_overlay = {
        "case_id": "CASE-C0-BENIGN",
        "alert_id": "ALT-C0-BENIGN",
        "rule_name": "PAYOUT_BATCH",
        "root_account": "ACC-MKT-1",
        "network_accounts": ["ACC-SEL-1", "ACC-SEL-2"],
        "total_amount_inr": "300000.00",
        "triggered_at": "2026-03-01T14:00:00Z",
        "transactions": txs,
        "kyc_profiles": {
            "ACC-MKT-1": _kyc_entry("ACC-MKT-1", "Verified Marketplace Pvt Ltd", "low", True),
            "ACC-SEL-1": _kyc_entry("ACC-SEL-1", "Seller One", "low", True),
            "ACC-SEL-2": _kyc_entry("ACC-SEL-2", "Seller Two", "low", True),
        },
        "commercial_registry": {
            a: {"is_registered": True, "registry_type": "GST", "status": "ACTIVE"}
            for a in ("ACC-MKT-1", "ACC-SEL-1", "ACC-SEL-2")
        },
    }
    tok = bank_records.set_eval_case_overlay(benign_overlay)
    try:
        c0_ben = await run_fixed_pipeline(
            Alert(
                alert_id="ALT-C0-BENIGN",
                rule_name="PAYOUT_BATCH",
                root_account="ACC-MKT-1",
                network_accounts=["ACC-SEL-1", "ACC-SEL-2"],
                total_amount_inr="300000.00",
                risk_level=RiskLevel.LOW,
            ),
            thread_id="thr-c0-benign",
        )
    finally:
        bank_records.reset_eval_case_overlay(tok)
    assert c0_ben.worksheet is not None
    assert c0_ben.worksheet.recommended_disposition == DispositionDecision.CLOSE_BENIGN

    unreg_overlay = {
        **benign_overlay,
        "alert_id": "ALT-C0-REQ",
        "kyc_profiles": {
            "ACC-MKT-1": _kyc_entry("ACC-MKT-1", "Unregistered Individual", "high", False),
            "ACC-SEL-1": _kyc_entry("ACC-SEL-1", "Seller One", "low", True),
            "ACC-SEL-2": _kyc_entry("ACC-SEL-2", "Seller Two", "low", True),
        },
        "commercial_registry": {
            "ACC-MKT-1": {"is_registered": False, "status": "NOT_FOUND"},
            "ACC-SEL-1": {"is_registered": True, "registry_type": "GST", "status": "ACTIVE"},
            "ACC-SEL-2": {"is_registered": True, "registry_type": "GST", "status": "ACTIVE"},
        },
    }
    tok2 = bank_records.set_eval_case_overlay(unreg_overlay)
    try:
        c0_req = await run_fixed_pipeline(
            Alert(
                alert_id="ALT-C0-REQ",
                rule_name="PAYOUT_BATCH",
                root_account="ACC-MKT-1",
                network_accounts=["ACC-SEL-1", "ACC-SEL-2"],
                total_amount_inr="300000.00",
                risk_level=RiskLevel.HIGH,
            ),
            thread_id="thr-c0-req",
        )
    finally:
        bank_records.reset_eval_case_overlay(tok2)
    assert c0_req.worksheet is not None
    assert c0_req.worksheet.recommended_disposition == DispositionDecision.REQUEST_INFO
