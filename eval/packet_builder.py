"""
Phase 4 Stratified 60-Worksheet Packet & Empty Annotator CSV Builder (`eval/packet_builder.py`).

Allocation (60 total = 20 dev + 40 held-out across 4 modes × 5 top-level families):
  * `c0_fixed`    : 5 dev (1/family) + 10 held-out (2/family) = 15
  * `rule_engine` : 5 dev (1/family) + 10 held-out (2/family) = 15
  * `c1_single`   : 5 dev (1/family) + 10 held-out (2/family) = 15 (genuine OpenRouter LLM runs)
  * `c2_multi`    : 5 dev (1/family) + 10 held-out (2/family) = 15 (genuine OpenRouter LLM runs)

Outputs:
  * `eval/human_labels/worksheets_packet_blinded.jsonl` (blinded worksheets + redacted evidence)
  * `eval/human_labels/worksheets_to_score_annotator_1.csv` (60 IDs, randomized order seed=4201, empty scores)
  * `eval/human_labels/worksheets_to_score_annotator_2.csv` (60 IDs, randomized order seed=4202, empty scores)
  * `eval/calibration_manifest/packet_manifest.json` (coordinator-only mapping outside `eval/human_labels/`)
"""

from __future__ import annotations

import asyncio
from collections import Counter
import csv
import json
import os
from pathlib import Path
import random
from typing import Any

from eval.calibration_stats import EXPECTED_CSV_COLUMNS
from eval.judge import compute_companions
from eval.judge_prompts import blind_worksheet_for_judge
from eval.run_eval import assert_isolated_eval_db, extract_gold_record, load_cases, prepare_isolated_eval_db
from src.agent.c0_fixed import run_fixed_pipeline
from src.agent.c1_single import run_investigation
from src.agent.c2_multi import run_multi_agent
from src.agent.prompts import load_c1_prompt_spec
from src.agent.rule_engine import run_rule_engine
from src.config import get_policy
from src.guardrails.guardrails import mask_pii
from src.llm.client import LLMClient, LLMClientError, LLMClientProtocol, _norm_temperature
from src.llm.replay import canonical_request_envelope, compute_cassette_key
from src.llm.schemas import ChatResponse
from src.mcp_servers import bank_records
from src.models import Alert, InvestigationState, RiskLevel

FAMILIES: tuple[str, ...] = (
    "ambiguous",
    "benign_lookalike",
    "incomplete_data",
    "layering",
    "layering_benign_cover",
)
MODES: tuple[str, ...] = ("c0_fixed", "rule_engine", "c1_single", "c2_multi")
CASSETTE_PATH = Path("eval/cassettes/phase4_packet_agents.jsonl")
LABELS_DIR = Path("eval/human_labels")
MANIFEST_PATH = Path("eval/calibration_manifest/packet_manifest.json")


def _select_stratified_cases(
    cases: list[dict[str, Any]], per_family: int, mode_idx: int, seed: int = 42
) -> list[dict[str, Any]]:
    """Deterministic stratified selection covering all 5 families without inspecting held-out outcomes."""
    rng = random.Random(seed + mode_idx * 97)
    by_fam: dict[str, list[dict[str, Any]]] = {f: [] for f in FAMILIES}
    for c in sorted(cases, key=lambda x: str(x["case_id"])):
        fg = str(c.get("family_group", ""))
        if fg in by_fam:
            by_fam[fg].append(c)

    chosen: list[dict[str, Any]] = []
    for fam in FAMILIES:
        pool = list(by_fam[fam])
        if len(pool) < per_family:
            raise RuntimeError(f"Insufficient cases in family {fam}: need {per_family}, found {len(pool)}")
        # Prefer diverse difficulty / held-out-only coverage when selecting 2 cases
        hard_or_med = [c for c in pool if c.get("difficulty") in ("hard", "medium")]
        working = hard_or_med if len(hard_or_med) >= per_family else pool
        rng.shuffle(working)
        offset = (mode_idx * per_family) % len(working)
        rotated = working[offset:] + working[:offset]
        if per_family == 2:
            ho_only = [c for c in rotated if c.get("held_out_only_variant")]
            base_v = [c for c in rotated if not c.get("held_out_only_variant")]
            if ho_only and base_v:
                chosen.extend([base_v[0], ho_only[0]])
                continue
        chosen.extend(rotated[:per_family])
    return chosen


def _redacted_evidence_summary(redacted_case: dict[str, Any], state: InvestigationState) -> dict[str, Any]:
    txs = [
        {
            "tx_id": t.get("tx_id"),
            "sender": t.get("sender_account"),
            "receiver": t.get("receiver_account"),
            "amount_inr": t.get("amount_inr"),
            "timestamp": t.get("timestamp"),
            "memo": mask_pii(str(t.get("memo", "")))[0][:120],
        }
        for t in list(redacted_case.get("transactions") or [])[:15]
    ]
    return {
        "alert_amount_inr": str(redacted_case["total_amount_inr"]),
        "root_account": str(redacted_case["root_account"]),
        "transactions_sample": txs,
        "reconstructed_paths": [p.model_dump(mode="json") for p in state.fund_flow_paths[:4]],
        "kyc_And_registry_checked": [
            {
                "account_id": k.get("account_id"),
                "evidence_id": k.get("evidence_id"),
                "entity_type": k.get("entity_type"),
                "risk_category": k.get("risk_category"),
                "declared_annual_income_inr": k.get("declared_annual_income_inr"),
                "is_commercially_registered": k.get("is_commercially_registered"),
                "registry_check": k.get("registry_check"),
            }
            for k in state.kyc_profiles[:5]
        ],
        "retrieved_regulatory_clauses": [
            {"clause_id": c.get("clause_id"), "category": c.get("category"), "title": c.get("title")}
            for c in state.regulatory_clauses[:5]
        ],
        "calc_log": list(state.calc_log[:6]),
    }


class _ResumeRecordClient:
    """Serve already-recorded genuine cassette hits first; record live on OpenRouter only on miss."""

    def __init__(self, inner: LLMClient) -> None:
        self._inner = inner

    @property
    def transcript_path(self) -> Path | None:
        return self._inner.transcript_path

    async def chat(self, messages: list[dict[str, Any]], **kwargs: Any) -> ChatResponse:
        spec = get_policy().model_for("c1_investigator")
        model = kwargs.get("model") or spec.model_id
        temp = _norm_temperature(kwargs.get("temperature", spec.temperature))
        max_tok = kwargs.get("max_tokens") if kwargs.get("max_tokens") is not None else spec.max_tokens
        env = canonical_request_envelope(
            model=model,
            messages=messages,
            tools=kwargs.get("tools"),
            temperature=temp,
            max_tokens=max_tok,
            response_format=kwargs.get("response_format"),
            seed=kwargs.get("seed"),
        )
        key = compute_cassette_key(env)
        st = self._inner.store
        with st._lock:
            has_unconsumed = st._cursors.get(key, 0) < len(st._index.get(key, ()))
        if has_unconsumed:
            hit = await st.lookup(key)
            await st.write_transcript(key, env, hit)
            return hit
        return await self._inner.chat(messages, **kwargs)


async def _execute_slot(
    raw_case: dict[str, Any],
    mode: str,
    run_id: str,
    effective_llm_mode: str,
    shared_client: LLMClientProtocol,
    sem: asyncio.Semaphore,
) -> dict[str, Any]:
    assert_isolated_eval_db()
    gold = extract_gold_record(raw_case)
    redacted = bank_records.redact_case_for_agent(raw_case)
    alert = Alert(
        alert_id=redacted["alert_id"],
        rule_name=str(redacted.get("rule_name", "SCATTER_GATHER")),
        root_account=redacted["root_account"],
        network_accounts=redacted["network_accounts"],
        total_amount_inr=redacted["total_amount_inr"],
        risk_level=RiskLevel.HIGH,
    )
    policy = get_policy()
    prompt_ver = load_c1_prompt_spec().version

    async with sem:
        tok = bank_records.set_eval_case_overlay(redacted)
        try:
            if mode == "c0_fixed":
                st = await run_fixed_pipeline(alert)
                model_used = "deterministic/c0_fixed"
                tx_path = None
            elif mode == "rule_engine":
                st = await run_rule_engine(alert)
                model_used = "deterministic/rule_engine"
                tx_path = None
            else:
                try:
                    if mode == "c1_single":
                        st = await run_investigation(
                            alert, llm_client=shared_client, llm_mode=effective_llm_mode, run_id=run_id
                        )
                        model_used = policy.model_for("c1_investigator").model_id
                    else:
                        st = await run_multi_agent(
                            alert, llm_client=shared_client, llm_mode=effective_llm_mode, run_id=run_id
                        )
                        model_used = policy.model_for("c2_supervisor").model_id
                except LLMClientError as exc:
                    return {
                        "blocked": True,
                        "case_id": str(raw_case["case_id"]),
                        "mode": mode,
                        "split": str(raw_case["split"]),
                        "family_group": str(raw_case["family_group"]),
                        "reason": str(exc),
                    }
                tx_path = str(shared_client.transcript_path)
        finally:
            bank_records.reset_eval_case_overlay(tok)

    if st.worksheet is None:
        raise RuntimeError(f"Mode {mode} produced no worksheet on {raw_case['case_id']}")
    ws_dict = st.worksheet.model_dump(mode="json")
    companions = compute_companions(ws_dict, st.evidence_registry, st.calc_log)
    actual_disp = st.worksheet.recommended_disposition.value
    return {
        "blocked": False,
        "case_id": str(raw_case["case_id"]),
        "alert_id": str(raw_case["alert_id"]),
        "original_worksheet_id": st.worksheet.worksheet_id,
        "mode": mode,
        "model_id": model_used,
        "prompt_version": prompt_ver if mode in ("c1_single", "c2_multi") else "deterministic",
        "split": str(raw_case["split"]),
        "family": str(raw_case["family"]),
        "family_group": str(raw_case["family_group"]),
        "difficulty": str(raw_case.get("difficulty", "medium")),
        "gold_disposition": gold["gold_disposition"],
        "acceptable_dispositions": gold["acceptable_dispositions"],
        "actual_disposition": actual_disp,
        "is_correct": actual_disp in set(gold["acceptable_dispositions"]),
        "tokens_used": st.total_tokens_used,
        "cost_usd": str(st.estimated_cost_usd),
        "tool_calls_used": st.tool_calls_used,
        "replan_count": st.replan_count,
        "source_run_id": run_id,
        "transcript_path": tx_path,
        "blinded_worksheet": blind_worksheet_for_judge(ws_dict),
        "evidence_summary": _redacted_evidence_summary(redacted, st),
        "deterministic_companions": companions.model_dump(mode="json"),
    }


def _population_weights(cases: list[dict[str, Any]]) -> dict[str, float]:
    counts = Counter(str(c["family_group"]) for c in cases)
    total = max(1, len(cases))
    return {fam: round(counts.get(fam, 0) / total, 6) for fam in FAMILIES}


def _write_empty_annotator_csv(path: Path, wids: list[str], seed: int) -> None:
    shuffled = list(wids)
    random.Random(seed).shuffle(shuffled)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(EXPECTED_CSV_COLUMNS))
        writer.writeheader()
        for wid in shuffled:
            writer.writerow({col: (wid if col == "worksheet_id" else "") for col in EXPECTED_CSV_COLUMNS})


async def build_phase4_packet(*, llm_mode: str = "record", run_id: str = "phase4_packet_v1") -> dict[str, Any]:
    os.environ.pop("SQLITE_DB_PATH", None)
    prepare_isolated_eval_db()
    dev_cases = load_cases("v2_dev")
    ho_cases = load_cases("v2_held_out")

    jobs: list[tuple[dict[str, Any], str]] = []
    for m_idx, mode in enumerate(MODES):
        for c in _select_stratified_cases(dev_cases, per_family=1, mode_idx=m_idx, seed=42):
            jobs.append((c, mode))
        for c in _select_stratified_cases(ho_cases, per_family=2, mode_idx=m_idx, seed=42):
            jobs.append((c, mode))

    effective_llm_mode = "replay" if llm_mode == "replay" else "record"
    raw_client = LLMClient(
        mode=effective_llm_mode,  # type: ignore[arg-type]
        cassette_path=CASSETTE_PATH,
        run_id=run_id,
        timeout_s=90.0,
        max_retries=4,
    )
    shared_client: LLMClientProtocol = (
        _ResumeRecordClient(raw_client) if effective_llm_mode == "record" else raw_client
    )
    sem = asyncio.Semaphore(3)
    results = await asyncio.gather(
        *(_execute_slot(c, m, run_id, effective_llm_mode, shared_client, sem) for c, m in jobs)
    )
    blocked = [r for r in results if r.get("blocked")]
    completed = [r for r in results if not r.get("blocked")]

    # Shuffle deterministically BEFORE assigning WS-CAL-001..060 so ID numbers leak zero metadata!
    rng = random.Random(42)
    rng.shuffle(completed)

    LABELS_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    pkt_path = LABELS_DIR / "worksheets_packet_blinded.jsonl"

    manifest_items: dict[str, dict[str, Any]] = {}
    wids: list[str] = []
    with pkt_path.open("w", encoding="utf-8") as fh:
        for idx, item in enumerate(completed, start=1):
            wid = f"WS-CAL-{idx:03d}"
            wids.append(wid)
            blinded_entry = {
                "worksheet_id": wid,
                "worksheet": item["blinded_worksheet"],
                "evidence_summary": item["evidence_summary"],
                "deterministic_companions": item["deterministic_companions"],
            }
            fh.write(json.dumps(blinded_entry, sort_keys=True) + "\n")
            manifest_items[wid] = {
                k: v
                for k, v in item.items()
                if k not in ("blinded_worksheet", "evidence_summary", "blocked")
            }

    _write_empty_annotator_csv(LABELS_DIR / "worksheets_to_score_annotator_1.csv", wids, seed=4201)
    _write_empty_annotator_csv(LABELS_DIR / "worksheets_to_score_annotator_2.csv", wids, seed=4202)

    by_mode_correct = {
        m: {
            "total": sum(1 for v in manifest_items.values() if v["mode"] == m),
            "dev": sum(1 for v in manifest_items.values() if v["mode"] == m and v["split"] == "dev"),
            "held_out": sum(1 for v in manifest_items.values() if v["mode"] == m and v["split"] == "held_out"),
            "correct": sum(1 for v in manifest_items.values() if v["mode"] == m and v["is_correct"]),
            "incorrect": sum(1 for v in manifest_items.values() if v["mode"] == m and not v["is_correct"]),
            "tokens_used": sum(int(v["tokens_used"]) for v in manifest_items.values() if v["mode"] == m),
            "cost_usd": f"{sum(float(v['cost_usd']) for v in manifest_items.values() if v['mode'] == m):.6f}",
        }
        for m in MODES
    }
    manifest_doc = {
        "packet_version": "1.0.0",
        "seed": 42,
        "rubric_frozen": False,
        "total_worksheets": len(wids),
        "blocked_slots": blocked,
        "mode_summary": by_mode_correct,
        "sampling_design": {
            "type": "balanced_stratified_mode_by_family",
            "note": (
                "Intentionally stratified (1 dev + 2 held_out per family x mode = 20 dev + 40 held_out). "
                "Calibration reports both unweighted sample agreement and population-weighted agreement."
            ),
            "sample_family_weights": {f: 0.20 for f in FAMILIES},
            "population_family_weights": {
                "dev": _population_weights(dev_cases),
                "held_out": _population_weights(ho_cases),
            },
        },
        "worksheets": manifest_items,
    }
    MANIFEST_PATH.write_text(json.dumps(manifest_doc, indent=2, sort_keys=True), encoding="utf-8")
    return {"total": len(wids), "blocked": len(blocked), "mode_summary": by_mode_correct}


if __name__ == "__main__":
    out = asyncio.run(build_phase4_packet())
    print(json.dumps(out, indent=2))
