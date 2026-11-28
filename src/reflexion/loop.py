"""
Dev-Split Reflexion Improvement Loop + Trace-Only LLM Reflector & Freeze Pipeline (`src/reflexion/loop.py`).

Enforces strict held-out & label discipline (`docs/AGENT_GUIDE.md` §4 Phase 5 E3):
  * Held-out and challenge cases are blocked (`PermissionError`).
  * Both the LLM reflector (`reflect_on_failure_trace`) and deterministic fallback (`generate_candidate_lesson`)
    operate STRICTLY on sanitized agent traces / observable transaction & KYC telemetry — NEVER reading
    `gold_disposition`, `expected_disposition`, `acceptable_dispositions`, `category`, or `family`.
  * Candidate lessons enter `LongTermMemoryStore` with `status="pending"` until human `review_lesson`
    and `freeze_playbook()` prior to held-out evaluation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
import json
from pathlib import Path
import re
from typing import Any, Optional

from pydantic import Field

from src.config import get_policy
from src.core.canonical import canonical_sha256, parse_utc_timestamp, to_money
from src.llm.client import LLMClientProtocol
from src.memory.store import LongTermMemoryStore, ReflexionLesson, memory_store
from src.models import StrictModel

FORBIDDEN_TRACE_LABEL_KEYS: frozenset[str] = frozenset(
    {
        "gold_disposition",
        "expected_disposition",
        "acceptable_dispositions",
        "expected_replan_required",
        "category",
        "category_id",
        "family",
        "family_group",
        "description",
        "severity_cost",
        "gold_evidence_ids",
        "gold_calc",
        "adversarial",
        "is_held_out",
        "split",
    }
)
_CASE_SPECIFIC_ID_RE = re.compile(r"\b(?:ACC|TXN|ALT|CASE|DWS|CUST)-[A-Za-z0-9\-_]+\b", re.IGNORECASE)
_DISPOSITIONS = r"(?:escalate_str|close_benign|request_info)"
# Phrasings that can only be written by someone who saw ground truth: a label field name, or a "should have been X"
# statement about the gold disposition.
_LABEL_LEAK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:alert |case )?(?:category|family(?:_group)?|gold|ground[- ]truth|expected[_ ]disposition)\b"),
    re.compile(rf"\binstead of\s+{_DISPOSITIONS}\b"),
    re.compile(rf"\b(?:should have been|correct (?:answer|disposition) (?:is|was))\s+{_DISPOSITIONS}\b"),
)


PROMPT_FACING_LESSON_FIELDS: tuple[str, ...] = ("trigger_precondition", "actionable_rule")


def label_leak_findings(
    lesson: ReflexionLesson,
    vocabulary: Sequence[str] = (),
    fields: Sequence[str] = ("trigger_precondition", "observed_failure", "actionable_rule"),
) -> list[str]:
    """
    Return reasons why `lesson` looks derived from ground-truth labels (empty list = clean).
    `vocabulary` holds dataset label names (case categories / families) supplied by the caller, so `src/` never
    has to import the data generators. `PROMPT_FACING_LESSON_FIELDS` are the only fields injected into prompts.
    """
    text = " ".join(str(getattr(lesson, f)) for f in fields).lower()
    found = [f"label phrasing: {m.group(0)!r}" for p in _LABEL_LEAK_PATTERNS for m in [p.search(text)] if m]
    for term in vocabulary:
        needle = term.lower()
        variants = {needle, needle.replace("_", " "), needle.replace(".", " ")}
        if any(re.search(rf"\b{re.escape(v)}\b", text) for v in variants):
            found.append(f"label vocabulary: {term!r}")
    return found


class CandidateLessonDraft(StrictModel):
    trigger_precondition: str = Field(min_length=10, max_length=1200)
    observed_failure: str = Field(min_length=10, max_length=1200)
    actionable_rule: str = Field(min_length=10, max_length=1200)


def _assert_dev_split_allowed(record: Mapping[str, Any]) -> None:
    if record.get("is_held_out") or str(record.get("split", "")) in ("held_out", "challenge"):
        raise PermissionError("Reflexion lesson generation is forbidden on held-out or challenge splits")


def sanitize_trace_for_reflector(
    trace_or_case: Mapping[str, Any], actual_disposition: str = "unknown"
) -> dict[str, Any]:
    """Strip all ground-truth labels/categories/splits before an LLM or heuristic reflector inspects a trace."""
    _assert_dev_split_allowed(trace_or_case)
    clean: dict[str, Any] = {}
    for key, val in trace_or_case.items():
        if key in FORBIDDEN_TRACE_LABEL_KEYS or key.startswith(("gold_", "expected_")):
            continue
        clean[key] = val
    clean["predicted_disposition"] = str(clean.get("predicted_disposition") or actual_disposition)
    leaked = [k for k in clean if k in FORBIDDEN_TRACE_LABEL_KEYS]
    if leaked:
        raise RuntimeError(f"Trace sanitization failed; forbidden keys remain: {leaked}")
    return clean


def _telemetry_signals(clean_record: Mapping[str, Any]) -> tuple[float, int, Decimal, bool]:
    txs = clean_record.get("transactions") or []
    root = str(clean_record.get("root_account", ""))
    timestamps = [parse_utc_timestamp(t["timestamp"]) for t in txs if isinstance(t, Mapping) and t.get("timestamp")]
    span_days = (max(timestamps) - min(timestamps)).total_seconds() / 86400.0 if len(timestamps) >= 2 else 0.0

    hop1 = {
        str(t.get("receiver_account"))
        for t in txs
        if isinstance(t, Mapping) and str(t.get("sender_account")) == root
    }
    hop2 = {
        str(t.get("receiver_account"))
        for t in txs
        if isinstance(t, Mapping) and str(t.get("sender_account")) in hop1 and str(t.get("receiver_account")) != root
    }
    hop3 = {
        str(t.get("receiver_account"))
        for t in txs
        if isinstance(t, Mapping)
        and str(t.get("sender_account")) in hop2
        and str(t.get("receiver_account")) not in hop1
    }
    depth = 3 if hop3 else (2 if hop2 else (1 if hop1 else 0))

    root_out = sum(
        (to_money(t["amount_inr"]) for t in txs if isinstance(t, Mapping) and str(t.get("sender_account")) == root),
        Decimal("0.00"),
    )
    inbound_by_acc: dict[str, Decimal] = {}
    for t in txs:
        if not isinstance(t, Mapping):
            continue
        sender, receiver = str(t.get("sender_account")), str(t.get("receiver_account"))
        if sender != root and receiver != root:
            inbound_by_acc[receiver] = inbound_by_acc.get(receiver, Decimal("0.00")) + to_money(t["amount_inr"])
    max_consol = max(inbound_by_acc.values(), default=Decimal("0.00"))
    skim_ratio = (root_out - max_consol) / root_out if root_out > 0 and max_consol > 0 else Decimal("0")

    kyc_map = clean_record.get("kyc_profiles") or {}
    if isinstance(kyc_map, Mapping):
        root_kyc = kyc_map.get(root) or {}
    elif isinstance(kyc_map, list) and kyc_map:
        root_kyc = kyc_map[0] if isinstance(kyc_map[0], Mapping) else {}
    else:
        root_kyc = {}
    registered = bool(root_kyc.get("is_commercially_registered"))
    return span_days, depth, skim_ratio, registered


def generate_candidate_lesson(case: Mapping[str, Any], actual_disposition: str) -> ReflexionLesson:
    """Deterministic trace-only candidate lesson generator (reads ZERO ground-truth label fields)."""
    clean = sanitize_trace_for_reflector(case, actual_disposition)
    gb = get_policy().graph_bounds
    span_days, depth, skim_ratio, registered = _telemetry_signals(clean)

    if span_days > gb.time_window_days.default:
        precondition = (
            f"Outbound scatter legs present within {gb.time_window_days.default} days "
            "with downstream activity extending beyond the initial lookahead window"
        )
        failure = (
            f"Agent emitted {actual_disposition} after scanning only the default "
            f"{gb.time_window_days.default}-day window"
        )
        rule = (
            f"Expand time_window_days up to {gb.time_window_days.max} days via replan_graph "
            "before concluding no consolidation exists."
        )
    elif depth > gb.max_hops.default:
        precondition = "Intermediaries forward funds across secondary tier accounts beyond default hop bound"
        failure = f"Agent emitted {actual_disposition} while capped at default max_hops={gb.max_hops.default}"
        rule = f"Increase max_hops up to {gb.max_hops.max} when intermediaries forward to secondary accounts."
    elif skim_ratio > gb.amount_tolerance.default:
        precondition = "Consolidated inflow is lower than distributed outflow due to intermediary fee retention"
        failure = (
            f"Agent emitted {actual_disposition} under tight default "
            f"amount_tolerance={gb.amount_tolerance.default}"
        )
        rule = (
            f"Widen amount_tolerance within [{gb.amount_tolerance.default}..{gb.amount_tolerance.max}] "
            "and compute exact Decimal retained fee percentage with calc."
        )
    elif registered:
        precondition = "Scatter-gather structure involving an account claiming commercial registration"
        failure = f"Agent emitted {actual_disposition} without cross-checking registry status and counterparty history"
        rule = "Verify check_commercial_registry and get_counterparty_history before finalizing disposition."
    else:
        precondition = "Outbound dispersal legs lack verified consolidation or corroborated commercial history"
        failure = f"Agent emitted {actual_disposition} without exhausting bounded graph replanning"
        rule = "Reconfigure time_window_days and max_hops within policy bounds and inspect counterparty history."

    lid = f"LES-{canonical_sha256({'precondition': precondition, 'rule': rule})[:6].upper()}"
    return ReflexionLesson(
        lesson_id=lid,
        trigger_precondition=precondition,
        observed_failure=failure,
        actionable_rule=rule,
    )


def _extract_json_obj(raw: str) -> dict[str, Any]:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=re.IGNORECASE | re.DOTALL).strip()
    m = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    parsed = json.loads(m.group(0) if m else cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("Reflector LLM did not return a JSON object")
    return parsed


def _scrub_case_ids(text: str) -> str:
    return re.sub(r"  +", " ", _CASE_SPECIFIC_ID_RE.sub("the target account", text)).strip()


async def reflect_on_failure_trace(
    trace: Mapping[str, Any],
    llm_client: LLMClientProtocol,
    *,
    actual_disposition: str = "unknown",
    model: Optional[str] = None,
) -> ReflexionLesson:
    """
    Invoke an LLM reflector on a SANITIZED dev-split investigation trace (never ground-truth labels)
    to author a generalizable `ReflexionLesson` (`status='pending'`).
    """
    clean = sanitize_trace_for_reflector(trace, actual_disposition)
    span_days, depth, skim_ratio, registered = _telemetry_signals(clean)
    policy = get_policy()
    gb = policy.graph_bounds
    chosen_model = model or policy.model_for("c1_investigator").model_id

    trace_digest = {
        "predicted_disposition": clean["predicted_disposition"],
        "replan_count": int(clean.get("replan_count", 0)),
        "tool_calls_used": int(clean.get("tool_calls", 0)),
        "observable_tx_span_days": round(span_days, 2),
        "observable_hop_depth": depth,
        "observable_fee_skim_ratio": str(round(float(skim_ratio), 4)),
        "root_kyc_registered_flag": registered,
        "degraded_evidence": list(clean.get("degraded_evidence") or [])[:5],
        "verification_discrepancies": list(clean.get("verification_discrepancies") or [])[:5],
        "policy_bounds": {
            "time_window_days": [gb.time_window_days.default, gb.time_window_days.max],
            "max_hops": [gb.max_hops.default, gb.max_hops.max],
            "amount_tolerance": [str(gb.amount_tolerance.default), str(gb.amount_tolerance.max)],
        },
    }
    sys_msg = (
        "You are an AML Investigation Process Reflector.\n"
        "Given ONLY the sanitized execution trace below (no ground-truth labels are provided), diagnose "
        "why the investigation trace may have been incomplete or miscalibrated, and write ONE generalizable "
        "procedural lesson within policy bounds (`time_window_days`, `max_hops`, `amount_tolerance`, "
        "`check_commercial_registry`, `get_counterparty_history`, `calc`).\n"
        "NEVER mention specific account/transaction/case IDs.\n"
        'Return JSON ONLY: {"trigger_precondition": "...", "observed_failure": "...", "actionable_rule": "..."}'
    )
    resp = await llm_client.chat(
        [
            {"role": "system", "content": sys_msg},
            {"role": "user", "content": json.dumps(trace_digest, indent=2)},
        ],
        model=chosen_model,
        temperature=policy.reflector.temperature,
        max_tokens=policy.reflector.max_tokens,
        response_format={"type": "json_object"},
    )
    draft = CandidateLessonDraft.model_validate(_extract_json_obj(resp.text))
    pre = _scrub_case_ids(draft.trigger_precondition)
    fail = _scrub_case_ids(draft.observed_failure)
    rule = _scrub_case_ids(draft.actionable_rule)
    lid = f"LES-{canonical_sha256({'precondition': pre, 'rule': rule})[:6].upper()}"
    return ReflexionLesson(
        lesson_id=lid,
        trigger_precondition=pre,
        observed_failure=fail,
        actionable_rule=rule,
    )


async def run_dev_reflexion_llm(
    eval_results: Sequence[Mapping[str, Any]],
    traces_by_id: Mapping[str, Mapping[str, Any]],
    llm_client: LLMClientProtocol,
    *,
    store: LongTermMemoryStore = memory_store,
    max_lessons: int = 5,
) -> list[ReflexionLesson]:
    """Run the async LLM reflector strictly over dev-split failures (skipping held-out/challenge)."""
    generated: list[ReflexionLesson] = []
    seen_ids = {les.lesson_id for les in store.list_all_lessons()}
    for res in eval_results:
        if len(generated) >= max_lessons or res.get("correct"):
            continue
        cid = str(res.get("case_id", ""))
        trace = traces_by_id.get(cid)
        if not trace or trace.get("is_held_out", False) or str(trace.get("split", "dev")) in ("held_out", "challenge"):
            continue
        lesson = await reflect_on_failure_trace(
            trace, llm_client, actual_disposition=str(res.get("actual", "unknown"))
        )
        if lesson.lesson_id not in seen_ids and store.add_lesson(lesson):
            seen_ids.add(lesson.lesson_id)
            generated.append(lesson)
    return generated


def run_dev_reflexion(
    eval_results: list[dict[str, Any]],
    cases_by_id: dict[str, dict[str, Any]],
    store: LongTermMemoryStore = memory_store,
) -> list[ReflexionLesson]:
    """Synchronous dev-only Reflexion pass (non-dev cases are strictly skipped)."""
    generated: list[ReflexionLesson] = []
    seen_ids = {les.lesson_id for les in store.list_all_lessons()}
    for res in eval_results:
        if res.get("correct"):
            continue
        case = cases_by_id.get(res.get("case_id", ""))
        if not case or case.get("is_held_out", True) or str(case.get("split", "")) in ("held_out", "challenge"):
            continue
        lesson = generate_candidate_lesson(case, str(res.get("actual", "unknown")))
        if lesson.lesson_id not in seen_ids and store.add_lesson(lesson):
            seen_ids.add(lesson.lesson_id)
            generated.append(lesson)
    return generated


def export_playbook(path: str = "config/reflexion_playbook.json", store: LongTermMemoryStore = memory_store) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "frozen": store.is_playbook_frozen(),
        "lessons": [lesson.model_dump() for lesson in store.list_all_lessons()],
    }
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
