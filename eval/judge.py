"""
Phase 4 — Calibrated Cross-Family LLM Judge (`eval/judge.py`).

Features:
  * `cohens_kappa` (plain nominal/binary) & `linear_weighted_kappa` (1–5 ordinal scales)
  * Strict canonical model-lineage family taxonomy (`infer_model_family` & `validate_cross_family_judge`)
    that inspects underlying model family rather than trusting provider prefix strings
  * Gemini cross-family judge (`temperature=0`, JSON-validated `JudgeScoreOutput` & `PairwiseJudgeOutput`)
  * Blindness to agent mode & model identity (`blind_worksheet_for_judge`)
  * Randomized pairwise presentation ordering (`score_pairwise`) & position-swap bias probe (`evaluate_position_swap`)
  * PII/secret-scrubbed raw request/response logging (`runs/<run_id>/judge_raw_responses.jsonl`)
    paired with deterministic companions (`numbers_match_calc`, `citations_exist`)
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import re
from typing import Any, Literal, Optional

from pydantic import Field

from eval.judge_prompts import (
    blind_worksheet_for_judge,
    build_pairwise_judge_messages,
    build_single_judge_messages,
)
from src.config import get_policy
from src.core.canonical import dumps_json
from src.core.verifier import verify_worksheet
from src.guardrails.guardrails import mask_pii
from src.llm.client import LLMClient, LLMClientProtocol
from src.models import StrictModel

ORDINAL_CRITERIA: tuple[str, ...] = ("G1", "G3", "G4", "G5", "G7")
BINARY_CRITERIA: tuple[str, ...] = ("G2", "G6")
ALL_CRITERIA: tuple[str, ...] = ("G1", "G2", "G3", "G4", "G5", "G6", "G7")

# Canonical model-lineage rules matched on the normalized model basename (independent of routing provider prefix!)
_LINEAGE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_gpt", re.compile(r"(?:^|/)(?:gpt-|o1\b|o3\b|o4\b|chatgpt-)", re.IGNORECASE)),
    ("google_gemini", re.compile(r"(?:^|/)(?:gemini-|gemma-)", re.IGNORECASE)),
    ("anthropic_claude", re.compile(r"(?:^|/)(?:claude-)", re.IGNORECASE)),
    ("meta_llama", re.compile(r"(?:^|/)(?:llama-|meta-llama)", re.IGNORECASE)),
    ("alibaba_qwen", re.compile(r"(?:^|/)(?:qwen)", re.IGNORECASE)),
    ("deepseek", re.compile(r"(?:^|/)(?:deepseek)", re.IGNORECASE)),
    ("zhipu_glm", re.compile(r"(?:^|/)(?:glm-)", re.IGNORECASE)),
    ("amazon_nova", re.compile(r"(?:^|/)(?:nova-)", re.IGNORECASE)),
)
_SECRET_RE = re.compile(r"\b(?:sk-[A-Za-z0-9\-_]{12,}|Bearer\s+[A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE)


class CrossFamilyViolationError(ValueError):
    """Raised when the configured judge shares a canonical model family with C1 or C2 agents."""


class JudgeScoreOutput(StrictModel):
    G1: int = Field(ge=1, le=5)
    G2: Literal["pass", "fail"]
    G3: int = Field(ge=1, le=5)
    G4: int = Field(ge=1, le=5)
    G5: int = Field(ge=1, le=5)
    G6: Literal["pass", "fail"]
    G7: int = Field(ge=1, le=5)
    rationale: str = Field(min_length=5)

    @property
    def judge_citation_relevant(self) -> bool:
        return self.G5 >= 4

    @property
    def ordinal_mean(self) -> float:
        return round((self.G1 + self.G3 + self.G4 + self.G5 + self.G7) / 5.0, 4)


class DeterministicCompanions(StrictModel):
    numbers_match_calc: bool
    citations_exist: bool
    no_guilt_claims: bool
    inr_error_count: int
    inr_numbers_total: int


class JudgeEvaluationRecord(StrictModel):
    worksheet_id: str
    judge_model: str
    judge_family: str
    rubric_version: str
    prompt_version: str
    scores: JudgeScoreOutput
    companions: DeterministicCompanions
    prompt_tokens: int
    completion_tokens: int
    cost_usd: str
    latency_s: float


class PairwiseJudgeOutput(StrictModel):
    winner: Literal["A", "B", "tie"]
    score_a: JudgeScoreOutput
    score_b: JudgeScoreOutput
    comparison_rationale: str = Field(min_length=5)


class PairwiseEvaluationResult(StrictModel):
    presented_order: tuple[str, str]
    raw_winner: Literal["A", "B", "tie"]
    mapped_winner: Literal["first", "second", "tie"]
    score_first: JudgeScoreOutput
    score_second: JudgeScoreOutput
    comparison_rationale: str


class PositionSwapResult(StrictModel):
    forward_winner: Literal["first", "second", "tie"]
    swapped_winner: Literal["first", "second", "tie"]
    position_consistent: bool
    mean_abs_ordinal_drift: float


def cohens_kappa(labels_a: Sequence[str], labels_b: Sequence[str]) -> float:
    """Compute plain nominal/binary Cohen's kappa between two raters (target >= 0.75)."""
    if len(labels_a) != len(labels_b) or not labels_a:
        return 0.0
    n = len(labels_a)
    categories = sorted(set(labels_a) | set(labels_b))
    p_o = sum(1 for a, b in zip(labels_a, labels_b, strict=True) if a == b) / n
    p_e = sum((sum(1 for a in labels_a if a == c) / n) * (sum(1 for b in labels_b if b == c) / n) for c in categories)
    if p_e >= 1.0 - 1e-12:
        return 1.0 if p_o >= 1.0 - 1e-12 else 0.0
    return (p_o - p_e) / (1.0 - p_e)


def linear_weighted_kappa(
    scores_a: Sequence[int], scores_b: Sequence[int], *, min_val: int = 1, max_val: int = 5
) -> float:
    """Compute linear-weighted Cohen's kappa for ordinal scales (`1..5`)."""
    if len(scores_a) != len(scores_b) or not scores_a or max_val <= min_val:
        return 0.0
    n = len(scores_a)
    span = float(max_val - min_val)
    levels = list(range(min_val, max_val + 1))
    freq_a = {k: sum(1 for x in scores_a if x == k) / n for k in levels}
    freq_b = {k: sum(1 for y in scores_b if y == k) / n for k in levels}

    obs_dis = sum(abs(x - y) / span for x, y in zip(scores_a, scores_b, strict=True)) / n
    exp_dis = sum((abs(i - j) / span) * freq_a[i] * freq_b[j] for i in levels for j in levels)
    if exp_dis <= 1e-12:
        return 1.0 if obs_dis <= 1e-12 else 0.0
    return 1.0 - (obs_dis / exp_dis)


def criterion_kappa(criterion: str, vals_a: Sequence[Any], vals_b: Sequence[Any]) -> float:
    """Dispatch linear-weighted kappa for ordinal criteria (`G1,G3,G4,G5,G7`) and plain kappa for binary (`G2,G6`)."""
    if criterion in ORDINAL_CRITERIA:
        return linear_weighted_kappa([int(x) for x in vals_a], [int(y) for y in vals_b])
    return cohens_kappa([str(x).lower() for x in vals_a], [str(y).lower() for y in vals_b])


def infer_model_family(model_slug: str) -> str:
    """Infer canonical model-lineage family from slug; raises `ValueError` if lineage is unknown."""
    slug = model_slug.strip()
    for family, pat in _LINEAGE_PATTERNS:
        if pat.search(slug):
            return family
    raise ValueError(f"Cannot verify canonical model family for unrecognized model slug: {model_slug!r}")


def validate_cross_family_judge(
    judge_model: Optional[str] = None,
    investigator_models: Optional[Mapping[str, str]] = None,
) -> dict[str, Any]:
    """Verify the judge model belongs to a strictly disjoint canonical family from C1 and C2 models."""
    policy = get_policy()
    j_slug = judge_model or policy.model_for("judge").model_id
    inv_map = (
        dict(investigator_models)
        if investigator_models is not None
        else {
            role: policy.model_for(role).model_id
            for role in ("c1_investigator", "c2_supervisor", "c2_specialists")
        }
    )
    j_fam = infer_model_family(j_slug)
    inv_fams = {role: infer_model_family(slug) for role, slug in inv_map.items()}
    collisions = [f"{role} ({inv_map[role]} -> {fam})" for role, fam in inv_fams.items() if fam == j_fam]
    if collisions:
        raise CrossFamilyViolationError(
            f"Self-preference violation: judge {j_slug!r} ({j_fam}) shares canonical model family with {collisions}"
        )
    return {
        "judge_model": j_slug,
        "judge_family": j_fam,
        "investigator_models": inv_map,
        "investigator_families": inv_fams,
        "cross_family_verified": True,
    }


def _extract_json_dict(raw: str) -> dict[str, Any]:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=re.IGNORECASE | re.DOTALL).strip()
    m = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    obj = json.loads(m.group(0) if m else cleaned)
    if not isinstance(obj, dict):
        raise ValueError("Judge response is not a JSON object")
    return obj


def _scrub_log_obj(node: Any) -> Any:
    if isinstance(node, str):
        masked, _ = mask_pii(_SECRET_RE.sub("[REDACTED_SECRET]", node))
        return masked
    if isinstance(node, dict):
        return {k: _scrub_log_obj(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_scrub_log_obj(x) for x in node]
    return node


def compute_companions(
    worksheet: Mapping[str, Any],
    evidence_registry: Mapping[str, Any],
    calc_log: Sequence[Mapping[str, Any]] = (),
) -> DeterministicCompanions:
    vr = verify_worksheet(worksheet, evidence_registry, calc_log=calc_log)
    return DeterministicCompanions(
        numbers_match_calc=bool(vr.checks.get("numbers_match_calc", False)),
        citations_exist=bool(vr.checks.get("citations_exist", False)),
        no_guilt_claims=bool(vr.checks.get("no_guilt_claims", False)),
        inr_error_count=vr.inr_error_count,
        inr_numbers_total=vr.inr_numbers_total,
    )


class LLMJudge:
    """Cross-family Gemini judge (`temperature=0`) with blind inputs, pairwise randomization & raw audit logs."""

    def __init__(
        self,
        llm_client: Optional[LLMClientProtocol] = None,
        *,
        judge_model: Optional[str] = None,
        run_id: str = "judge_default",
        runs_dir: Path = Path("runs"),
        enforce_cross_family: bool = True,
    ) -> None:
        policy = get_policy()
        self.model = judge_model or policy.model_for("judge").model_id
        self.max_tokens = policy.model_for("judge").max_tokens
        self.family_check = (
            validate_cross_family_judge(self.model)
            if enforce_cross_family
            else {"judge_model": self.model, "judge_family": infer_model_family(self.model)}
        )
        self.client: LLMClientProtocol = llm_client or LLMClient(mode="live", run_id=run_id, runs_dir=runs_dir)
        self.raw_log_path = Path(runs_dir) / run_id / "judge_raw_responses.jsonl"

    def _append_raw_log_sync(self, entry: dict[str, Any]) -> None:
        self.raw_log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.raw_log_path.open("a", encoding="utf-8") as fh:
            fh.write(dumps_json(_scrub_log_obj(entry)) + "\n")

    async def score_worksheet(
        self,
        worksheet: Mapping[str, Any],
        evidence_summary: Mapping[str, Any],
        *,
        worksheet_id: str = "WS-UNKNOWN",
        evidence_registry: Optional[Mapping[str, Any]] = None,
        calc_log: Sequence[Mapping[str, Any]] = (),
    ) -> JudgeEvaluationRecord:
        blinded = blind_worksheet_for_judge(worksheet)
        messages, rubric_ver, prompt_ver = build_single_judge_messages(blinded, evidence_summary)
        resp = await self.client.chat(
            messages,
            model=self.model,
            temperature="0.0",
            max_tokens=self.max_tokens,
            response_format={"type": "json_object"},
        )
        scores = JudgeScoreOutput.model_validate(_extract_json_dict(resp.text))
        companions = compute_companions(
            worksheet, evidence_registry if evidence_registry is not None else {}, calc_log
        )
        await asyncio.to_thread(
            self._append_raw_log_sync,
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "single_score",
                "worksheet_id": worksheet_id,
                "model": resp.model or self.model,
                "judge_family": self.family_check["judge_family"],
                "rubric_version": rubric_ver,
                "prompt_version": prompt_ver,
                "prompt_tokens": resp.usage.prompt_tokens,
                "completion_tokens": resp.usage.completion_tokens,
                "cost_usd": str(resp.cost_usd),
                "latency_s": round(resp.latency_s, 6),
                "request_messages": messages,
                "raw_response": resp.text,
                "parsed_scores": scores.model_dump(mode="json"),
                "deterministic_companions": companions.model_dump(mode="json"),
            },
        )
        return JudgeEvaluationRecord(
            worksheet_id=worksheet_id,
            judge_model=resp.model or self.model,
            judge_family=str(self.family_check["judge_family"]),
            rubric_version=rubric_ver,
            prompt_version=prompt_ver,
            scores=scores,
            companions=companions,
            prompt_tokens=resp.usage.prompt_tokens,
            completion_tokens=resp.usage.completion_tokens,
            cost_usd=str(resp.cost_usd),
            latency_s=round(resp.latency_s, 6),
        )

    async def score_pairwise(
        self,
        ws_first: Mapping[str, Any],
        ws_second: Mapping[str, Any],
        evidence_summary: Mapping[str, Any],
        *,
        seed: Optional[int] = 42,
        force_swap: Optional[bool] = None,
    ) -> PairwiseEvaluationResult:
        """Compare two blinded worksheets; randomizes `(A, B)` presentation order unless `force_swap` is set."""
        swapped = bool(random.Random(seed).choice([False, True])) if force_swap is None else force_swap
        b1, b2 = blind_worksheet_for_judge(ws_first), blind_worksheet_for_judge(ws_second)
        slot_a, slot_b = (b2, b1) if swapped else (b1, b2)
        order = ("second_as_A", "first_as_B") if swapped else ("first_as_A", "second_as_B")

        messages, rubric_ver, prompt_ver = build_pairwise_judge_messages(slot_a, slot_b, evidence_summary)
        resp = await self.client.chat(
            messages,
            model=self.model,
            temperature="0.0",
            max_tokens=max(1536, self.max_tokens),
            response_format={"type": "json_object"},
        )
        parsed = PairwiseJudgeOutput.model_validate(_extract_json_dict(resp.text))
        await asyncio.to_thread(
            self._append_raw_log_sync,
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "pairwise",
                "presented_order": list(order),
                "model": resp.model or self.model,
                "rubric_version": rubric_ver,
                "prompt_version": prompt_ver,
                "prompt_tokens": resp.usage.prompt_tokens,
                "completion_tokens": resp.usage.completion_tokens,
                "cost_usd": str(resp.cost_usd),
                "latency_s": round(resp.latency_s, 6),
                "raw_response": resp.text,
            },
        )
        if parsed.winner == "tie":
            mapped: Literal["first", "second", "tie"] = "tie"
        elif (parsed.winner == "A" and not swapped) or (parsed.winner == "B" and swapped):
            mapped = "first"
        else:
            mapped = "second"
        return PairwiseEvaluationResult(
            presented_order=order,
            raw_winner=parsed.winner,
            mapped_winner=mapped,
            score_first=parsed.score_b if swapped else parsed.score_a,
            score_second=parsed.score_a if swapped else parsed.score_b,
            comparison_rationale=parsed.comparison_rationale,
        )

    async def evaluate_position_swap(
        self,
        ws_first: Mapping[str, Any],
        ws_second: Mapping[str, Any],
        evidence_summary: Mapping[str, Any],
    ) -> PositionSwapResult:
        """Run forward `(1, 2)` and swapped `(2, 1)` pairwise judge passes to measure position bias."""
        fwd = await self.score_pairwise(ws_first, ws_second, evidence_summary, force_swap=False)
        rev = await self.score_pairwise(ws_first, ws_second, evidence_summary, force_swap=True)
        drifts = [
            abs(getattr(fwd.score_first, c) - getattr(rev.score_first, c))
            + abs(getattr(fwd.score_second, c) - getattr(rev.score_second, c))
            for c in ORDINAL_CRITERIA
        ]
        mean_drift = round(sum(drifts) / (2.0 * len(ORDINAL_CRITERIA)), 4)
        return PositionSwapResult(
            forward_winner=fwd.mapped_winner,
            swapped_winner=rev.mapped_winner,
            position_consistent=(fwd.mapped_winner == rev.mapped_winner),
            mean_abs_ordinal_drift=mean_drift,
        )
