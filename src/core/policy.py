"""
PolicyConfig (validated, fail-fast) and the per-run BudgetLedger.

`config/models.yaml` is the single source of truth for budgets, policy bounds, model slugs, temperatures,
suspicion rules and structuring thresholds. Selected environment variables override individual values
(see `ENV_OVERRIDES`). Pure module: callers pass the environment mapping explicitly.
"""
from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from src.core.canonical import to_decimal, to_money, to_ratio, to_usd


class PolicyConfigError(ValueError):
    """Raised at startup when config/models.yaml (+ env overrides) is missing or invalid."""


def _lenient_decimal(value: Any) -> Decimal:
    """Config files are trusted human input: allow float literals, converting through str exactly."""
    if isinstance(value, float):
        value = str(value)
    return to_decimal(value, Decimal("0.000001"))


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ModelSpec(_Strict):
    provider: str
    model_id: str
    temperature: Decimal
    max_tokens: int = Field(gt=0)

    @field_validator("temperature", mode="before")
    @classmethod
    def _temp(cls, v: Any) -> Decimal:
        return _lenient_decimal(v)


class Price(_Strict):
    input_per_million_usd: Decimal
    output_per_million_usd: Decimal

    @field_validator("input_per_million_usd", "output_per_million_usd", mode="before")
    @classmethod
    def _p(cls, v: Any) -> Decimal:
        return _lenient_decimal(v)


class Budgets(_Strict):
    max_tool_calls: int = Field(gt=0)
    max_replans: int = Field(ge=0)
    max_critique_retries: int = Field(ge=0)
    max_cost_usd_per_case: Decimal

    @field_validator("max_cost_usd_per_case", mode="before")
    @classmethod
    def _c(cls, v: Any) -> Decimal:
        return to_usd(_lenient_decimal(v))


class Timeouts(_Strict):
    mcp_call_seconds: int = Field(gt=0)
    llm_call_seconds: int = Field(gt=0)


class IntRange(_Strict):
    min: int
    max: int
    default: int

    @model_validator(mode="after")
    def _ordered(self) -> IntRange:
        if not self.min <= self.default <= self.max:
            raise ValueError(f"range must satisfy min<=default<=max, got {self.min}/{self.default}/{self.max}")
        return self


class DecRange(_Strict):
    min: Decimal
    max: Decimal
    default: Decimal

    @field_validator("min", "max", "default", mode="before")
    @classmethod
    def _d(cls, v: Any) -> Decimal:
        return to_ratio(_lenient_decimal(v))

    @model_validator(mode="after")
    def _ordered(self) -> DecRange:
        if not self.min <= self.default <= self.max:
            raise ValueError("range must satisfy min<=default<=max")
        return self


class GraphBounds(_Strict):
    time_window_days: IntRange
    max_hops: IntRange
    amount_tolerance: DecRange
    min_intermediaries: IntRange


class GraphLimits(_Strict):
    max_raw_paths: int = Field(gt=0)
    max_paths_returned: int = Field(gt=0)
    anchor_lookback_days: int = Field(ge=0)


class SuspicionRules(_Strict):
    scatter_gather_min_nodes: int
    rapid_layering_max_days: int
    rapid_layering_min_nodes: int
    fee_skim_min_ratio: Decimal

    @field_validator("fee_skim_min_ratio", mode="before")
    @classmethod
    def _r(cls, v: Any) -> Decimal:
        return to_ratio(_lenient_decimal(v))


class Structuring(_Strict):
    threshold_inr: Decimal
    floor_inr: Decimal

    @field_validator("threshold_inr", "floor_inr", mode="before")
    @classmethod
    def _m(cls, v: Any) -> Decimal:
        return to_money(_lenient_decimal(v))


class MemoryPolicy(_Strict):
    short_term_window_messages: int = Field(gt=0)


class RetrievalPolicy(_Strict):
    embedding_model: str
    reranker_model: str
    rrf_k: int
    top_k_dense: int
    top_k_bm25: int
    top_k_final: int


class ScoringConfig(_Strict):
    prior: Decimal
    min_confidence: Decimal
    max_confidence: Decimal
    disposition_threshold: Decimal
    request_info_floor: Decimal
    suspicious_weights: dict[str, Decimal]
    benign_weights: dict[str, Decimal]

    @field_validator("prior", "min_confidence", "max_confidence", "disposition_threshold", "request_info_floor", mode="before")
    @classmethod
    def _ratio(cls, v: Any) -> Decimal:
        return to_ratio(_lenient_decimal(v))

    @field_validator("suspicious_weights", "benign_weights", mode="before")
    @classmethod
    def _weights(cls, v: Any) -> dict[str, Decimal]:
        return {k: to_ratio(_lenient_decimal(x)) for k, x in dict(v).items()}


class PolicyConfig(_Strict):
    config_version: str
    allowed_models: tuple[str, ...]
    models: dict[str, ModelSpec]
    pricing: dict[str, Price]
    budgets: Budgets
    timeouts: Timeouts
    graph_bounds: GraphBounds
    graph_limits: GraphLimits
    suspicion: SuspicionRules
    structuring: Structuring
    scoring: ScoringConfig
    memory: MemoryPolicy
    retrieval: RetrievalPolicy

    @model_validator(mode="after")
    def _models_allowed(self) -> PolicyConfig:
        bad = [f"{role}={spec.model_id}" for role, spec in self.models.items() if spec.model_id not in self.allowed_models]
        if bad:
            raise ValueError(f"model slugs not in allowed_models: {bad}")
        if "default" not in self.pricing:
            raise ValueError("pricing.default is required")
        for required in ("c1_investigator", "c2_supervisor", "c2_specialists"):
            if required not in self.models:
                raise ValueError(f"models.{required} is required")
        return self

    # ------------------------------------------------------------------ helpers
    def model_for(self, role: str) -> ModelSpec:
        return self.models[role]

    def is_allowed_model(self, slug: str) -> bool:
        return slug in self.allowed_models

    def default_graph_params(self) -> dict[str, Any]:
        gb = self.graph_bounds
        return {
            "time_window_days": gb.time_window_days.default,
            "max_hops": gb.max_hops.default,
            "amount_tolerance": gb.amount_tolerance.default,
            "min_intermediaries": gb.min_intermediaries.default,
        }

    def validate_graph_params(self, params: Mapping[str, Any]) -> list[str]:
        """Return human-readable violations for whichever graph parameters are present."""
        gb = self.graph_bounds
        errors: list[str] = []
        for key, rng in (
            ("time_window_days", gb.time_window_days),
            ("max_hops", gb.max_hops),
            ("min_intermediaries", gb.min_intermediaries),
        ):
            if key in params and params[key] is not None:
                value = params[key]
                if isinstance(value, bool) or not isinstance(value, int) or not rng.min <= value <= rng.max:
                    errors.append(f"{key}={value} outside allowed [{rng.min}, {rng.max}]")
        if "amount_tolerance" in params and params["amount_tolerance"] is not None:
            try:
                tol = Decimal(str(params["amount_tolerance"]))
            except Exception:  # noqa: BLE001 - any malformed literal is a violation
                tol = None
            rng_t = gb.amount_tolerance
            if tol is None or not rng_t.min <= tol <= rng_t.max:
                errors.append(f"amount_tolerance={params['amount_tolerance']} outside allowed [{rng_t.min}, {rng_t.max}]")
        return errors

    def estimate_cost_usd(self, model_id: str, tokens_in: int, tokens_out: int) -> Decimal:
        price = self.pricing.get(model_id, self.pricing["default"])
        million = Decimal(1_000_000)
        cost = (Decimal(tokens_in) * price.input_per_million_usd + Decimal(tokens_out) * price.output_per_million_usd) / million
        return to_usd(cost)

    def new_ledger(self) -> BudgetLedger:
        return BudgetLedger(self.budgets)


# Env var -> (dotted path, caster)
ENV_OVERRIDES: dict[str, tuple[tuple[str, ...], Any]] = {
    "MAX_TOOL_CALLS": (("budgets", "max_tool_calls"), int),
    "MAX_REPLANS": (("budgets", "max_replans"), int),
    "MAX_CRITIQUE_RETRIES": (("budgets", "max_critique_retries"), int),
    "MAX_TOOL_BUDGET_USD": (("budgets", "max_cost_usd_per_case"), str),
    "OPENAI_MODEL": (("models", "c1_investigator", "model_id"), str),
    "OPENAI_STRONG_MODEL": (("models", "c2_supervisor", "model_id"), str),
    "OPENAI_SPECIALIST_MODEL": (("models", "c2_specialists", "model_id"), str),
    "JUDGE_MODEL": (("models", "judge", "model_id"), str),
}


def _set_path(tree: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    node = tree
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value


def load_policy(path: Path, environ: Mapping[str, str]) -> PolicyConfig:
    """Load + validate the policy; raises PolicyConfigError (fail-fast) on any problem."""
    if not path.exists():
        raise PolicyConfigError(f"policy file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise PolicyConfigError(f"invalid YAML in {path}: {exc}") from exc
    for env_key, (dotted, caster) in ENV_OVERRIDES.items():
        if environ.get(env_key):
            try:
                _set_path(raw, dotted, caster(environ[env_key]))
            except ValueError as exc:
                raise PolicyConfigError(f"invalid {env_key}={environ[env_key]!r}: {exc}") from exc
    if "models" in raw and "c2_specialists" in raw["models"] and not environ.get("OPENAI_SPECIALIST_MODEL") and environ.get("OPENAI_MODEL"):
        raw["models"]["c2_specialists"]["model_id"] = environ["OPENAI_MODEL"]
    try:
        return PolicyConfig.model_validate(raw)
    except ValidationError as exc:
        raise PolicyConfigError(f"invalid policy configuration in {path}: {exc}") from exc


# --------------------------------------------------------------------------------------------------
# Per-run budget ledger (thread-safe; enforced BEFORE every MCP tool call and LLM invocation)
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class BudgetVerdict:
    allowed: bool
    error_code: str = ""
    message: str = ""


class BudgetLedger:
    def __init__(self, budgets: Budgets) -> None:
        self._budgets = budgets
        self._lock = threading.Lock()
        self._calls = 0
        self._cost = Decimal("0")
        self._tokens_in = 0
        self._tokens_out = 0
        self._replans = 0
        self._critique_retries = 0

    # -- tool calls --------------------------------------------------------------------------------
    def try_consume_tool_call(self) -> BudgetVerdict:
        with self._lock:
            if self._calls >= self._budgets.max_tool_calls:
                return BudgetVerdict(False, "BUDGET_EXCEEDED", f"Tool call budget exhausted ({self._calls}/{self._budgets.max_tool_calls})")
            if self._cost >= self._budgets.max_cost_usd_per_case:
                return BudgetVerdict(False, "BUDGET_EXCEEDED", f"Cost budget exhausted (${self._cost}/${self._budgets.max_cost_usd_per_case})")
            self._calls += 1
            return BudgetVerdict(True)

    # -- LLM calls ---------------------------------------------------------------------------------
    def check_llm_allowed(self) -> BudgetVerdict:
        with self._lock:
            if self._cost >= self._budgets.max_cost_usd_per_case:
                return BudgetVerdict(False, "BUDGET_EXCEEDED", f"Cost budget exhausted (${self._cost}/${self._budgets.max_cost_usd_per_case})")
            return BudgetVerdict(True)

    def record_llm_usage(self, tokens_in: int, tokens_out: int, cost_usd: Decimal) -> None:
        with self._lock:
            self._tokens_in += tokens_in
            self._tokens_out += tokens_out
            self._cost += cost_usd

    # -- replans / critique retries ----------------------------------------------------------------
    def try_replan(self) -> BudgetVerdict:
        with self._lock:
            if self._replans >= self._budgets.max_replans:
                return BudgetVerdict(False, "REPLAN_BUDGET_EXCEEDED", f"Replan budget exhausted ({self._replans}/{self._budgets.max_replans})")
            self._replans += 1
            return BudgetVerdict(True)

    def try_critique_retry(self) -> BudgetVerdict:
        with self._lock:
            if self._critique_retries >= self._budgets.max_critique_retries:
                return BudgetVerdict(False, "CRITIQUE_BUDGET_EXCEEDED", f"Critique retries exhausted ({self._critique_retries}/{self._budgets.max_critique_retries})")
            self._critique_retries += 1
            return BudgetVerdict(True)

    def preload(self, calls: int = 0, cost_usd: Decimal = Decimal("0"), replans: int = 0, critique_retries: int = 0) -> None:
        """Restore counters (crash-resume) or simulate exhaustion in tests/red-team runs."""
        with self._lock:
            self._calls, self._cost = calls, to_usd(cost_usd)
            self._replans, self._critique_retries = replans, critique_retries

    # -- introspection -----------------------------------------------------------------------------
    @property
    def calls_used(self) -> int:
        return self._calls

    @property
    def cost_usd(self) -> Decimal:
        return self._cost

    @property
    def tokens_used(self) -> int:
        return self._tokens_in + self._tokens_out

    @property
    def replans_used(self) -> int:
        return self._replans

    @property
    def critique_retries_used(self) -> int:
        return self._critique_retries

    @property
    def budgets(self) -> Budgets:
        return self._budgets

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "tool_calls_used": self._calls,
                "max_tool_calls": self._budgets.max_tool_calls,
                "cost_usd": self._cost,
                "max_cost_usd": self._budgets.max_cost_usd_per_case,
                "tokens_used": self._tokens_in + self._tokens_out,
                "replans_used": self._replans,
                "critique_retries_used": self._critique_retries,
            }
