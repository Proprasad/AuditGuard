"""
Deterministic Decimal token-cost table per OpenRouter / provider model slug.

Falls back to `PolicyConfig.pricing["default"]` (`config/models.yaml`) for unlisted models
so cost accounting is always exact, deterministic, and never floating-point.
"""

from __future__ import annotations

from decimal import Decimal

from src.config import get_policy
from src.core.canonical import to_usd

_MILLION = Decimal("1000000")

# (input_per_million_usd, output_per_million_usd)
MODEL_PRICING_PER_MILLION_USD: dict[str, tuple[Decimal, Decimal]] = {
    "openai/gpt-6-luna": (Decimal("1.25"), Decimal("5.00")),
    "openai/gpt-5-mini": (Decimal("0.25"), Decimal("2.00")),
    "openai/gpt-5-nano": (Decimal("0.05"), Decimal("0.40")),
    "openai/gpt-5.4-nano": (Decimal("0.08"), Decimal("0.45")),
    "openai/gpt-4.1-mini": (Decimal("0.40"), Decimal("1.60")),
    "openai/gpt-4.1-nano": (Decimal("0.10"), Decimal("0.40")),
    "openai/gpt-4o-mini": (Decimal("0.15"), Decimal("0.60")),
    "openai/gpt-oss-120b": (Decimal("0.15"), Decimal("0.60")),
    "anthropic/claude-haiku-5.5": (Decimal("0.80"), Decimal("4.00")),
    "anthropic/claude-3-haiku": (Decimal("0.25"), Decimal("1.25")),
    "google/gemini-3.1-flash-lite": (Decimal("0.075"), Decimal("0.30")),
    "google/gemma-4-31b-it": (Decimal("0.10"), Decimal("0.30")),
    "qwen/qwen3.7-plus": (Decimal("0.40"), Decimal("1.20")),
    "qwen/qwen3.6-plus": (Decimal("0.35"), Decimal("1.05")),
    "qwen/qwen3.8-27b": (Decimal("0.20"), Decimal("0.60")),
    "qwen/qwen3.5-35b-a3b": (Decimal("0.18"), Decimal("0.54")),
    "qwen/qwen3.5-9b": (Decimal("0.08"), Decimal("0.24")),
    "deepseek/deepseek-v4-flash": (Decimal("0.10"), Decimal("0.28")),
    "deepseek/deepseek-chat": (Decimal("0.27"), Decimal("1.10")),
    "z-ai/glm-5.3": (Decimal("0.35"), Decimal("1.40")),
    "z-ai/glm-5.3-flash": (Decimal("0.08"), Decimal("0.25")),
    "meta-llama/llama-3.3-70b-instruct": (Decimal("0.12"), Decimal("0.30")),
    "meta-llama/llama-3.1-70b-instruct": (Decimal("0.12"), Decimal("0.30")),
    "meta-llama/llama-3.1-8b-instruct": (Decimal("0.04"), Decimal("0.08")),
    "amazon/nova-lite-v1": (Decimal("0.06"), Decimal("0.24")),
}


def get_model_rates_per_million(model: str) -> tuple[Decimal, Decimal]:
    """Return `(input_per_million_usd, output_per_million_usd)` for `model`."""
    if model in MODEL_PRICING_PER_MILLION_USD:
        return MODEL_PRICING_PER_MILLION_USD[model]
    policy = get_policy()
    price = policy.pricing.get(model) or policy.pricing["default"]
    return price.input_per_million_usd, price.output_per_million_usd


def compute_call_cost_usd(model: str, prompt_tokens: int, completion_tokens: int) -> Decimal:
    """Compute exact USD cost (`Decimal` quantized to 1e-6) for a single LLM call."""
    in_rate, out_rate = get_model_rates_per_million(model)
    raw = (Decimal(max(0, prompt_tokens)) * in_rate + Decimal(max(0, completion_tokens)) * out_rate) / _MILLION
    return to_usd(raw)


def estimate_prompt_ceiling_usd(model: str, messages: list[dict[str, object]], max_tokens: int) -> Decimal:
    """Conservative upper-bound cost check before issuing a live network call."""
    approx_chars = sum(len(str(m.get("content", ""))) for m in messages)
    approx_prompt_tokens = max(1, approx_chars // 4)
    return compute_call_cost_usd(model, approx_prompt_tokens, max(64, max_tokens))
