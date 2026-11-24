"""
AuditGuard v3 LLM Client Package (`src/llm/`).

Provides:
  * `LLMClient` & `LLMClientProtocol` (OpenRouter / OpenAI-compatible via async `httpx`)
  * `CassetteStore` & `CassetteMissError` (`live` | `record` | `replay` modes + JSONL transcripts)
  * `compute_call_cost_usd` & `MODEL_PRICING_PER_MILLION_USD` (`Decimal` cost accounting)
  * `ChatResponse`, `ToolCallRequest`, `TokenUsage`, `TranscriptEntry`
"""

from __future__ import annotations

from src.llm.client import LLMClient, LLMClientError, LLMClientProtocol
from src.llm.cost import (
    MODEL_PRICING_PER_MILLION_USD,
    compute_call_cost_usd,
    estimate_prompt_ceiling_usd,
    get_model_rates_per_million,
)
from src.llm.replay import (
    CassetteMissError,
    CassetteStore,
    LLMMode,
    canonical_request_envelope,
    compute_cassette_key,
)
from src.llm.schemas import ChatResponse, TokenUsage, ToolCallRequest, TranscriptEntry

__all__ = [
    "MODEL_PRICING_PER_MILLION_USD",
    "CassetteMissError",
    "CassetteStore",
    "ChatResponse",
    "LLMClient",
    "LLMClientError",
    "LLMClientProtocol",
    "LLMMode",
    "TokenUsage",
    "ToolCallRequest",
    "TranscriptEntry",
    "canonical_request_envelope",
    "compute_call_cost_usd",
    "compute_cassette_key",
    "estimate_prompt_ceiling_usd",
    "get_model_rates_per_million",
]
