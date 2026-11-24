"""
Typed schemas for OpenRouter / OpenAI-compatible chat completions, tool calls,
token accounting, and append-only transcript / cassette records.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from pydantic import Field

from src.core.canonical import Usd
from src.models import StrictModel


def _zero_usd() -> Decimal:
    return Decimal("0.000000")


class ToolCallRequest(StrictModel):
    """Parsed OpenAI-style function tool call emitted by an assistant turn."""

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    raw_arguments: str = ""


class TokenUsage(StrictModel):
    """Exact token counts reported by the provider (or 0 on offline/scripted fakes)."""

    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)


class ChatResponse(StrictModel):
    """Normalized LLM completion returned by `LLMClient.chat` and `FakeLLM.chat`."""

    text: str = ""
    tool_calls: list[ToolCallRequest] = Field(default_factory=list)
    usage: TokenUsage = Field(default_factory=TokenUsage)
    model: str = "offline"
    cost_usd: Usd = Field(default_factory=_zero_usd)
    latency_s: float = Field(default=0.0, ge=0.0)
    finish_reason: str = "stop"
    from_cassette: bool = False

    def to_assistant_message(self) -> dict[str, Any]:
        """Convert this turn into an OpenAI-compatible assistant message for conversation history."""
        msg: dict[str, Any] = {"role": "assistant", "content": self.text or ""}
        if self.tool_calls:
            import json

            msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": tc.raw_arguments or json.dumps(tc.arguments, sort_keys=True),
                    },
                }
                for tc in self.tool_calls
            ]
        return msg


class TranscriptEntry(StrictModel):
    """Immutable audit record written to `runs/<run_id>/transcripts.jsonl` on every LLM call."""

    timestamp: str
    run_id: str
    mode: str
    cassette_key: str
    model: str
    request: dict[str, Any]
    response: dict[str, Any]
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    cost_usd: str
    latency_s: float = Field(ge=0.0)
    from_cassette: bool = False
