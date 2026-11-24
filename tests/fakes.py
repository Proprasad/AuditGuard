"""
Scripted offline `FakeLLM` implementing `LLMClientProtocol` for deterministic unit tests
of C1/C2 tool-calling loops, RBAC, bounds, budgets, repair retries, and forced finishes.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from decimal import Decimal
import json
from pathlib import Path
import threading
from typing import Any, Optional, Union

from src.llm.replay import CassetteStore, canonical_request_envelope, compute_cassette_key
from src.llm.schemas import ChatResponse, TokenUsage, ToolCallRequest

StepHandler = Callable[[list[dict[str, Any]], Optional[list[dict[str, Any]]]], ChatResponse]
ScriptItem = Union[ChatResponse, StepHandler]


def make_tool_turn(
    *calls: tuple[str, dict[str, Any]],
    text: str = "",
    prompt_tokens: int = 120,
    completion_tokens: int = 60,
    cost_usd: str | Decimal = "0.000150",
    model: str = "fake/gpt-5-mini",
) -> ChatResponse:
    """Construct a scripted assistant turn containing one or more OpenAI function tool calls."""
    tcs = [
        ToolCallRequest(
            id=f"call_{idx + 1}",
            name=name,
            arguments=args,
            raw_arguments=json.dumps(args, sort_keys=True),
        )
        for idx, (name, args) in enumerate(calls)
    ]
    return ChatResponse(
        text=text,
        tool_calls=tcs,
        usage=TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        ),
        model=model,
        cost_usd=Decimal(str(cost_usd)),
        latency_s=0.005,
        finish_reason="tool_calls",
    )


def make_text_turn(
    text: str,
    *,
    prompt_tokens: int = 100,
    completion_tokens: int = 40,
    cost_usd: str | Decimal = "0.000110",
    model: str = "fake/gpt-5-mini",
) -> ChatResponse:
    """Construct a scripted plain-text / JSON assistant turn with zero tool calls."""
    return ChatResponse(
        text=text,
        tool_calls=[],
        usage=TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        ),
        model=model,
        cost_usd=Decimal(str(cost_usd)),
        latency_s=0.004,
        finish_reason="stop",
    )


class FakeLLM:
    """
    Thread/task-safe scripted fake LLM.

    Supports either a flat `script` sequence or `role_scripts` keyed by role substring
    found in the leading system message (ideal for concurrent `asyncio.gather` C2 tests).
    """

    def __init__(
        self,
        script: Optional[Sequence[ScriptItem]] = None,
        *,
        role_scripts: Optional[dict[str, Sequence[ScriptItem]]] = None,
        runs_dir: Optional[Path] = None,
        run_id: str = "fake_run",
    ) -> None:
        self._script = list(script or [])
        self._cursor = 0
        self._role_scripts = {k: list(v) for k, v in (role_scripts or {}).items()}
        self._role_cursors = {k: 0 for k in (role_scripts or {})}
        self._lock = threading.Lock()
        self.calls: list[dict[str, Any]] = []
        self._store = CassetteStore(mode="live", run_id=run_id, runs_dir=runs_dir) if runs_dir is not None else None

    @property
    def transcript_path(self) -> Optional[Path]:
        return self._store.transcript_path if self._store is not None else None

    def _next_item(self, messages: list[dict[str, Any]]) -> ScriptItem:
        sys_txt = str(messages[0].get("content", "")) if messages else ""
        with self._lock:
            for role_key, items in self._role_scripts.items():
                if role_key in sys_txt:
                    idx = self._role_cursors[role_key]
                    if idx >= len(items):
                        return make_text_turn(f"{role_key} exhausted script")
                    self._role_cursors[role_key] = idx + 1
                    return items[idx]
            if self._cursor >= len(self._script):
                return make_text_turn("script exhausted")
            item = self._script[self._cursor]
            self._cursor += 1
            return item

    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        model: Optional[str] = None,
        temperature: Optional[float | Decimal | str] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[dict[str, Any]] = None,
        seed: Optional[int] = None,
    ) -> ChatResponse:
        with self._lock:
            self.calls.append(
                {
                    "messages": list(messages),
                    "tools": tools,
                    "model": model,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "seed": seed,
                }
            )
        item = self._next_item(messages)
        resp = item(messages, tools) if callable(item) else item
        if self._store is not None:
            env = canonical_request_envelope(
                model=model or resp.model,
                messages=messages,
                tools=tools,
                temperature=Decimal(str(temperature)) if temperature is not None else None,
                max_tokens=max_tokens,
                response_format=response_format,
                seed=seed,
            )
            await self._store.write_transcript(compute_cassette_key(env), env, resp)
        return resp
