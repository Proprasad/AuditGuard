"""
Async OpenRouter / OpenAI-compatible LLM client (`httpx.AsyncClient`) with:
  * `chat(messages, tools, model, temperature, max_tokens, response_format, seed)`
  * Exponential-backoff retries (3 retries), 60 s timeout
  * Modes: `live`, `record`, `replay` (raises `CassetteMissError` on miss)
  * Every call logged to `runs/<run_id>/transcripts.jsonl` with exact Decimal USD cost
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
import json
import os
from pathlib import Path
import time
from typing import Any, Optional, Protocol, runtime_checkable

import httpx

from src.agent.llm_client import _resolve_api_key
from src.config import get_policy, settings
from src.core.canonical import to_decimal
from src.llm.cost import compute_call_cost_usd
from src.llm.replay import (
    CassetteStore,
    LLMMode,
    canonical_request_envelope,
    compute_cassette_key,
)
from src.llm.schemas import ChatResponse, TokenUsage, ToolCallRequest
from src.observability.metrics import LLM_CALL_DURATION, LLM_CALLS_TOTAL, LLM_COST_USD_TOTAL, LLM_TOKENS_TOTAL

RETRYABLE_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})


class LLMClientError(RuntimeError):
    """Raised when an OpenRouter/OpenAI chat completion fails after retries or lacks credentials."""


@runtime_checkable
class LLMClientProtocol(Protocol):
    """Structural interface satisfied by both `LLMClient` and `tests/fakes.py:FakeLLM`."""

    @property
    def transcript_path(self) -> Optional[Path]: ...

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
    ) -> ChatResponse: ...


def _record_llm_metrics(model: str, mode: str, response: ChatResponse, seconds: float) -> None:
    """Prometheus only (floats are fine here); budget accounting stays in exact Decimal in `BudgetLedger`."""
    LLM_CALLS_TOTAL.labels(model=model, mode=mode, status="ok").inc()
    LLM_CALL_DURATION.labels(model=model, mode=mode).observe(seconds)
    LLM_TOKENS_TOTAL.labels(model=model, kind="prompt").inc(response.usage.prompt_tokens)
    LLM_TOKENS_TOTAL.labels(model=model, kind="completion").inc(response.usage.completion_tokens)
    LLM_COST_USD_TOTAL.labels(model=model).inc(float(response.cost_usd))


def _norm_temperature(value: Optional[float | Decimal | str]) -> Optional[Decimal]:
    if value is None:
        return None
    return to_decimal(str(value), Decimal("0.0001"))


def _extract_message_text(raw_content: Any) -> str:
    if isinstance(raw_content, str):
        return raw_content
    if isinstance(raw_content, list):
        parts = [
            str(block.get("text", ""))
            for block in raw_content
            if isinstance(block, dict) and block.get("type") in ("text", "output_text", None)
        ]
        return "\n".join(p for p in parts if p)
    return ""


def _parse_tool_calls(raw_calls: Any) -> list[ToolCallRequest]:
    if not isinstance(raw_calls, list):
        return []
    parsed: list[ToolCallRequest] = []
    for idx, item in enumerate(raw_calls):
        if not isinstance(item, dict):
            continue
        fn = item.get("function") or {}
        if not isinstance(fn, dict) or not fn.get("name"):
            continue
        raw_args = fn.get("arguments")
        raw_str = raw_args if isinstance(raw_args, str) else json.dumps(raw_args or {}, sort_keys=True)
        try:
            args_obj = json.loads(raw_str) if raw_str.strip() else {}
            if not isinstance(args_obj, dict):
                args_obj = {"_invalid_json": raw_str}
        except json.JSONDecodeError:
            args_obj = {"_invalid_json": raw_str}
        parsed.append(
            ToolCallRequest(
                id=str(item.get("id") or f"call_{idx}"),
                name=str(fn["name"]),
                arguments=args_obj,
                raw_arguments=raw_str,
            )
        )
    return parsed


def _parse_chat_response(data: dict[str, Any], requested_model: str, latency_s: float) -> ChatResponse:
    choice = (data.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    usage_raw = data.get("usage") or {}
    p_tok = int(usage_raw.get("prompt_tokens") or 0)
    c_tok = int(usage_raw.get("completion_tokens") or 0)
    t_tok = int(usage_raw.get("total_tokens") or (p_tok + c_tok))
    actual_model = str(data.get("model") or requested_model)
    cost = compute_call_cost_usd(requested_model, p_tok, c_tok)
    return ChatResponse(
        text=_extract_message_text(message.get("content")),
        tool_calls=_parse_tool_calls(message.get("tool_calls")),
        usage=TokenUsage(prompt_tokens=p_tok, completion_tokens=c_tok, total_tokens=t_tok),
        model=actual_model,
        cost_usd=cost,
        latency_s=latency_s,
        finish_reason=str(choice.get("finish_reason") or "stop"),
        from_cassette=False,
    )


def _wire_payload(
    *,
    model: str,
    messages: list[dict[str, Any]],
    tools: Optional[list[dict[str, Any]]],
    temperature: Optional[Decimal],
    max_tokens: int,
    response_format: Optional[dict[str, Any]],
    seed: Optional[int],
    drop_temperature: bool = False,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
    }
    if not drop_temperature and temperature is not None:
        if "gpt-5" in model:
            payload["reasoning"] = {"effort": os.getenv("OPENAI_REASONING_EFFORT") or "low"}
        else:
            payload["temperature"] = float(temperature)
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    if response_format is not None:
        payload["response_format"] = response_format
    if seed is not None:
        payload["seed"] = seed
    return payload


def _should_strip_temp(resp: httpx.Response, drop_temp: bool, can_retry: bool) -> bool:
    if resp.status_code != 400 or drop_temp or not can_retry:
        return False
    body_txt = resp.text.lower()
    return "temperature" in body_txt or "reasoning" in body_txt


class LLMClient:
    """OpenRouter / OpenAI-compatible async client with cassette replay and JSONL transcripts."""

    def __init__(
        self,
        *,
        mode: LLMMode = "live",
        cassette_path: Optional[Path | str] = None,
        run_id: Optional[str] = None,
        runs_dir: Path | str = Path("runs"),
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_s: float = 60.0,
        max_retries: int = 3,
        backoff_base_s: float = 0.5,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        if mode in ("record", "replay") and cassette_path is None:
            raise ValueError(f"cassette_path must be provided when mode={mode!r}")
        self.mode: LLMMode = mode
        self.base_url = (base_url or os.getenv("OPENAI_BASE_URL") or settings.openai_base_url).rstrip("/")
        self._explicit_key = api_key
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.backoff_base_s = backoff_base_s
        self._transport = transport
        self.store = CassetteStore(
            mode=mode,
            cassette_path=Path(cassette_path) if cassette_path is not None else None,
            run_id=run_id,
            runs_dir=Path(runs_dir),
        )

    @property
    def transcript_path(self) -> Optional[Path]:
        return self.store.transcript_path

    def _headers(self) -> dict[str, str]:
        key = self._explicit_key if self._explicit_key is not None else _resolve_api_key()
        if not key:
            raise LLMClientError(
                "No OPENROUTER_API_KEY / OPENAI_API_KEY configured; use `--llm replay` or configure .env"
            )
        return {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": settings.public_base_url,
            "X-Title": "AuditGuard AML Workbench",
        }

    async def _post_with_retries(self, payload: dict[str, Any], model: str) -> ChatResponse:
        headers = self._headers()
        url = f"{self.base_url}/chat/completions"
        last_exc: Optional[Exception] = None
        drop_temp = False
        async with httpx.AsyncClient(timeout=self.timeout_s, transport=self._transport) as client:
            for attempt in range(self.max_retries + 1):
                req_body = dict(payload)
                if drop_temp:
                    req_body.pop("temperature", None)
                    req_body.pop("reasoning", None)
                t0 = time.perf_counter()
                try:
                    resp = await client.post(url, headers=headers, json=req_body)
                    latency = time.perf_counter() - t0
                    if _should_strip_temp(resp, drop_temp, attempt < self.max_retries):
                        drop_temp = True
                        continue
                    if resp.status_code in RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                        await asyncio.sleep(self.backoff_base_s * (2**attempt))
                        continue
                    resp.raise_for_status()
                    return _parse_chat_response(resp.json(), model, latency)
                except (httpx.TransportError, httpx.TimeoutException) as exc:
                    last_exc = exc
                    if attempt < self.max_retries:
                        await asyncio.sleep(self.backoff_base_s * (2**attempt))
                        continue
                except httpx.HTTPStatusError as exc:
                    raise LLMClientError(
                        f"LLM HTTP {exc.response.status_code} for model={model}: {exc.response.text[:300]}"
                    ) from exc
        raise LLMClientError(f"LLM transport failed after {self.max_retries + 1} attempts: {last_exc}") from last_exc

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
        policy = get_policy()
        default_spec = policy.model_for("c1_investigator")
        chosen_model = model or default_spec.model_id
        norm_temp = _norm_temperature(temperature if temperature is not None else default_spec.temperature)
        chosen_max_tokens = max_tokens if max_tokens is not None else default_spec.max_tokens

        envelope = canonical_request_envelope(
            model=chosen_model,
            messages=messages,
            tools=tools,
            temperature=norm_temp,
            max_tokens=chosen_max_tokens,
            response_format=response_format,
            seed=seed,
        )
        cassette_key = compute_cassette_key(envelope)
        started = time.perf_counter()
        try:
            response = await self._chat_once(envelope, cassette_key, chosen_model, messages, tools, norm_temp,
                                             chosen_max_tokens, response_format, seed)
        except Exception:
            LLM_CALLS_TOTAL.labels(model=chosen_model, mode=self.mode, status="error").inc()
            raise
        _record_llm_metrics(chosen_model, self.mode, response, time.perf_counter() - started)
        return response

    async def _chat_once(
        self,
        envelope: dict[str, Any],
        cassette_key: str,
        chosen_model: str,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]],
        norm_temp: Optional[Decimal],
        chosen_max_tokens: int,
        response_format: Optional[dict[str, Any]],
        seed: Optional[int],
    ) -> ChatResponse:
        if self.mode == "replay":
            replayed = await self.store.lookup(cassette_key)
            await self.store.write_transcript(cassette_key, envelope, replayed)
            return replayed

        payload = _wire_payload(
            model=chosen_model,
            messages=messages,
            tools=tools,
            temperature=norm_temp,
            max_tokens=chosen_max_tokens,
            response_format=response_format,
            seed=seed,
        )
        response = await self._post_with_retries(payload, chosen_model)
        if self.mode == "record":
            await self.store.record_cassette(cassette_key, envelope, response)
        await self.store.write_transcript(cassette_key, envelope, response)
        return response
