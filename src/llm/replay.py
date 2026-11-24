"""
Append-only cassette replay store and per-run `runs/<run_id>/transcripts.jsonl` logger.

Modes:
  * `live`   : call provider; write transcript to `runs/<run_id>/transcripts.jsonl`.
  * `record` : call provider; append response to `cassette_path` AND write transcript.
  * `replay` : serve strictly from `cassette_path` by canonical SHA-256 request key;
               raise `CassetteMissError` immediately on a miss (zero network calls).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
import threading
from typing import Any, Literal, Optional
from uuid import uuid4

from src.core.canonical import canonical_sha256, dumps_json, loads_json
from src.llm.schemas import ChatResponse, TranscriptEntry

LLMMode = Literal["live", "record", "replay"]


class CassetteMissError(KeyError):
    """Raised when `mode='replay'` encounters an unrecorded canonical request hash."""


def canonical_request_envelope(
    *,
    model: str,
    messages: list[dict[str, Any]],
    tools: Optional[list[dict[str, Any]]] = None,
    temperature: Optional[Decimal] = None,
    max_tokens: Optional[int] = None,
    response_format: Optional[dict[str, Any]] = None,
    seed: Optional[int] = None,
) -> dict[str, Any]:
    """Build deterministic request representation hashed to compute `cassette_key`."""
    return {
        "model": model,
        "messages": messages,
        "tools": tools or [],
        "temperature": str(temperature) if temperature is not None else None,
        "max_tokens": max_tokens,
        "response_format": response_format,
        "seed": seed,
    }


def compute_cassette_key(envelope: Mapping[str, Any]) -> str:
    """Return canonical SHA-256 digest of a normalized LLM request envelope."""
    return canonical_sha256(dict(envelope))


class CassetteStore:
    """Thread-safe JSONL cassette store and run transcript writer."""

    def __init__(
        self,
        *,
        mode: LLMMode = "live",
        cassette_path: Optional[Path] = None,
        run_id: Optional[str] = None,
        runs_dir: Path = Path("runs"),
    ) -> None:
        self.mode: LLMMode = mode
        self.run_id = run_id or f"run_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid4().hex[:8]}"
        self.runs_dir = runs_dir
        self.transcript_path = self.runs_dir / self.run_id / "transcripts.jsonl"
        self.cassette_path = cassette_path
        self._lock = threading.Lock()
        self._index: dict[str, list[dict[str, Any]]] = {}
        self._cursors: dict[str, int] = {}
        if self.cassette_path is not None and self.cassette_path.exists():
            self._load_cassette_sync(self.cassette_path)

    def _load_cassette_sync(self, path: Path) -> None:
        with self._lock:
            self._index.clear()
            for raw_line in path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                record = loads_json(line)
                key = str(record["cassette_key"])
                self._index.setdefault(key, []).append(dict(record["response"]))

    def lookup_sync(self, cassette_key: str) -> ChatResponse:
        with self._lock:
            entries = self._index.get(cassette_key)
            if not entries:
                raise CassetteMissError(
                    f"Cassette miss for key={cassette_key} in {self.cassette_path!s}; "
                    "re-record with `--llm record` before running in replay mode."
                )
            idx = self._cursors.get(cassette_key, 0)
            chosen = entries[min(idx, len(entries) - 1)]
            self._cursors[cassette_key] = idx + 1
        resp = ChatResponse.model_validate(chosen)
        return resp.model_copy(update={"from_cassette": True, "latency_s": 0.0})

    async def lookup(self, cassette_key: str) -> ChatResponse:
        return await asyncio.to_thread(self.lookup_sync, cassette_key)

    def _append_jsonl_sync(self, path: Path, payload: Mapping[str, Any]) -> None:
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(dumps_json(dict(payload)) + "\n")

    def record_cassette_sync(
        self, cassette_key: str, request_envelope: Mapping[str, Any], response: ChatResponse
    ) -> None:
        if self.cassette_path is None:
            raise ValueError("cassette_path is required when LLMClient runs in mode='record'")
        serialized = response.model_dump(mode="json")
        record = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "cassette_key": cassette_key,
            "request": dict(request_envelope),
            "response": serialized,
        }
        self._append_jsonl_sync(self.cassette_path, record)
        with self._lock:
            self._index.setdefault(cassette_key, []).append(serialized)

    async def record_cassette(
        self, cassette_key: str, request_envelope: Mapping[str, Any], response: ChatResponse
    ) -> None:
        await asyncio.to_thread(self.record_cassette_sync, cassette_key, request_envelope, response)

    def write_transcript_sync(
        self, cassette_key: str, request_envelope: Mapping[str, Any], response: ChatResponse
    ) -> None:
        entry = TranscriptEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            run_id=self.run_id,
            mode=self.mode,
            cassette_key=cassette_key,
            model=response.model,
            request=dict(request_envelope),
            response=response.model_dump(mode="json"),
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
            total_tokens=response.usage.total_tokens,
            cost_usd=str(response.cost_usd),
            latency_s=round(response.latency_s, 6),
            from_cassette=response.from_cassette,
        )
        self._append_jsonl_sync(self.transcript_path, entry.model_dump(mode="json"))

    async def write_transcript(
        self, cassette_key: str, request_envelope: Mapping[str, Any], response: ChatResponse
    ) -> None:
        await asyncio.to_thread(self.write_transcript_sync, cassette_key, request_envelope, response)
