"""
Request correlation id (audit AG-09).

One id per API request, carried in a contextvar so it follows the request into background investigation tasks,
`asyncio.to_thread` workers, durable SSE events, Loki records, error responses and MCP tool calls (`meta`).
Clients may supply `X-Correlation-ID`; anything that is not 8-64 safe characters is replaced, so the value can
never inject headers or log fields.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
import re
import uuid

CORRELATION_HEADER = "X-Correlation-ID"
_VALID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_CURRENT: ContextVar[str] = ContextVar("auditguard_correlation_id", default="")


def new_correlation_id() -> str:
    return uuid.uuid4().hex[:12]


def current_correlation_id() -> str:
    """The id bound to this request or task, or `""` outside any request."""
    return _CURRENT.get()


def bind_correlation_id(candidate: str | None) -> tuple[str, Token[str]]:
    """Bind `candidate` if it is well formed, else a fresh id; returns the id and a reset token."""
    cid = candidate if candidate and _VALID.match(candidate) else new_correlation_id()
    return cid, _CURRENT.set(cid)


def reset_correlation_id(token: Token[str]) -> None:
    _CURRENT.reset(token)
