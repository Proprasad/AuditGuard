"""In-memory sliding-window rate limiting (per client IP, per limiter). Exceeding the limit returns HTTP 429."""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable

from fastapi import HTTPException, Request

from src.config import settings


class SlidingWindowLimiter:
    def __init__(self, limit_getter: Callable[[], int], window_seconds: float = 60.0) -> None:
        self._limit_getter = limit_getter
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self._window:
                hits.popleft()
            if len(hits) >= self._limit_getter():
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


login_limiter = SlidingWindowLimiter(lambda: settings.auth_rate_limit_per_min)
api_limiter = SlidingWindowLimiter(lambda: settings.api_rate_limit_per_min)


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def rate_limit_api(request: Request) -> None:
    if not api_limiter.allow(_client(request)):
        raise HTTPException(status_code=429, detail="RATE_LIMITED", headers={"Retry-After": "60"})


def enforce_login_limit(request: Request) -> None:
    if not login_limiter.allow(_client(request)):
        raise HTTPException(status_code=429, detail="RATE_LIMITED: too many login attempts", headers={"Retry-After": "60"})


def reset_limiters() -> None:
    login_limiter.reset()
    api_limiter.reset()
