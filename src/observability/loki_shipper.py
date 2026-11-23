"""
Lightweight Non-Blocking Grafana Loki Log Shipper (`src/observability/loki_shipper.py`)

Streams structured JSON logs from AuditGuard (Agent Investigation Flow, FastMCP Tool Calls,
Cryptographic Audit Trail, and FastAPI HTTP Requests) directly to Grafana Loki (`/loki/api/v1/push`).

Key Design Properties:
  - Uses `service_name="auditguard"` so Grafana 13 Drilldown -> Logs & Explore -> Loki
    auto-discover the service immediately with zero manual setup.
  - Non-blocking daemon ThreadPoolExecutor (1.5s timeout): if Loki is offline, drops silently
    with zero latency or error impact on investigations.
  - Automatically disabled during `pytest` runs (`PYTEST_CURRENT_TEST`).
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from src.observability.redaction import redact_for_logs, redact_text

logger = logging.getLogger("auditguard.loki")
_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="loki-shipper")


def _loki_push_url() -> str:
    base = os.getenv("LOKI_URL", "http://localhost:3100").rstrip("/")
    return f"{base}/loki/api/v1/push"


def _post_to_loki(labels: dict[str, str], line_str: str, ts_ns: int) -> None:
    payload = {
        "streams": [
            {
                "stream": labels,
                "values": [[str(ts_ns), line_str]],
            }
        ]
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310 - scheme validated below before any request is made
        _loki_push_url(),
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if urllib.parse.urlparse(req.full_url).scheme not in ("http", "https"):
        logger.debug("loki push skipped: unsupported URL scheme")
        return
    try:
        with urllib.request.urlopen(req, timeout=1.5):  # noqa: S310 - scheme validated above
            pass
    except (
        OSError,
        ValueError,
    ) as exc:  # Loki being down must never break the app, but is visible at debug level
        logger.debug("loki push failed: %s", exc)


def emit_loki_log(
    stream_type: str,
    event: str,
    message: str,
    level: str = "INFO",
    extra: Optional[dict[str, Any]] = None,
) -> None:
    """Fire-and-forget structured log push to Grafana Loki."""
    if os.getenv("PYTEST_CURRENT_TEST"):
        return

    ts_ns = time.time_ns()
    labels = {
        "service_name": "auditguard",
        "app": "auditguard",
        "stream_type": stream_type,
        "level": level.upper(),
    }
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level.upper(),
        "stream_type": stream_type,
        "event": event,
        "message": redact_text(message),
        **redact_for_logs(extra or {}),
    }
    line_str = json.dumps(record, default=str)
    try:
        _EXECUTOR.submit(_post_to_loki, labels, line_str, ts_ns)
    except RuntimeError as exc:  # executor already shut down (interpreter exit)
        logger.debug("loki submit failed: %s", exc)
