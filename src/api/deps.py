"""Shared FastAPI dependencies and request helpers for the route modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from src.api.auth import require_role
from src.api.ratelimit import rate_limit_api
from src.api.services.threads import thread_view
from src.guardrails.guardrails import apply_input_guardrails
from src.mcp_servers import bank_records
from src.models import Alert, RiskLevel

STATIC_DIR = Path(__file__).resolve().parents[1] / "ui" / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

ANALYST = Depends(require_role("analyst"))
ADMIN = Depends(require_role("admin"))
SENIOR = Depends(require_role("senior_reviewer"))
api_deps = [Depends(rate_limit_api)]


class TokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    password: str


class LlmConfigUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = None
    model: Optional[str] = None
    strong_model: Optional[str] = None


def alert_from_db(alert_id: str) -> Alert:
    """Alerts always come from the trusted operational DB (no client-supplied account/amount, no fallbacks)."""
    rec = bank_records.get_alert_record(alert_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"INVALID_ALERT_ID: alert {alert_id!r} not found")
    return Alert(
        alert_id=rec["alert_id"],
        rule_name=rec["rule_name"],
        root_account=rec["root_account"],
        network_accounts=rec["network_accounts"],
        total_amount_inr=rec["total_amount_inr"],
        risk_level=RiskLevel.HIGH,
    )


def guard_alert_id(alert_id: str) -> None:
    guard = apply_input_guardrails(alert_id)
    if not guard.allowed:
        raise HTTPException(status_code=422, detail=f"GUARDRAIL_BLOCKED: {guard.blocked_reason}")


def require_thread(thread_id: str) -> dict[str, Any]:
    thread = thread_view(thread_id)
    if thread is None:
        raise HTTPException(status_code=404, detail="Thread not found")
    return thread
