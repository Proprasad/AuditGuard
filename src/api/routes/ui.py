"""UI, auth-token/logout and health/metrics routes."""

from __future__ import annotations

import asyncio
import hmac
import logging
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from src.api.auth import Principal, create_jwt_token, revoke_jwt_token, verify_jwt_token
from src.api.deps import ANALYST, STATIC_DIR, TokenRequest
from src.api.ratelimit import enforce_login_limit
from src.api.users import authenticate
from src.config import settings
from src.db.database import init_db, utc_now_iso

logger = logging.getLogger("auditguard.api")
router = APIRouter()
_LOCAL_SCRAPER_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def _read_workbench_html() -> Optional[str]:
    ui_file = STATIC_DIR / "index.html"
    return ui_file.read_text(encoding="utf-8") if ui_file.exists() else None


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def analyst_workbench() -> HTMLResponse:
    content = await asyncio.to_thread(_read_workbench_html)
    if content is not None:
        return HTMLResponse(content, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
    return HTMLResponse("<h1>AuditGuard API Running</h1><p>Visit <a href='/api/docs'>/api/docs</a></p>")


@router.post("/api/v1/auth/token")
async def issue_token(req: TokenRequest, request: Request) -> dict[str, str]:
    enforce_login_limit(request)
    role = await asyncio.to_thread(authenticate, req.username, req.password)
    if role is None:
        raise HTTPException(status_code=401, detail="UNAUTHORIZED: invalid credentials")
    return {
        "access_token": create_jwt_token(subject=req.username, role=role),
        "token_type": "bearer",
        "role": role,
    }


@router.post("/api/v1/auth/logout")
async def logout_token(principal: Principal = ANALYST) -> dict[str, str]:
    await asyncio.to_thread(revoke_jwt_token, principal.jti, principal.sub, principal.exp)
    return {"status": "revoked", "sub": principal.sub}


@router.get("/health")
async def health() -> dict[str, Any]:
    db_path = await asyncio.to_thread(init_db)
    return {
        "status": "healthy",
        "service": "auditguard-api",
        "version": "1.0.0",
        "database": str(db_path.name),
        "timestamp": utc_now_iso(),
    }


def _metrics_authorized(request: Request, authorization: Optional[str]) -> bool:
    configured = settings.metrics_token.get_secret_value().strip() if settings.metrics_token else ""
    has_bearer = bool(authorization and authorization.lower().startswith("bearer "))
    bearer = authorization.split(" ", 1)[1].strip() if (authorization and has_bearer) else ""
    if configured:
        if bearer and hmac.compare_digest(bearer, configured):
            return True
    else:
        host = request.client.host if request.client else ""
        if host in _LOCAL_SCRAPER_HOSTS or host.startswith(("172.", "192.168.", "10.")):
            return True
    if bearer:
        try:
            verify_jwt_token(bearer)
            return True
        except ValueError:
            return False
    return False


@router.get("/metrics")
async def metrics(request: Request, authorization: Optional[str] = Header(default=None)) -> Response:
    if not await asyncio.to_thread(_metrics_authorized, request, authorization):
        raise HTTPException(status_code=401, detail="UNAUTHORIZED: metrics access denied")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
