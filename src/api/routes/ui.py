"""UI, auth-token and health/metrics routes."""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from src.api.auth import create_jwt_token
from src.api.deps import (
    STATIC_DIR, TokenRequest,
)
from src.api.ratelimit import enforce_login_limit
from src.api.users import authenticate
from src.db.database import init_db, utc_now_iso

logger = logging.getLogger("auditguard.api")
router = APIRouter()

# ---------------------------------------------------------------------------
# UI, Auth & Health Routes
# ---------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def analyst_workbench():
    ui_file = STATIC_DIR / "index.html"
    if ui_file.exists():
        return HTMLResponse(ui_file.read_text(encoding="utf-8"),
                            headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
    return HTMLResponse("<h1>AuditGuard API Running</h1><p>Visit <a href='/api/docs'>/api/docs</a></p>")


@router.post("/api/v1/auth/token")
async def issue_token(req: TokenRequest, request: Request):
    enforce_login_limit(request)
    role = await asyncio.to_thread(authenticate, req.username, req.password)
    if role is None:
        raise HTTPException(status_code=401, detail="UNAUTHORIZED: invalid credentials")
    return {"access_token": create_jwt_token(subject=req.username, role=role), "token_type": "bearer", "role": role}


@router.get("/health")
async def health():
    db_path = init_db()
    return {"status": "healthy", "service": "auditguard-api", "version": "1.0.0",
            "database": str(db_path.name), "timestamp": utc_now_iso()}


@router.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


