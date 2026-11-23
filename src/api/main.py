"""
AuditGuard FastAPI application: thin HTTP layer. Business logic lives in `src/api/services/*`; every `/api/v1/*`
route is authenticated (JWT, role-gated), rate limited and returns masked errors with a correlation id.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response

from src.agent.llm_client import close_shared_llm_client, open_shared_llm_client
from src.api.users import ensure_seed_users
from src.config import env_mapping, reload_policy, settings, validate_startup
from src.db.database import init_db
from src.observability.loki_shipper import emit_loki_log

logger = logging.getLogger("auditguard.api")


def _startup_sync() -> None:
    for warning in validate_startup():
        logger.warning("startup warning (dev/test only): %s", warning)
    policy = reload_policy()
    init_db()
    seeded = ensure_seed_users(env_mapping())
    logger.info(
        "PolicyConfig %s loaded (max_tool_calls=%s, max_cost_usd=%s); users=%s",
        policy.config_version,
        policy.budgets.max_tool_calls,
        policy.budgets.max_cost_usd_per_case,
        seeded,
    )


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Fail-fast startup: validated secrets/auth, validated PolicyConfig, initialised schema, shared HTTP client."""
    await asyncio.to_thread(_startup_sync)
    await open_shared_llm_client()
    try:
        yield
    finally:
        await close_shared_llm_client()


app = FastAPI(
    title="AuditGuard API",
    description="Evidence-Grounded AI Investigation System for Ambiguous Fund-Flow Networks",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def loki_http_request_logger(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    t0 = time.perf_counter()
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/api/v1/"):
        ms = round((time.perf_counter() - t0) * 1000, 1)
        emit_loki_log(
            stream_type="http_api",
            event="api_request",
            message=f"{request.method} {path} -> {response.status_code} ({ms}ms)",
            level="WARN" if response.status_code >= 400 else "INFO",
            extra={
                "method": request.method,
                "path": path,
                "status_code": response.status_code,
                "duration_ms": ms,
            },
        )
    return response


@app.exception_handler(Exception)
async def masked_exception_handler(request: Request, _exc: Exception) -> JSONResponse:
    correlation = uuid.uuid4().hex[:12]
    logger.exception("unhandled error path=%s correlation_id=%s", request.url.path, correlation)
    return JSONResponse(status_code=500, content={"detail": "INTERNAL_ERROR", "correlation_id": correlation})


@app.exception_handler(RequestValidationError)
async def validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [{"loc": list(e.get("loc", [])), "msg": str(e.get("msg", ""))} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


from src.api.deps import STATIC_DIR  # noqa: E402
from src.api.routes import data, investigations, ui  # noqa: E402

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
for _router in (ui.router, data.router, investigations.router):
    app.include_router(_router)
