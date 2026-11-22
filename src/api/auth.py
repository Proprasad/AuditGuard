"""
JWT Authentication & Role-Based Analyst Context (Zero External C-Crypto Dependencies)
Implements RFC 7519 HS256 JWT signing & verification using Python stdlib (`hmac`, `hashlib`, `base64`).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Optional

from fastapi import Header, HTTPException

from src.config import get_api_secret, settings


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def create_jwt_token(subject: str, role: str = "tier2_analyst", expires_in_seconds: int = 86400) -> str:
    """Issue a signed HS256 Bearer JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + expires_in_seconds,
        "iss": "auditguard-api",
    }
    signing_input = f"{_b64url_encode(json.dumps(header).encode())}.{_b64url_encode(json.dumps(payload).encode())}"
    secret = get_api_secret().encode()
    sig = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def verify_jwt_token(token: str) -> dict[str, Any]:
    """Verify signature and expiration of an HS256 JWT token."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT")
    signing_input = f"{parts[0]}.{parts[1]}"
    secret = get_api_secret().encode()
    expected_sig = _b64url_encode(hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(parts[2], expected_sig):
        raise ValueError("Invalid JWT signature")

    payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("JWT expired")
    return payload


async def get_analyst_principal(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    """
    FastAPI dependency:
    - If an Authorization Bearer header is provided, strictly validates it (401 on invalid/expired).
    - If omitted: permits `dev_analyst` when `AUTH_REQUIRED=false` (local dev convenience),
      or raises `401 UNAUTHORIZED` when `AUTH_REQUIRED=true`.
    """
    if authorization:
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="UNAUTHORIZED: Invalid Authorization header scheme")
        raw_token = authorization.split(" ", 1)[1].strip()
        try:
            return verify_jwt_token(raw_token)
        except Exception as exc:
            raise HTTPException(status_code=401, detail=f"UNAUTHORIZED: {exc}") from exc

    if settings.auth_required:
        raise HTTPException(status_code=401, detail="UNAUTHORIZED: Bearer JWT required")

    return {"sub": "analyst_local", "role": "tier2_analyst"}
