"""
JWT (HS256, stdlib only) with issuer/audience/expiry/role/jti validation, logout revocation, and RBAC dependencies.
`AUTH_REQUIRED=true` by default: every protected route needs a valid Bearer token and a sufficient role.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Optional

from fastapi import Depends, Header, HTTPException

from src.api.users import ROLE_RANK, ROLES
from src.config import get_api_secret, settings
from src.db.database import get_db, get_ro_db, init_db, utc_now_iso

ISSUER = "auditguard-api"
AUDIENCE = "auditguard-api-clients"
TOKEN_TTL_SECONDS = 3600


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _sign(signing_input: str) -> str:
    return _b64url_encode(hmac.new(get_api_secret().encode(), signing_input.encode("ascii"), hashlib.sha256).digest())


def create_jwt_token(subject: str, role: str, expires_in_seconds: int = TOKEN_TTL_SECONDS) -> str:
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}")
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "role": role,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + expires_in_seconds,
        "iss": ISSUER,
        "aud": AUDIENCE,
    }
    signing_input = f"{_b64url_encode(json.dumps(header).encode())}.{_b64url_encode(json.dumps(payload).encode())}"
    return f"{signing_input}.{_sign(signing_input)}"


def is_token_revoked(jti: str) -> bool:
    if not jti:
        return False
    init_db()
    with get_ro_db() as conn:
        row = conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone()
    return row is not None


def revoke_jwt_token(jti: str, actor: str, expires_at: int) -> None:
    if not jti:
        return
    init_db()
    now_epoch = int(time.time())
    with get_db() as conn:
        conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now_epoch,))
        conn.execute(
            "INSERT OR REPLACE INTO revoked_tokens (jti, revoked_by, expires_at, revoked_at) VALUES (?, ?, ?, ?)",
            (jti, actor, expires_at, utc_now_iso()),
        )


def verify_jwt_token(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT")
    if json.loads(_b64url_decode(parts[0])).get("alg") != "HS256":
        raise ValueError("Unsupported JWT algorithm")
    if not hmac.compare_digest(parts[2], _sign(f"{parts[0]}.{parts[1]}")):
        raise ValueError("Invalid JWT signature")
    payload = json.loads(_b64url_decode(parts[1]))
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("JWT expired")
    if payload.get("iss") != ISSUER or payload.get("aud") != AUDIENCE:
        raise ValueError("JWT issuer/audience mismatch")
    if payload.get("role") not in ROLES or not payload.get("sub"):
        raise ValueError("JWT missing subject/role")
    jti = str(payload.get("jti", ""))
    if jti and is_token_revoked(jti):
        raise ValueError("JWT has been revoked")
    return dict(payload)


@dataclass(frozen=True)
class Principal:
    sub: str
    role: str
    jti: str = ""
    exp: int = 0

    def at_least(self, minimum: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[minimum]


async def get_principal(authorization: Optional[str] = Header(default=None)) -> Principal:
    if authorization:
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="UNAUTHORIZED: invalid Authorization scheme")
        try:
            claims = verify_jwt_token(authorization.split(" ", 1)[1].strip())
        except (ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=401, detail=f"UNAUTHORIZED: {exc}") from exc
        return Principal(
            sub=str(claims["sub"]),
            role=str(claims["role"]),
            jti=str(claims.get("jti", "")),
            exp=int(claims.get("exp", 0)),
        )
    if settings.auth_required:
        raise HTTPException(status_code=401, detail="UNAUTHORIZED: Bearer token required")
    return Principal(sub="dev_user", role="admin")


def require_role(minimum: str) -> Callable[..., Any]:
    async def dependency(principal: Principal = Depends(get_principal)) -> Principal:  # noqa: B008
        if not principal.at_least(minimum):
            raise HTTPException(status_code=403, detail=f"FORBIDDEN: role '{minimum}' or higher required")
        return principal

    return dependency
