"""Local user store: PBKDF2-HMAC-SHA256 password hashes, three roles, env-seeded accounts."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from collections.abc import Mapping
from typing import Optional

from src.db.database import get_db, init_db, utc_now_iso

logger = logging.getLogger("auditguard.users")

ROLES = ("analyst", "senior_reviewer", "admin")
ROLE_RANK = {"analyst": 1, "senior_reviewer": 2, "admin": 3}
# (username, env var holding the password, role)
SEEDED_ACCOUNTS = (
    ("analyst", "ANALYST_PASSWORD", "analyst"),
    ("reviewer", "REVIEWER_PASSWORD", "senior_reviewer"),
    ("admin", "ADMIN_PASSWORD", "admin"),
)
_DUMMY_HASH = ""


def _iterations() -> int:
    return int(os.environ.get("PASSWORD_HASH_ITERATIONS", "200000"))


def hash_password(password: str, salt: Optional[bytes] = None, iterations: Optional[int] = None) -> str:
    salt = salt or os.urandom(16)
    rounds = iterations or _iterations()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return f"pbkdf2_sha256${rounds}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, rounds, salt_hex, digest_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate.hex(), digest_hex)


def ensure_seed_users(environ: Mapping[str, str]) -> list[str]:
    """Upsert the seeded accounts so the environment/.env stays the source of truth. Missing password => no account."""
    init_db()
    seeded: list[str] = []
    with get_db() as conn:
        for username, env_key, role in SEEDED_ACCOUNTS:
            password = environ.get(env_key, "")
            if not password:
                logger.warning("%s not set - account %r is disabled (run scripts/init_env.py)", env_key, username)
                continue
            row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
            if row is None:
                conn.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                             (username, hash_password(password), role, utc_now_iso()))
            elif not verify_password(password, row["password_hash"]):
                conn.execute("UPDATE users SET password_hash = ?, role = ? WHERE username = ?", (hash_password(password), role, username))
            seeded.append(username)
    return seeded


def authenticate(username: str, password: str) -> Optional[str]:
    """Return the user's role on success, else None (constant-ish time for unknown users)."""
    global _DUMMY_HASH
    init_db()
    with get_db() as conn:
        row = conn.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        _DUMMY_HASH = _DUMMY_HASH or hash_password("dummy-password")
        verify_password(password, _DUMMY_HASH)
        return None
    return str(row["role"]) if verify_password(password, row["password_hash"]) else None
