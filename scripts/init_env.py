"""
Bootstrap local secrets into `.env` (never overwrites existing values, never prints secrets).

    python scripts/init_env.py

Generates strong random values for any missing/placeholder secret so the app, docker-compose and
the startup validator (`src.config.validate_startup`) never rely on hardcoded defaults.
"""

from __future__ import annotations

import re
import secrets
from pathlib import Path

ENV_PATH = Path(__file__).resolve().parents[1] / ".env"

GENERATED = {
    "API_SECRET_KEY": lambda: secrets.token_urlsafe(48),
    "HMAC_SECRET": lambda: secrets.token_urlsafe(48),
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(24),
    "NEXTAUTH_SECRET": lambda: secrets.token_urlsafe(32),
    "LANGFUSE_SALT": lambda: secrets.token_urlsafe(24),
    "GRAFANA_ADMIN_PASSWORD": lambda: secrets.token_urlsafe(18),
    "ANALYST_PASSWORD": lambda: secrets.token_urlsafe(18),
    "REVIEWER_PASSWORD": lambda: secrets.token_urlsafe(18),
    "ADMIN_PASSWORD": lambda: secrets.token_urlsafe(18),
    "CHAINLIT_AUTH_SECRET": lambda: secrets.token_urlsafe(48),
}
DEFAULTS = {"APP_ENV": "development"}
PLACEHOLDER = re.compile(r"(change[-_]?me|placeholder|^$)", re.IGNORECASE)


def main() -> None:
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.exists() else []
    current = {}
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            current[key.strip()] = value.strip()
    added: list[str] = []
    for key, make in GENERATED.items():
        if key not in current or PLACEHOLDER.search(current[key]):
            lines = [ln for ln in lines if not ln.startswith(f"{key}=")]
            lines.append(f"{key}={make()}")
            added.append(key)
    for key, value in DEFAULTS.items():
        if key not in current:
            lines.append(f"{key}={value}")
            added.append(key)
    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("generated:", ", ".join(added) if added else "nothing (all secrets already set)")


if __name__ == "__main__":
    main()
