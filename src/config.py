"""
AuditGuard - validated startup configuration.

* `Settings`   : environment / `.env` driven infrastructure + security settings (no secret defaults).
* `get_policy` : `PolicyConfig` loaded from `config/models.yaml` with env overrides (budgets, bounds, models).
* `validate_startup` : fail-fast checks executed in the FastAPI lifespan; outside APP_ENV=development|test
  insecure/missing secrets or `AUTH_REQUIRED=false` abort startup.
"""
from __future__ import annotations

import os
import secrets as _secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from dotenv import dotenv_values
from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.core.policy import PolicyConfig, PolicyConfigError, load_policy

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEV_ENVS = ("development", "test")
INSECURE_MARKERS = ("change-in-prod", "changeme", "change_me", "auditguard-dev", "placeholder", "password", "auditguard_secret")


class StartupConfigError(RuntimeError):
    """Raised when the process must refuse to start (insecure or invalid configuration)."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    app_env: Literal["development", "test", "staging", "production"] = Field(
        default="development", validation_alias=AliasChoices("APP_ENV", "ENVIRONMENT")
    )
    log_level: str = "INFO"

    # LLM / OpenRouter (model slugs, temperatures and budgets live in config/models.yaml)
    llm_enabled: bool = False
    openrouter_api_key: Optional[SecretStr] = None
    openai_api_key: Optional[SecretStr] = None
    openai_base_url: str = "https://openrouter.ai/api/v1"

    # Persistence
    sqlite_db_path: str = "data/auditguard.db"
    use_postgres: bool = False
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "auditguard"
    postgres_user: str = "auditguard"
    postgres_password: Optional[SecretStr] = None

    # Vector store / observability
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_collection: str = "compliance_kb"
    langfuse_host: str = "http://localhost:3000"

    # API & auth
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_secret_key: Optional[SecretStr] = None
    hmac_secret: Optional[SecretStr] = None
    auth_required: bool = True
    cors_origins: str = "http://127.0.0.1:8000,http://localhost:8000,http://127.0.0.1:8001,http://localhost:8001"
    api_rate_limit_per_min: int = 600
    auth_rate_limit_per_min: int = 10

    # MCP
    mcp_transport: Literal["inprocess", "http"] = "inprocess"
    mcp_host: str = "localhost"
    mcp_timeout_s: float = 30.0
    mcp_compliance_kb_port: int = 8010
    mcp_graph_engine_port: int = 8011
    mcp_bank_records_port: int = 8012
    mcp_case_actions_port: int = 8013

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip() and o.strip() != "*"]

    @property
    def environment(self) -> str:
        return self.app_env

    @property
    def is_dev(self) -> bool:
        return self.app_env in DEV_ENVS

    @property
    def sync_database_url(self) -> str:
        pw = self.postgres_password.get_secret_value() if self.postgres_password else ""
        return f"postgresql://{self.postgres_user}:{pw}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"

    @property
    def resolved_llm_api_key(self) -> str:
        for candidate in (self.openrouter_api_key, self.openai_api_key):
            raw = candidate.get_secret_value().strip() if candidate else ""
            if raw and not raw.endswith("placeholder"):
                return raw
        return ""


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

_ephemeral_secrets: dict[str, str] = {}


def _resolve_secret(name: str, value: Optional[SecretStr]) -> str:
    raw = value.get_secret_value().strip() if value else ""
    if raw:
        return raw
    if settings.is_dev:
        return _ephemeral_secrets.setdefault(name, _secrets.token_urlsafe(48))
    raise StartupConfigError(f"{name} must be provided via environment/.env when APP_ENV={settings.app_env}")


def get_api_secret() -> str:
    return _resolve_secret("API_SECRET_KEY", settings.api_secret_key)


def get_hmac_secret() -> bytes:
    return _resolve_secret("HMAC_SECRET", settings.hmac_secret).encode("utf-8")


def _insecure(raw: str) -> bool:
    lowered = raw.lower()
    return len(raw) < 32 or any(marker in lowered for marker in INSECURE_MARKERS)


def validate_startup(cfg: Optional[Settings] = None) -> list[str]:
    """Fail-fast validation. Returns warnings (dev) or raises StartupConfigError (non-dev) on violations."""
    cfg = cfg or settings
    problems: list[str] = []
    for name, secret in (("API_SECRET_KEY", cfg.api_secret_key), ("HMAC_SECRET", cfg.hmac_secret)):
        raw = secret.get_secret_value().strip() if secret else ""
        if not raw or _insecure(raw):
            problems.append(f"{name} is missing or insecure (>=32 random chars required)")
    if not cfg.auth_required:
        problems.append("AUTH_REQUIRED=false is not permitted")
    if cfg.use_postgres and (not cfg.postgres_password or _insecure(cfg.postgres_password.get_secret_value())):
        problems.append("POSTGRES_PASSWORD is missing or insecure while USE_POSTGRES=true")
    if problems and not cfg.is_dev:
        raise StartupConfigError(f"Refusing to start with APP_ENV={cfg.app_env}: " + "; ".join(problems))
    return problems if cfg.is_dev else []


def _env_mapping() -> dict[str, str]:
    merged: dict[str, str] = {k: v for k, v in dotenv_values(PROJECT_ROOT / ".env").items() if v is not None}
    merged.update(os.environ)
    return merged


def env_mapping() -> dict[str, str]:
    return _env_mapping()


def _policy_path() -> Path:
    return Path(os.environ.get("POLICY_CONFIG_PATH") or PROJECT_ROOT / "config" / "models.yaml")


@lru_cache
def get_policy() -> PolicyConfig:
    return load_policy(_policy_path(), _env_mapping())


def reload_policy() -> PolicyConfig:
    get_policy.cache_clear()
    return get_policy()


__all__ = [
    "PolicyConfig", "PolicyConfigError", "Settings", "StartupConfigError", "get_api_secret", "get_hmac_secret",
    "get_policy", "get_settings", "reload_policy", "settings", "validate_startup",
]
