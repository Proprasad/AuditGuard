"""
AuditGuard - Core Configuration & Settings
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal, Optional

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # LLM / OpenRouter (Toggleable via LLM_ENABLED=true / false)
    llm_enabled: bool = False
    openrouter_api_key: SecretStr = Field(default=SecretStr("sk-placeholder"))
    openai_api_key: SecretStr = Field(default=SecretStr("sk-placeholder"))
    openai_base_url: str = "https://openrouter.ai/api/v1"
    openai_model: str = "openai/gpt-5-mini"
    openai_strong_model: str = "openai/gpt-5-mini"

    # Persistence
    sqlite_db_path: str = "data/auditguard.db"
    use_postgres: bool = False
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "auditguard"
    postgres_user: str = "auditguard"
    postgres_password: SecretStr = Field(default=SecretStr("auditguard_secret"))
    database_url: str = "postgresql+asyncpg://auditguard:auditguard_secret@localhost:5432/auditguard"

    # Qdrant
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_collection: str = "compliance_kb"

    # Langfuse
    langfuse_host: str = "http://localhost:3000"
    langfuse_public_key: str = "pk-lf-placeholder"
    langfuse_secret_key: SecretStr = Field(default=SecretStr("sk-lf-placeholder"))

    # API & Auth
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_secret_key: SecretStr = Field(default=SecretStr("auditguard-dev-jwt-secret-change-in-prod"))
    auth_required: bool = False

    # MCP
    mcp_transport: Literal["inprocess", "http"] = "inprocess"
    mcp_compliance_kb_port: int = 8010
    mcp_graph_engine_port: int = 8011
    mcp_bank_records_port: int = 8012
    mcp_case_actions_port: int = 8013

    # Security & Budgets
    hmac_secret: SecretStr = Field(default=SecretStr("auditguard-dev-hmac-secret-change-in-prod"))
    max_tool_budget_usd: float = 0.15
    max_tool_calls: int = 15
    max_replans: int = 3

    # Graph engine defaults (policy-bounded: window [1,30], hops [2,5], tol [0.01,0.25])
    graph_max_hops: int = 3
    graph_time_window_days: int = 7
    graph_amount_tolerance: float = 0.10

    # Memory
    short_term_window_messages: int = 12

    # Environment
    environment: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"

    @property
    def is_dev(self) -> bool:
        return self.environment == "development"

    @property
    def sync_database_url(self) -> str:
        return self.database_url.replace("+asyncpg", "")

    @property
    def resolved_llm_api_key(self) -> str:
        or_key = self.openrouter_api_key.get_secret_value().strip()
        if or_key and not or_key.endswith("placeholder"):
            return or_key
        oa_key = self.openai_api_key.get_secret_value().strip()
        if oa_key and not oa_key.endswith("placeholder"):
            return oa_key
        return ""


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
