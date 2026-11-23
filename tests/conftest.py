"""
Shared pytest fixtures.

Every test gets its own throw-away SQLite file (`tmp_path/test_auditguard.db`) seeded with the clean
dev fixtures. The real `data/auditguard.db` is never opened by the test-suite; a session-level guard
fails the run if its modification time changes.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

OPERATIONAL_DB = (Path(__file__).resolve().parents[1] / "data" / "auditguard.db").resolve()
# Recorded when conftest is imported - i.e. BEFORE test-module collection imports the application.
_OPERATIONAL_DB_MTIME_AT_START = OPERATIONAL_DB.stat().st_mtime_ns if OPERATIONAL_DB.exists() else None


TEST_ENV = {
    "ANALYST_PASSWORD": "analyst-test-pw-0001",
    "REVIEWER_PASSWORD": "reviewer-test-pw-0002",
    "ADMIN_PASSWORD": "admin-test-pw-0003",
    "PASSWORD_HASH_ITERATIONS": "1000",
    "LLM_ENABLED": "false",
}
USERS = {
    "analyst": ("analyst", "ANALYST_PASSWORD"),
    "senior_reviewer": ("reviewer", "REVIEWER_PASSWORD"),
    "admin": ("admin", "ADMIN_PASSWORD"),
}


def _reset_process_singletons() -> None:
    from src.agent.llm_client import reset_dotenv_cache
    from src.memory.store import memory_store

    memory_store.reset_in_memory_cache()
    reset_dotenv_cache()
    try:
        from src.api.ratelimit import reset_limiters

        reset_limiters()
    except ImportError:  # api not importable in some unit-test contexts
        pass


@pytest.fixture(scope="session", autouse=True)
def _operational_db_untouched() -> Iterator[None]:
    before = _OPERATIONAL_DB_MTIME_AT_START
    yield
    after = OPERATIONAL_DB.stat().st_mtime_ns if OPERATIONAL_DB.exists() else None
    assert before == after, "test-suite modified data/auditguard.db (isolation breach)"


@pytest.fixture(autouse=True)
def isolated_operational_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    db_path = tmp_path / "test_auditguard.db"
    monkeypatch.setenv("SQLITE_DB_PATH", str(db_path))
    from src.db import database

    database.reset_db_init()
    assert database.get_sqlite_path().resolve() != OPERATIONAL_DB
    for key, value in TEST_ENV.items():
        monkeypatch.setenv(key, value)
    from src.config import settings

    monkeypatch.setattr(settings, "auth_required", True)
    database.init_db(force=True)
    database.seed_operational_db()
    _reset_process_singletons()
    yield db_path
    _reset_process_singletons()


@pytest.fixture
def client(isolated_operational_db: Path) -> Iterator["TestClient"]:  # noqa: F821
    """TestClient that runs the app lifespan (schema + seeded users) against the isolated DB."""
    from fastapi.testclient import TestClient

    from src.api.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth(client):  # noqa: ANN001
    """auth('analyst'|'senior_reviewer'|'admin') -> Authorization header dict via the real login endpoint."""

    def _login(role: str = "analyst") -> dict[str, str]:
        username, key = USERS[role]
        resp = client.post("/api/v1/auth/token", json={"username": username, "password": TEST_ENV[key]})
        assert resp.status_code == 200, resp.text
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    return _login
