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


def _reset_process_singletons() -> None:
    from src.agent import llm_client
    from src.mcp_servers import bank_records, case_actions
    from src.memory.store import memory_store

    bank_records._db_seeded = False
    case_actions._worksheets.clear()
    llm_client._runtime_enabled_override = None
    llm_client._runtime_model_override = None
    llm_client._runtime_strong_model_override = None
    memory_store._entity_profiles.clear()
    memory_store._case_episodes.clear()
    memory_store._reflexion_playbook.clear()
    memory_store._playbook_frozen = False
    try:
        from src.api import main as api_main

        getattr(api_main, "_threads", {}).clear()
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

    database._initialized_paths.clear()
    assert database.get_sqlite_path().resolve() != OPERATIONAL_DB
    database.init_db(force=True)
    database.seed_operational_db()
    _reset_process_singletons()
    yield db_path
    _reset_process_singletons()
