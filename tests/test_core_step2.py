"""Step 2 gate: pure core (Decimal, MultiDiGraph, canonical hash), PolicyConfig, BudgetLedger & startup."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest
import yaml

from src.config import PROJECT_ROOT, Settings, StartupConfigError, get_policy, validate_startup
from src.core import graph_math
from src.core.canonical import (
    NumericError,
    TimestampError,
    canonical_json,
    canonical_sha256,
    parse_utc_timestamp,
    to_money,
    to_ratio,
)
from src.core.policy import PolicyConfigError, load_policy

T0 = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)


def _txn(tx_id: str, sender: str, receiver: str, amount: str, minutes: int = 0) -> graph_math.Txn:
    from datetime import timedelta

    return graph_math.Txn(tx_id, sender, receiver, Decimal(amount), T0 + timedelta(minutes=minutes))


def _params(window: int = 7) -> graph_math.GraphParams:
    p = get_policy()
    return graph_math.GraphParams(window, 3, p.graph_bounds.amount_tolerance.default, 1)


# ------------------------------------------------------------------------------------ (a) MultiDiGraph
def test_five_parallel_transfers_preserved_with_exact_decimal_totals() -> None:
    txns = [_txn(f"TXN-A{i}", "A", "B", "1000.10", minutes=i) for i in range(5)] + [
        _txn("TXN-B1", "B", "C", "5000.00", 30)
    ]
    graph = graph_math.build_multigraph(txns, 7, None, 1)
    assert graph.number_of_edges() == 5 + 1  # 5 parallel A->B edges + B->C, none collapsed

    policy = get_policy()
    run = graph_math.find_candidate_paths(txns, "A", _params(), policy.suspicion, policy.graph_limits)
    two_hop = next(p for p in run.paths if p.nodes == ("A", "B", "C"))
    assert two_hop.total_outflow_inr == Decimal("5000.50")  # exact: 5 x 1000.10
    assert two_hop.total_consolidated_inr == Decimal("5000.00")
    assert two_hop.net_difference_inr == Decimal("0.50")
    assert set(two_hop.edge_tx_ids) == {f"TXN-A{i}" for i in range(5)} | {"TXN-B1"}


def test_graph_ids_are_deterministic_sha256_not_random() -> None:
    txns = [_txn("TXN-1", "A", "B", "100.00"), _txn("TXN-2", "B", "C", "90.00", 5)]
    policy = get_policy()
    r1 = graph_math.find_candidate_paths(txns, "A", _params(), policy.suspicion, policy.graph_limits)
    r2 = graph_math.find_candidate_paths(list(reversed(txns)), "A", _params(), policy.suspicion, policy.graph_limits)
    assert r1.calc_id == r2.calc_id and r1.calc_id.startswith("CALC-")
    assert [p.path_id for p in r1.paths] == [p.path_id for p in r2.paths]
    assert all(p.path_id.startswith("PATH-") for p in r1.paths)


# ------------------------------------------------------------------------------------ (b) exact decimals
def test_decimal_exactness_and_float_rejection() -> None:
    assert Decimal("0.10") + Decimal("0.20") == Decimal("0.30")
    assert to_ratio("0.10") + to_ratio("0.20") == Decimal("0.3000")
    assert to_money("1000.105") == Decimal("1000.11")  # ROUND_HALF_UP
    for bad in (0.1, 1.5, True):
        with pytest.raises(NumericError):
            to_money(bad)
    with pytest.raises(NumericError):
        to_money("12.3.4")


def test_canonical_hash_is_representation_invariant() -> None:
    a = {"amount": Decimal("300000.00"), "ids": {"b", "a"}, "when": T0}
    b = {"when": "2026-09-01T10:00:00+00:00", "ids": ["a", "b"], "amount": "300000.00"}
    assert canonical_json(a) == canonical_json(b)
    assert canonical_sha256(a) == canonical_sha256(b)
    assert canonical_sha256({"amount": Decimal("300000.01")}) != canonical_sha256({"amount": Decimal("300000.00")})


def test_malformed_timestamp_raises_instead_of_silent_fallback() -> None:
    with pytest.raises(TimestampError):
        parse_utc_timestamp("not-a-date")
    assert parse_utc_timestamp("2026-09-01T10:00:00").tzinfo is not None


# ------------------------------------------------------------------------------------ (c) PolicyConfig + ledger
def test_policy_loads_models_yaml_and_halts_ledger_at_call_16() -> None:
    policy = get_policy()
    raw = yaml.safe_load((PROJECT_ROOT / "config" / "models.yaml").read_text(encoding="utf-8"))
    assert policy.budgets.max_tool_calls == raw["budgets"]["max_tool_calls"] == 15
    assert policy.budgets.max_cost_usd_per_case == Decimal("0.15")
    assert policy.budgets.max_replans == 3 and policy.budgets.max_critique_retries == 2

    ledger = policy.new_ledger()
    assert all(ledger.try_consume_tool_call().allowed for _ in range(15))
    sixteenth = ledger.try_consume_tool_call()
    assert not sixteenth.allowed and sixteenth.error_code == "BUDGET_EXCEEDED"
    assert ledger.calls_used == 15


def test_ledger_halts_tool_and_llm_calls_at_usd_cap() -> None:
    ledger = get_policy().new_ledger()
    assert ledger.check_llm_allowed().allowed
    ledger.record_llm_usage(1000, 500, Decimal("0.150000"))
    assert not ledger.check_llm_allowed().allowed
    assert not ledger.try_consume_tool_call().allowed


def test_ledger_replan_and_critique_budgets() -> None:
    ledger = get_policy().new_ledger()
    assert [ledger.try_replan().allowed for _ in range(4)] == [True, True, True, False]
    assert [ledger.try_critique_retry().allowed for _ in range(3)] == [True, True, False]


def test_policy_rejects_disallowed_model_and_bad_bounds(tmp_path: Path) -> None:
    base = yaml.safe_load((PROJECT_ROOT / "config" / "models.yaml").read_text(encoding="utf-8"))
    with pytest.raises(PolicyConfigError):
        load_policy(PROJECT_ROOT / "config" / "models.yaml", {"OPENAI_MODEL": "evil/model\nAPI_SECRET_KEY=x"})
    bad = dict(base)
    bad["graph_bounds"] = {**base["graph_bounds"], "max_hops": {"min": 2, "max": 5, "default": 9}}
    f = tmp_path / "bad.yaml"
    f.write_text(yaml.safe_dump(bad), encoding="utf-8")
    with pytest.raises(PolicyConfigError):
        load_policy(f, {})
    with pytest.raises(PolicyConfigError):
        load_policy(tmp_path / "missing.yaml", {})


def test_policy_graph_bounds_validation_uses_yaml_not_literals() -> None:
    policy = get_policy()
    assert policy.validate_graph_params({"time_window_days": 14, "max_hops": 4, "amount_tolerance": "0.15"}) == []
    errors = policy.validate_graph_params({"time_window_days": 365, "max_hops": 6, "amount_tolerance": 0.9})
    assert len(errors) == 3


# ------------------------------------------------------------------------------------ startup validation
def test_startup_refuses_insecure_config_outside_dev() -> None:
    insecure = Settings(
        _env_file=None,
        app_env="production",
        api_secret_key="auditguard-dev-jwt-secret-change-in-prod",
        hmac_secret="short",
        auth_required=False,
    )
    with pytest.raises(StartupConfigError) as exc:
        validate_startup(insecure)
    assert "API_SECRET_KEY" in str(exc.value) and "HMAC_SECRET" in str(exc.value) and "AUTH_REQUIRED" in str(exc.value)

    secure = Settings(
        _env_file=None,
        app_env="production",
        api_secret_key="x" * 48,
        hmac_secret="y" * 48,
        auth_required=True,
    )
    assert validate_startup(secure) == []


def test_dev_startup_only_warns() -> None:
    dev = Settings(_env_file=None, app_env="development", api_secret_key=None, hmac_secret=None, auth_required=False)
    assert validate_startup(dev)  # warnings, no exception


# ------------------------------------------------------------------------------------ schema / money storage
def test_operational_db_stores_money_as_exact_text(isolated_operational_db: Path) -> None:
    conn = sqlite3.connect(isolated_operational_db)
    types = {r[0] for r in conn.execute("SELECT typeof(amount_inr) FROM transactions")}
    assert types == {"text"}
    assert {r[0] for r in conn.execute("SELECT typeof(initial_amount_inr) FROM alerts")} == {"text"}
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    conn.close()


def test_legacy_numeric_schema_is_migrated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    legacy = tmp_path / "legacy.db"
    conn = sqlite3.connect(legacy)
    conn.executescript(
        "CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, initial_amount_inr NUMERIC);"
        "CREATE TABLE worksheets (worksheet_id TEXT PRIMARY KEY, alert_id TEXT, content_json TEXT, payload_hash TEXT,"
        " status TEXT, reviewer_id TEXT, reviewer_decision TEXT, "
        "reviewer_notes TEXT, created_at TEXT, updated_at TEXT);"
        "INSERT INTO alerts VALUES ('A1', 12.5);"
    )
    conn.commit()
    conn.close()
    monkeypatch.setenv("SQLITE_DB_PATH", str(legacy))
    from src.db import database

    database.reset_db_init()
    database.init_db(force=True)
    conn = sqlite3.connect(legacy)
    cols = {r[1]: r[2] for r in conn.execute("PRAGMA table_info(alerts)")}
    assert cols["initial_amount_inr"] == "TEXT"
    assert {"thread_id", "revision"} <= {r[1] for r in conn.execute("PRAGMA table_info(worksheets)")}
    conn.close()
