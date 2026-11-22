"""
Frontend Workbench DOM-Contract, ES-Module Asset & Live SSE Integration Tests
Verifies:
  1. Every `document.getElementById('...')` in `app.js` exists in `index.html` (save dynamic modal/subview IDs).
  2. All 9 sidebar `data-nav` items and all 5 center `data-tab` buttons exist in `index.html`.
  3. Live SSE stream (`/api/v1/investigations/{thread_id}/stream`) emits `started`, `plan_updated`,
     `agent_updated`, `tool_called`, `verification_completed`, and `interrupt_required` with full
     `flow_summary`, `workflow_steps`, `agent_runs`, `transactions`, and `worksheet`.
"""
import json
import re
from pathlib import Path
from fastapi.testclient import TestClient

from src.api.main import app

STATIC_DIR = Path("src/ui/static")
DYNAMIC_IDS = {
    "regSearchInput",
    "btnRegSearch",
    "regResultsTable",
    "btnToggleLlm",
    "llmFastModelSelect",
    "llmStrongModelSelect",
    "btnSaveModels",
    "btnPingLlm",
    "llmTestStatus",
}


def test_every_static_dom_id_in_app_js_exists_in_index_html():
    html_text = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC_DIR / "js" / "app.js").read_text(encoding="utf-8")

    html_ids = set(re.findall(r'id="([^"]+)"', html_text))
    referenced_ids = set(re.findall(r'getElementById\("([^"]+)"\)', app_js))

    missing = referenced_ids - html_ids - DYNAMIC_IDS
    assert not missing, f"DOM IDs referenced in app.js missing from index.html: {missing}"
    assert "switchNav(" not in app_js, "app.js must call switchSidebarView(), not undefined switchNav()"


def test_all_9_sidebar_navs_and_5_center_tabs_present():
    html_text = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    navs = set(re.findall(r'data-nav="([^"]+)"', html_text))
    tabs = set(re.findall(r'data-tab="([^"]+)"', html_text))

    assert navs == {
        "investigation",
        "alerts",
        "cases",
        "customers",
        "graph_explorer",
        "regulations",
        "audit",
        "analytics",
        "settings",
    }
    assert tabs == {"graph", "flow", "hypotheses", "evidence", "agents"}


def test_sse_stream_emits_complete_workbench_telemetry():
    client = TestClient(app)
    reg = client.post(
        "/api/v1/investigations",
        json={"alert_id": "ALT-2026-0412", "mode": "c2_multi", "total_amount_inr": 900000},
    ).json()
    tid = reg["thread_id"]

    events = []
    interrupt_payload = None
    with client.stream("GET", f"/api/v1/investigations/{tid}/stream?alert_id=ALT-2026-0412&mode=c2_multi") as resp:
        assert resp.status_code == 200
        for line in resp.iter_lines():
            if line.startswith("event: "):
                events.append(line.split("event: ", 1)[1].strip())
            elif line.startswith("data: "):
                d = json.loads(line.split("data: ", 1)[1])
                if d.get("event") == "interrupt_required":
                    interrupt_payload = d

    assert "started" in events
    assert "plan_updated" in events
    assert "agent_updated" in events
    assert "tool_called" in events
    assert "replan_triggered" in events
    assert "verification_completed" in events
    assert "interrupt_required" in events

    assert interrupt_payload is not None
    st = interrupt_payload["state"]
    assert st["flow_summary"]["total_outflow_inr"] == "900000.00"
    assert st["flow_summary"]["total_consolidated_inr"] == "828000.00"
    assert st["flow_summary"]["total_retained_inr"] == "72000.00"
    assert len(st["transactions"]) == 6
    assert len(st["workflow_steps"]) == 7
    assert len(st["agent_runs"]) == 4


def test_llm_config_toggle_and_secret_masking():
    client = TestClient(app)
    r1 = client.post("/api/v1/config/llm", json={"enabled": False, "model": "openai/gpt-5-mini"})
    assert r1.status_code == 200
    data1 = r1.json()
    assert data1["c1_and_specialist_model"] == "openai/gpt-5-mini"
    # Full API secret must never appear in API payload
    assert len(data1["key_preview"]) <= 20

    r2 = client.post("/api/v1/config/llm", json={"enabled": True, "strong_model": "anthropic/claude-haiku-5.5"})
    assert r2.status_code == 200
    assert r2.json()["c2_supervisor_model"] == "anthropic/claude-haiku-5.5"
    # Reset runtime override back to None/env default
    from src.agent import llm_client
    llm_client._runtime_enabled_override = None
    llm_client._runtime_model_override = None
    llm_client._runtime_strong_model_override = None
