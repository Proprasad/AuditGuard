"""
Chainlit UI - AuditGuard Analyst Interface.

A thin client of the authenticated FastAPI service: it logs in with a service account (`UI_API_USERNAME` /
`UI_API_PASSWORD`, defaulting to the seeded `analyst` account and `ANALYST_PASSWORD`), starts an investigation,
follows its durable event stream and submits decisions with the exact `approved_hash` + single-use `approval_token`.
It never fabricates results: any failure is shown as an error and no approval card is created.
"""
import json
import os
from typing import Any, Optional

import chainlit as cl
import httpx

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")
MODES = ("c0_fixed", "c1_single", "c2_multi")
TARGET_DISPOSITION = {"approve": "escalate_str", "close_benign": "close_benign", "request_info": "request_info"}
_token_cache: dict[str, str] = {}


class ApiError(RuntimeError):
    pass


async def _headers(client: httpx.AsyncClient) -> dict[str, str]:
    if "token" not in _token_cache:
        username = os.getenv("UI_API_USERNAME", "analyst")
        password = os.getenv("UI_API_PASSWORD") or os.getenv("ANALYST_PASSWORD", "")
        if not password:
            raise ApiError("UI_API_PASSWORD (or ANALYST_PASSWORD) is not configured")
        resp = await client.post(f"{API_BASE}/api/v1/auth/token", json={"username": username, "password": password})
        if resp.status_code != 200:
            raise ApiError(f"login failed (HTTP {resp.status_code})")
        _token_cache["token"] = resp.json()["access_token"]
    return {"Authorization": f"Bearer {_token_cache['token']}"}


async def _api(client: httpx.AsyncClient, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
    resp = await client.request(method, f"{API_BASE}{path}", headers=await _headers(client), **kwargs)
    if resp.status_code == 401:
        _token_cache.pop("token", None)
    if resp.status_code >= 400:
        raise ApiError(f"HTTP {resp.status_code}: {resp.text[:300]}")
    return resp.json()


@cl.on_chat_start
async def on_chat_start() -> None:
    await cl.Message(
        content="""# AuditGuard - AML Investigation System

Evidence-grounded AI for ambiguous fund-flow networks. Start with:
```
investigate <alert_id>
```
Switch agent mode with `/mode c0_fixed|c1_single|c2_multi`.
All dispositions require your explicit approval; editing a worksheet invalidates any earlier approval.
""",
        author="AuditGuard",
    ).send()
    cl.user_session.set("mode", "c1_single")
    cl.user_session.set("thread_id", None)
    cl.user_session.set("pending", None)


@cl.on_message
async def on_message(message: cl.Message) -> None:
    content = message.content.strip()
    parts = content.split()
    if content.startswith("/mode"):
        mode = parts[-1] if len(parts) > 1 else "c1_single"
        if mode in MODES:
            cl.user_session.set("mode", mode)
            await cl.Message(content=f"Switched to mode: **{mode}**").send()
        else:
            await cl.Message(content=f"Invalid mode. Use: {', '.join(MODES)}").send()
        return

    if parts and parts[0].lower() == "investigate":
        if len(parts) < 2:
            await cl.Message(content="Usage: `investigate <alert_id>`").send()
            return
        await _run_investigation(parts[1], cl.user_session.get("mode", "c1_single"))
        return

    if cl.user_session.get("pending"):
        lower = content.lower()
        if "reject" in lower:
            await _decide("reject", content)
        elif any(w in lower for w in ("approve", "escalate", "confirm")):
            await _decide("approve", content)
        elif "benign" in lower:
            await _decide("close_benign", content)
        elif "request" in lower or "more info" in lower:
            await _decide("request_info", content)
        else:
            await cl.Message(content="Reply with: **approve**, **close as benign**, **request more info** or **reject**").send()
        return

    await cl.Message(content="Type `investigate <alert_id>` to start, or `/mode ...` to switch agent mode.").send()


def _render_event(event: str, data: dict[str, Any]) -> Optional[str]:
    if event == "plan_updated":
        return "\n\n**Investigation plan:**\n" + "\n".join(f"  {s}" for s in data.get("steps", []))
    if event == "tool_called":
        return f"\n{data.get('message', 'Tool calls executed')}"
    if event == "hypotheses_scored":
        return f"\n{data.get('message', 'Hypotheses scored')}"
    if event == "replan_triggered":
        return f"\n\n**Replanning** - {data.get('reason', '')}"
    if event == "verification_completed":
        return f"\n{data.get('message', 'Verification complete')}"
    return None


async def _run_investigation(alert_id: str, mode: str) -> None:
    cl.user_session.set("pending", None)
    msg = cl.Message(content=f"Starting **{mode}** investigation for `{alert_id}`...\n")
    await msg.send()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0)) as client:
            reg = await _api(client, "POST", "/api/v1/investigations", json={"alert_id": alert_id, "mode": mode})
            thread_id = reg["thread_id"]
            cl.user_session.set("thread_id", thread_id)
            async with client.stream("GET", f"{API_BASE}/api/v1/investigations/{thread_id}/stream", headers=await _headers(client)) as resp:
                if resp.status_code != 200:
                    raise ApiError(f"stream failed (HTTP {resp.status_code})")
                event = "message"
                async for line in resp.aiter_lines():
                    if line.startswith("event:"):
                        event = line[6:].strip()
                        continue
                    if not line.startswith("data:"):
                        continue
                    try:
                        data = json.loads(line[5:].strip())
                    except json.JSONDecodeError:
                        continue
                    if text := _render_event(event, data):
                        await msg.stream_token(text)
                    if event == "interrupt_required":
                        await _show_approval_card(data)
                        return
                    if event == "verification_failed":
                        cl.user_session.set("pending", data)
                        await cl.Message(content=f"Verification FAILED (fail-closed): {data.get('message', '')}\nEdit the worksheet in the Workbench or reject.").send()
                        return
                    if event in ("completed", "error"):
                        await msg.stream_token(f"\n\n{data.get('message', event)}")
                        return
    except (ApiError, httpx.HTTPError) as exc:
        cl.user_session.set("pending", None)
        await cl.Message(content=f"Investigation failed: {exc}. No result was produced.", author="AuditGuard").send()


async def _show_approval_card(data: dict[str, Any]) -> None:
    cl.user_session.set("pending", data)
    actions = [
        cl.Action(name="approve", label="Approve & Escalate STR", payload={"choice": "approve"}),
        cl.Action(name="close_benign", label="Close as Benign", payload={"choice": "close_benign"}),
        cl.Action(name="request_info", label="Request More Info", payload={"choice": "request_info"}),
        cl.Action(name="reject", label="Reject", payload={"choice": "reject"}),
    ]
    await cl.Message(
        content=(
            f"## Human approval required\n\n**Worksheet:** `{data.get('worksheet_id')}`\n"
            f"**Recommendation:** `{str(data.get('recommended_disposition', '')).upper()}` "
            f"({float(data.get('confidence_score', 0)):.0%} confidence)\n"
            f"**Payload hash:** `{str(data.get('payload_hash', ''))[:20]}...`\n\n"
            "Choosing a different disposition edits the worksheet (re-verified, new hash and token) before approval."
        ),
        actions=actions,
        author="AuditGuard",
    ).send()


@cl.action_callback("approve")
async def on_approve(action: cl.Action) -> None:
    await _decide("approve", "Analyst approved via UI")


@cl.action_callback("close_benign")
async def on_close_benign(action: cl.Action) -> None:
    await _decide("close_benign", "Analyst closed as benign via UI")


@cl.action_callback("request_info")
async def on_request_info(action: cl.Action) -> None:
    await _decide("request_info", "Analyst requested more information via UI")


@cl.action_callback("reject")
async def on_reject(action: cl.Action) -> None:
    await _decide("reject", "Analyst rejected via UI")


async def _decide(choice: str, notes: str) -> None:
    pending: Optional[dict[str, Any]] = cl.user_session.get("pending")
    thread_id = cl.user_session.get("thread_id")
    if not pending or not thread_id:
        await cl.Message(content="No investigation is awaiting a decision.").send()
        return
    path = f"/api/v1/investigations/{thread_id}/decision"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            if choice == "reject":
                body = await _api(client, "POST", path, json={"action": "reject", "notes": notes})
            else:
                approved_hash, token = pending.get("approved_hash"), pending.get("approval_token")
                target = TARGET_DISPOSITION[choice]
                if target != pending.get("recommended_disposition") or not approved_hash:
                    edited = await _api(client, "POST", path, json={"action": "edit", "edit": {"recommended_disposition": target}})
                    approved_hash, token = edited["approved_hash"], edited["approval_token"]
                body = await _api(client, "POST", path, json={"action": "approve", "approved_hash": approved_hash,
                                                              "approval_token": token, "notes": notes})
    except (ApiError, httpx.HTTPError) as exc:
        await cl.Message(content=f"Decision was NOT recorded: {exc}", author="AuditGuard").send()
        return
    receipt = body.get("receipt") or {}
    await cl.Message(
        content=(f"## Decision recorded: `{str(body.get('decision', choice)).upper()}`\n"
                 f"**Case:** `{receipt.get('case_id', '-')}`  **Audit entry:** `{receipt.get('audit_entry_id', '-')}`\n\n"
                 "Type `investigate <alert_id>` to start another."),
        author="AuditGuard",
    ).send()
    cl.user_session.set("pending", None)
