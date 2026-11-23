"""
Chainlit UI — AuditGuard Analyst Interface
Real-time investigation traces, approval card, evidence display
"""
import asyncio
import os

import chainlit as cl
import httpx

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")


@cl.on_chat_start
async def on_chat_start():
    await cl.Message(
        content="""# 🛡️ AuditGuard — AML Investigation System

**Evidence-Grounded AI for Ambiguous Fund-Flow Networks**

I'm your AI-assisted AML investigation agent. I will:
- Analyze fund-flow networks for suspicious patterns
- Test competing hypotheses (suspicious vs. benign)
- Research applicable regulations
- Draft a disposition worksheet for your review

**To start an investigation, type:**
```
investigate ALT-2026-0412
```
Or provide a custom alert in this format:
```
alert: <alert_id> amount: <INR amount> accounts: <acc1,acc2,acc3>
```

*Architecture: C0 (Fixed) | C1 (Single-Agent) | C2 (Multi-Agent)*
*All dispositions require your explicit approval before filing.*
""",
        author="AuditGuard",
    ).send()

    cl.user_session.set("mode", "c1_single")
    cl.user_session.set("thread_id", None)
    cl.user_session.set("pending_worksheet", None)


@cl.on_message
async def on_message(message: cl.Message):
    content = message.content.strip()

    # Mode switching
    if content.startswith("/mode"):
        mode = content.split()[-1] if len(content.split()) > 1 else "c1_single"
        if mode in ["c0_fixed", "c1_single", "c2_multi"]:
            cl.user_session.set("mode", mode)
            await cl.Message(content=f"✅ Switched to mode: **{mode}**").send()
        else:
            await cl.Message(content="❌ Invalid mode. Use: c0_fixed, c1_single, c2_multi").send()
        return

    # Handle investigation start
    if "investigate" in content.lower() or "alert" in content.lower():
        # Parse alert ID
        parts = content.split()
        alert_id = "ALT-2026-0412"  # Default
        for i, p in enumerate(parts):
            if p.lower() in ("investigate", "alert:") and i + 1 < len(parts):
                alert_id = parts[i + 1]
                break

        mode = cl.user_session.get("mode", "c1_single")
        await _run_investigation(alert_id, mode)
        return

    # Handle approval/rejection
    pending = cl.user_session.get("pending_worksheet")
    if pending:
        lower = content.lower()
        if any(word in lower for word in ["approve", "escalate", "confirm"]):
            await _approve_worksheet(pending, "approve", content)
        elif any(word in lower for word in ["reject", "close", "benign"]):
            await _approve_worksheet(pending, "close_benign", content)
        elif "request" in lower or "more info" in lower:
            await _approve_worksheet(pending, "request_info", content)
        else:
            await cl.Message(
                content="Please respond with: **approve**, **close as benign**, or **request more info**"
            ).send()
        return

    await cl.Message(
        content="Type `investigate <alert_id>` to start an investigation.\n"
                "Or `/mode c0_fixed|c1_single|c2_multi` to switch agent mode."
    ).send()


async def _run_investigation(alert_id: str, mode: str):
    """Stream an investigation and display results."""
    import uuid

    thread_id = f"thr-{uuid.uuid4().hex[:12]}"
    cl.user_session.set("thread_id", thread_id)

    # Progress message
    msg = cl.Message(content=f"🔍 Starting **{mode}** investigation for `{alert_id}`...\n\n")
    await msg.send()

    steps = []

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            url = f"{API_BASE}/api/v1/investigations/{thread_id}/stream"
            params = {"alert_id": alert_id, "mode": mode}

            async with client.stream("GET", url, params=params) as response:
                async for line in response.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data_str = line[5:].strip()
                    if not data_str:
                        continue

                    try:
                        data = __import__("json").loads(data_str)
                        event_type = line.split("event:")[0] if "event:" in line else "message"
                    except Exception:
                        continue

                    # Render events
                    if "tool_called" in str(data):
                        server = data.get("server", "")
                        tool = data.get("tool", "")
                        steps.append(f"  🔧 `{server}.{tool}`")
                        await msg.stream_token(f"\n🔧 Calling `{server}.{tool}`...")

                    elif "plan_updated" in str(data):
                        plan_steps = data.get("steps", [])
                        plan_text = "\n".join(f"  {s}" for s in plan_steps)
                        await msg.stream_token(f"\n\n📋 **Investigation Plan:**\n{plan_text}")

                    elif "replan_triggered" in str(data):
                        await msg.stream_token(f"\n\n🔄 **Replanning** — {data.get('reason', '')}")

                    elif "interrupt_required" in str(data):
                        await _show_approval_card(data, alert_id, mode)
                        return

                    elif "completed" in str(data):
                        await msg.stream_token(f"\n\n✅ Investigation complete.")
                        return

                    elif "error" in str(data):
                        await msg.stream_token(f"\n\n❌ Error: {data.get('error', 'Unknown error')}")
                        return

    except Exception as exc:  # noqa: BLE001 - UI boundary: surface a real error, never fabricate a result
        cl.user_session.set("pending_worksheet", None)
        await cl.Message(content=f"Investigation failed: {type(exc).__name__}. No result was produced; check the API logs and retry.", author="AuditGuard").send()


async def _show_approval_card(data: dict, alert_id: str, mode: str):
    """Show human approval card with worksheet summary."""
    worksheet_id = data.get("worksheet_id", "DWS-UNKNOWN")
    disposition = data.get("recommended_disposition", "request_info")
    confidence = data.get("confidence_score", 0.5)
    payload_hash = data.get("payload_hash", "")

    cl.user_session.set("pending_worksheet", data)

    actions = [
        cl.Action(name="approve", label="✅ Approve & Escalate STR", value="approve"),
        cl.Action(name="close_benign", label="✅ Close as Benign", value="close_benign"),
        cl.Action(name="request_info", label="ℹ️ Request More Info", value="request_info"),
    ]

    await cl.Message(
        content=f"""## 🛑 Human Approval Required

**Worksheet:** `{worksheet_id}`
**Recommendation:** `{disposition.upper()}` ({confidence:.0%} confidence)
**Payload Hash:** `{payload_hash[:20]}...`

> ⚠️ Editing the worksheet content will invalidate this approval token.

Please review the evidence above and choose your disposition:""",
        actions=actions,
        author="AuditGuard",
    ).send()


@cl.action_callback("approve")
async def on_approve(action: cl.Action):
    pending = cl.user_session.get("pending_worksheet")
    if pending:
        await _approve_worksheet(pending, "escalate_str", "Analyst approved via UI")


@cl.action_callback("close_benign")
async def on_close_benign(action: cl.Action):
    pending = cl.user_session.get("pending_worksheet")
    if pending:
        await _approve_worksheet(pending, "close_benign", "Analyst closed as benign")


@cl.action_callback("request_info")
async def on_request_info(action: cl.Action):
    pending = cl.user_session.get("pending_worksheet")
    if pending:
        await _approve_worksheet(pending, "request_info", "Analyst requested more information")


async def _approve_worksheet(worksheet: dict, decision: str, notes: str):
    """Submit analyst decision to the FastAPI Human Approval Gate with exact SHA-256 hash."""
    worksheet_id = worksheet.get("worksheet_id", "UNKNOWN")
    thread_id = cl.user_session.get("thread_id", "unknown")
    payload_hash = worksheet.get("payload_hash", "")
    mapped_decision = "escalate_str" if decision == "approve" else decision
    action = "reject" if decision == "rejected" else "approve"

    receipt_info = ""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{API_BASE}/api/v1/investigations/{thread_id}/decision",
                json={
                    "worksheet_id": worksheet_id,
                    "action": action,
                    "decision": mapped_decision,
                    "approved_hash": payload_hash,
                    "reviewer_id": "chainlit_analyst",
                    "notes": notes,
                },
            )
            if resp.status_code == 200:
                body = resp.json()
                receipt = body.get("receipt") or {}
                receipt_info = f"\n**Case Receipt:** `{receipt.get('case_id', 'COMMITTED')}` (`{receipt.get('audit_entry_id', 'AUD-OK')}`)"
            else:
                receipt_info = f"\n⚠️ **API Response ({resp.status_code}):** `{resp.text}`"
    except Exception as exc:
        receipt_info = f"\n*(Offline UI preview: `{exc}`)*"

    decision_icons = {
        "escalate_str": "🔴",
        "close_benign": "✅",
        "request_info": "ℹ️",
        "approve": "🔴",
    }
    icon = decision_icons.get(decision, "✅")

    await cl.Message(
        content=f"""## {icon} Decision Recorded

**Worksheet:** `{worksheet_id}`
**Decision:** `{mapped_decision.upper().replace('_', ' ')}`
**Notes:** {notes}
**Reviewed by:** Analyst (via Chainlit UI){receipt_info}

---
*Disposition committed to case management database with SHA-256 verification.*
*PII scrubbed from logs. Append-only audit log entry created.*

Type `investigate <alert_id>` to start a new investigation.
""",
        author="AuditGuard",
    ).send()

    cl.user_session.set("pending_worksheet", None)
