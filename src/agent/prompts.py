"""
Versioned 6-slot prompt loader (`config/prompts/c1_investigator.yaml`) and
system/user prompt builders for C1 (`c1_single`) and C2 (`c2_multi` supervisor + specialists).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field

from src.config import PROJECT_ROOT
from src.core.policy import PolicyConfig
from src.models import Alert, StrictModel


class PromptExample(StrictModel):
    name: str
    summary: str


class SixSlotBody(StrictModel):
    role: str
    context: str
    task: str
    constraints: list[str] = Field(min_length=1)
    format: str
    examples: list[PromptExample] = Field(default_factory=list)


class SixSlotPromptSpec(StrictModel):
    version: str
    agent: str
    six_slot_prompt: SixSlotBody


@lru_cache
def load_c1_prompt_spec(path: Path | None = None) -> SixSlotPromptSpec:
    """Load and validate the 6-slot YAML prompt from `config/prompts/c1_investigator.yaml`."""
    target = path or (PROJECT_ROOT / "config" / "prompts" / "c1_investigator.yaml")
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    return SixSlotPromptSpec.model_validate(raw)


def render_c1_system_prompt(
    policy: PolicyConfig,
    *,
    lessons: list[str] | None = None,
    replanning_enabled: bool = True,
) -> str:
    """Render the versioned 6-slot prompt with live policy bounds, budgets, and frozen lessons."""
    spec = load_c1_prompt_spec()
    body = spec.six_slot_prompt
    gb = policy.graph_bounds
    b = policy.budgets
    constraints_block = "\n".join(f"  - {c}" for c in body.constraints)
    examples_block = "\n".join(f"  - [{ex.name}] {ex.summary}" for ex in body.examples)
    lesson_block = (
        "\n".join(f"  - {les}" for les in lessons)
        if lessons
        else "  - None active for this run."
    )
    replan_note = (
        f"Allowed up to {b.max_replans} calls to `replan_graph` within bounds "
        f"time_window_days=[{gb.time_window_days.min}..{gb.time_window_days.max}], "
        f"max_hops=[{gb.max_hops.min}..{gb.max_hops.max}], "
        f"amount_tolerance=[{gb.amount_tolerance.min}..{gb.amount_tolerance.max}]."
        if replanning_enabled
        else "Replanning is DISABLED for this run; do not call `replan_graph`."
    )
    return (
        f"[PROMPT_VERSION={spec.version} | AGENT={spec.agent}]\n"
        f"1. ROLE:\n  {body.role.strip()}\n\n"
        f"2. CONTEXT:\n  {body.context.strip()}\n"
        f"  Budgets: max_tool_calls={b.max_tool_calls}, max_cost_usd=${b.max_cost_usd_per_case}, "
        f"max_turns=12. {replan_note}\n"
        f"  Frozen Reflexion Lessons:\n{lesson_block}\n\n"
        f"3. TASK:\n  {body.task.strip()}\n\n"
        f"4. CONSTRAINTS:\n{constraints_block}\n\n"
        f"5. FORMAT:\n  {body.format.strip()}\n\n"
        f"6. EXAMPLES:\n{examples_block}"
    )


def render_alert_user_message(alert: Alert) -> str:
    """Initial user message presenting trusted Alert metadata to the investigator."""
    net = ", ".join(alert.network_accounts[:12]) if alert.network_accounts else "(fetch via get_alert_context)"
    return (
        f"Investigate Alert `{alert.alert_id}`:\n"
        f"- Triggered Rule: `{alert.rule_name}`\n"
        f"- Seed / Root Account: `{alert.root_account}`\n"
        f"- Alert Amount: `INR {alert.total_amount_inr}`\n"
        f"- Initial Network Accounts: {net}\n\n"
        "Begin by calling `get_alert_context`, reconstruct fund flows, check KYC & commercial "
        "registrations for key accounts, formulate case-specific `search_regulations` queries "
        "covering (1) observed typology, (2) benign hypothesis, and (3) missing/degraded evidence, "
        "cite ONLY retrieved passage IDs, use `calc` for any arithmetic, and conclude by calling "
        "`finish` with both competing hypotheses (`suspicious` and `benign`), exact evidence IDs, "
        "and an explicit `missing_evidence` list."
    )


class PromptTemplate(StrictModel):
    version: str
    agent: str
    template: str


@lru_cache
def load_prompt_template(name: str) -> PromptTemplate:
    """Load a versioned prompt template from `config/prompts/<name>.yaml` (audit AG-24)."""
    raw = yaml.safe_load((PROJECT_ROOT / "config" / "prompts" / f"{name}.yaml").read_text(encoding="utf-8")) or {}
    return PromptTemplate.model_validate(raw)


def _versioned(tpl: PromptTemplate, body: str) -> str:
    return f"[PROMPT_VERSION={tpl.version} | AGENT={tpl.agent}]\n{body}"


def render_c2_supervisor_prompt(policy: PolicyConfig, lessons: list[str] | None = None) -> str:
    tpl = load_prompt_template("c2_supervisor")
    b = policy.budgets
    lesson_txt = "\n".join(f"- {les}" for les in (lessons or [])) or "- None"
    body = tpl.template.format(
        max_tool_calls=b.max_tool_calls, max_cost_usd=b.max_cost_usd_per_case, lessons=lesson_txt
    )
    return _versioned(tpl, body)


def render_specialist_prompt(role: str, objective: str, budget_slice: int, context_summary: dict[str, Any]) -> str:
    import json

    tpl = load_prompt_template("c2_specialist")
    body = tpl.template.format(
        role=role,
        objective=objective,
        budget_slice=budget_slice,
        context_json=json.dumps(context_summary, indent=2, default=str),
    )
    return _versioned(tpl, body)
