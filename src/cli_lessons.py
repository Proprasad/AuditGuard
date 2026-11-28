"""`auditguard lessons ...`: human review of Reflexion lessons in the playbook JSON (audit AG-04 / AG-32)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Optional

import typer

from src.reflexion import review

lessons_app = typer.Typer(name="lessons", help="Review, edit and freeze Reflexion lessons (human review only)")
_PLAYBOOK = typer.Option(review.DEFAULT_PLAYBOOK, "--playbook", help="Playbook JSON to review")
_REVIEWER = typer.Option(..., "--reviewer", help="Your name, recorded with the decision")
_REASON = typer.Option(..., "--reason", help="Why; recorded with the decision")


def _run(action: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except review.ReviewError as exc:
        typer.echo(f"{action} refused: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@lessons_app.command("list")
def list_cmd(
    status: str = typer.Option("all", "--status", help="pending | approved | rejected | all"), playbook: str = _PLAYBOOK
) -> None:
    """Show lessons with their status, reviewer and prompt-facing text."""
    data = _run("list", review.load, playbook)
    typer.echo(f"{playbook}: frozen={data.get('frozen', False)} sha256={data.get('frozen_sha256', '-')}")
    for les in _run("list", review.list_lessons, playbook, status):
        typer.echo(
            f"- {les['lesson_id']} [{les.get('status', 'pending')}] reviewer={les.get('reviewer') or '-'}\n"
            f"    IF {les['trigger_precondition']}\n    THEN {les['actionable_rule']}"
        )


@lessons_app.command("accept")
def accept_cmd(lesson_id: str, reviewer: str = _REVIEWER, reason: str = _REASON, playbook: str = _PLAYBOOK) -> None:
    """Approve a pending lesson (refused if its prompt-facing text leaks gold labels)."""
    _run("accept", review.decide, playbook, lesson_id, "approved", reviewer=reviewer, reason=reason)
    typer.echo(f"{lesson_id} approved by {reviewer}")


@lessons_app.command("reject")
def reject_cmd(lesson_id: str, reviewer: str = _REVIEWER, reason: str = _REASON, playbook: str = _PLAYBOOK) -> None:
    """Reject a lesson; it will never be retrieved into a prompt."""
    _run("reject", review.decide, playbook, lesson_id, "rejected", reviewer=reviewer, reason=reason)
    typer.echo(f"{lesson_id} rejected by {reviewer}")


@lessons_app.command("edit")
def edit_cmd(
    lesson_id: str,
    reviewer: str = _REVIEWER,
    reason: str = _REASON,
    precondition: Optional[str] = typer.Option(None, "--precondition", help="New trigger precondition"),
    failure: Optional[str] = typer.Option(None, "--failure", help="New observed failure"),
    rule: Optional[str] = typer.Option(None, "--rule", help="New actionable rule"),
    playbook: str = _PLAYBOOK,
) -> None:
    """Edit a lesson's text; it goes back to pending and needs an explicit accept."""
    _run(
        "edit", review.edit, playbook, lesson_id, reviewer=reviewer, reason=reason,
        trigger_precondition=precondition, observed_failure=failure, actionable_rule=rule,
    )
    typer.echo(f"{lesson_id} edited by {reviewer}; now pending review")


@lessons_app.command("freeze")
def freeze_cmd(reviewer: str = _REVIEWER, playbook: str = _PLAYBOOK) -> None:
    """Freeze the playbook (needs zero pending lessons) and record its sha256."""
    digest = _run("freeze", review.freeze, playbook, reviewer=reviewer)
    typer.echo(f"frozen by {reviewer}: sha256={digest}")


@lessons_app.command("unfreeze")
def unfreeze_cmd(reviewer: str = _REVIEWER, reason: str = _REASON, playbook: str = _PLAYBOOK) -> None:
    """Unfreeze to allow further review; recorded in the file."""
    _run("unfreeze", review.unfreeze, playbook, reviewer=reviewer, reason=reason)
    typer.echo(f"unfrozen by {reviewer}")
