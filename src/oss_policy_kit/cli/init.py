"""``oss-policy-kit init`` subcommand: zero-friction repo bootstrap.

This is the user-facing entry point for the ``init`` wizard. It owns:

- Argument parsing and validation (delegating semantics to
  :func:`build_init_plan`).
- Filesystem execution via :func:`execute_init_plan`.
- Human and JSON rendering of the resulting :class:`InitOutcome`.

The command is intentionally thin: every decision lives in
``init_planner``, every side effect lives in ``init_writer``. That keeps
the Typer surface easy to evolve without touching the planning logic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import typer

from oss_policy_kit.application.init_planner import (
    INIT_RESULT_SCHEMA_VERSION,
    build_init_plan,
)
from oss_policy_kit.application.init_writer import (
    InitOutcome,
    execute_init_plan,
)
from oss_policy_kit.cli.common import (
    app,
    stderr_console,
    write_stdout_text,
)
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError


def _resolve_target(raw: str) -> Path:
    """Resolve and validate the ``--target`` directory.

    Unlike ``evaluate``'s helper, ``init`` happily creates new files inside
    an *existing* but empty directory, so the only requirement is that the
    target already exists. We never auto-create the target itself: a
    missing directory almost always means the user mistyped a path.

    Raises:
        InvalidInputError: When the path does not exist or is not a dir.
    """

    candidate = Path(raw).expanduser()
    if not candidate.exists():
        raise InvalidInputError(
            f"--target path does not exist: {candidate}. "
            "Pass an existing repository root, or create the directory first.",
        )
    if not candidate.is_dir():
        raise InvalidInputError(
            f"--target must be a directory: {candidate}.",
        )
    return candidate.resolve()


def _normalize_format(raw: str) -> str:
    """Map ``init --format`` aliases to ``human`` or ``json``."""

    normalized = raw.lower().strip()
    if normalized in {"human", "table", "compact"}:
        return "human"
    if normalized == "json":
        return "json"
    raise InvalidInputError(
        "init --format must be human or json (aliases: table, compact map to human).",
    )


def _print_human_summary(*, plan: Any, outcome: InitOutcome, dry_run: bool) -> None:
    """Render a friendly human summary on stdout (no Rich coloring inside
    the CliRunner so tests can assert on plain strings).

    The summary always lists every artifact the writer touched, plus the
    next steps tailored to the chosen profile.
    """

    write_stdout_text("oss-policy-kit init - project bootstrap\n\n")
    write_stdout_text(f"Target:        {plan.target}\n")
    write_stdout_text(f"Platform:      {plan.platform}\n")
    write_stdout_text(
        f"Primary stack: {plan.primary_stack if plan.primary_stack else '(not detected)'}\n",
    )
    write_stdout_text(f"Profile:       {plan.profile} (source: {plan.profile_source})\n")
    write_stdout_text(f"Fail-on:       {plan.fail_on}\n")
    write_stdout_text(f"Output dir:    {plan.output_dir}\n")
    if plan.signals:
        write_stdout_text("Signals:       " + ", ".join(plan.signals) + "\n")

    header = "Plan (dry-run, nothing written)" if dry_run else "Actions"
    write_stdout_text(f"\n{header}:\n")

    if outcome.created:
        for p in outcome.created:
            write_stdout_text(f"  + {p}\n")
    if outcome.overwritten:
        for p in outcome.overwritten:
            write_stdout_text(f"  ! {p}  (replaced)\n")
    if outcome.skipped:
        for p in outcome.skipped:
            write_stdout_text(f"  = {p}  (kept; re-run with --force to replace)\n")
    if not (outcome.created or outcome.overwritten or outcome.skipped):
        write_stdout_text("  (no actions)\n")

    if plan.notes:
        write_stdout_text("\nNotes:\n")
        for note in plan.notes:
            write_stdout_text(f"  - {note}\n")

    if outcome.next_steps:
        write_stdout_text("\nNext steps:\n")
        for step in outcome.next_steps:
            write_stdout_text(f"  - {step}\n")


def _build_json_payload(
    *,
    plan: Any,
    outcome: InitOutcome,
    dry_run: bool,
) -> dict[str, Any]:
    """Build the stable JSON payload returned by ``--format json``.

    The shape is contractual: external automation may parse it. Add fields
    via additive changes only; never remove or rename keys without bumping
    :data:`INIT_RESULT_SCHEMA_VERSION`.
    """

    return {
        "schema_version": INIT_RESULT_SCHEMA_VERSION,
        "dry_run": dry_run,
        "target": str(plan.target),
        "detected": {
            "platform": plan.platform,
            "primary_stack": plan.primary_stack,
            "signals": list(plan.signals),
        },
        "profile_chosen": plan.profile,
        "profile_source": plan.profile_source,
        "fail_on": plan.fail_on,
        "output_dir": plan.output_dir,
        "actions": {
            "created": [str(p) for p in outcome.created],
            "skipped": [str(p) for p in outcome.skipped],
            "overwritten": [str(p) for p in outcome.overwritten],
        },
        "notes": list(plan.notes),
        "next_steps": list(outcome.next_steps),
    }


@app.command("init")
def init_cmd(
    target: str = typer.Option(
        ".",
        "--target",
        "-t",
        help="Repository root to initialize (must exist). Defaults to the current directory.",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help=("Force a specific profile (e.g. github-level-2). When omitted, init recommends one from repo signals."),
    ),
    platform: str | None = typer.Option(
        None,
        "--platform",
        help=(
            "Force the platform for the recommended profile: github | azure | aws. "
            "Skip this flag to auto-detect from CI files."
        ),
        case_sensitive=False,
    ),
    fail_on: str = typer.Option(
        "fail",
        "--fail-on",
        help="Severity that should trip CI: none | fail | degraded. Stored in oss-policy-kit.yaml.",
        case_sensitive=False,
    ),
    output_dir: str = typer.Option(
        "./oss-policy-reports",
        "--output-dir",
        "-o",
        help="Directory where evaluate will write its reports. Stored in oss-policy-kit.yaml.",
    ),
    with_waivers: bool = typer.Option(
        False,
        "--with-waivers",
        help="Also write a waivers.yaml stub (commented example included).",
    ),
    with_evidence: bool = typer.Option(
        False,
        "--with-evidence",
        help="Also scaffold .oss-policy-kit/evidence/ for the detected platform.",
    ),
    with_workflow: bool = typer.Option(
        False,
        "--with-workflow",
        help="Also drop a baseline GitHub Actions workflow under .github/workflows/.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing files (default: keep them and report as skipped).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview every action without writing anything.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Reserved for future interactive prompts; today init is always non-interactive.",
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        help="human (default) or json on stdout; aliases table, compact map to human.",
        case_sensitive=False,
    ),
) -> None:
    """Initialize a repository to use oss-policy-kit (config + optional artifacts).

    Detects the CI platform and primary language stack from the repository
    layout, picks a recommended profile (or honors ``--profile`` /
    ``--platform``), and writes ``oss-policy-kit.yaml`` plus any optional
    artifacts requested via ``--with-*`` flags.

    The command is idempotent: re-running without ``--force`` preserves
    existing files and reports them under ``skipped``. Use ``--dry-run`` to
    preview every action without touching the filesystem.

    Honesty contract: ``oss-policy-kit.yaml`` is reserved for future
    versions of ``evaluate`` to consume when ``--profile`` is omitted. In
    this release the file documents intent and powers reproducibility, but
    ``evaluate`` still requires explicit flags. The contract uses a stable
    ``schema_version`` so the upcoming consumer can migrate safely.
    """

    # ``--yes`` is currently a no-op because the wizard is fully
    # non-interactive. Accepting the flag now keeps future scripts
    # forward-compatible when interactive prompts land.
    _ = yes

    try:
        fmt = _normalize_format(output_format)
        target_path = _resolve_target(target)
        plan = build_init_plan(
            target=target_path,
            forced_profile=profile,
            forced_platform=platform,
            fail_on=fail_on,
            output_dir=output_dir,
            with_waivers=with_waivers,
            with_evidence=with_evidence,
            with_workflow=with_workflow,
            force=force,
            dry_run=dry_run,
        )
        outcome = execute_init_plan(plan)

        if fmt == "json":
            payload = _build_json_payload(plan=plan, outcome=outcome, dry_run=dry_run)
            sys.stdout.write(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            )
        else:
            _print_human_summary(plan=plan, outcome=outcome, dry_run=dry_run)

    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except OSError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort user message
        stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc
