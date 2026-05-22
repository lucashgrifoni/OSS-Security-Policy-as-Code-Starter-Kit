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


def _resolve_target(raw: str, *, allow_missing: bool = False) -> Path:
    """Resolve and validate the ``--target`` directory.

    Unlike ``evaluate``'s helper, ``init`` happily creates new files inside
    an *existing* but empty directory, so the only requirement is that the
    target already exists. We never auto-create the target itself: a
    missing directory almost always means the user mistyped a path.

    When ``allow_missing`` is True (used by ``--dry-run``), a path that
    does not exist yet is accepted: the caller will only render the plan
    and write nothing. The "is a directory" guard still applies whenever
    the path exists but is a file. (OP-001 / MELHORIA-011)

    Raises:
        InvalidInputError: When the path does not exist (and
            ``allow_missing`` is False), or when the path exists but is
            not a directory.
    """

    candidate = Path(raw).expanduser()
    if not candidate.exists():
        if allow_missing:
            return candidate.resolve()
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


def _print_human_summary(*, plan: Any, outcome: InitOutcome, dry_run: bool) -> None:  # noqa: C901
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

    _print_init_actions(outcome, dry_run=dry_run)
    _print_init_notes_and_steps(plan, outcome)


def _print_init_actions(outcome: InitOutcome, *, dry_run: bool) -> None:
    """Print the created / overwritten / skipped artifact lines (or '(no actions)')."""

    header = "Plan (dry-run, nothing written)" if dry_run else "Actions"
    write_stdout_text(f"\n{header}:\n")
    for p in outcome.created:
        write_stdout_text(f"  + {p}\n")
    for p in outcome.overwritten:
        write_stdout_text(f"  ! {p}  (replaced)\n")
    for p in outcome.skipped:
        write_stdout_text(f"  = {p}  (kept; re-run with --force to replace)\n")
    if not (outcome.created or outcome.overwritten or outcome.skipped):
        write_stdout_text("  (no actions)\n")


def _print_init_notes_and_steps(plan: Any, outcome: InitOutcome) -> None:
    """Print the optional Notes and Next-steps sections."""

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
        help="Skip the interactive profile-confirmation prompt (use the recommended profile as-is).",
    ),
    interactive: bool = typer.Option(
        False,
        "--interactive/--no-interactive",
        help=(
            "Prompt the user to confirm or override the recommended profile "
            "before writing oss-policy-kit.yaml. Only fires when --profile is "
            "not supplied and stdin is a TTY. Other flags remain "
            "non-interactive."
        ),
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

    try:
        fmt = _normalize_format(output_format)
        # In --dry-run we accept a path that does not exist yet so the user
        # can preview the plan before creating the directory (OP-001).
        target_path = _resolve_target(target, allow_missing=dry_run)
        target_pre_existed = Path(target).expanduser().exists()

        # Interactive prompt path (v5.9.0). Only fires when:
        # - --interactive is set
        # - --profile was NOT supplied (we have something to recommend)
        # - --yes was NOT supplied (operator wants the prompt)
        # - stdin is a TTY (we are not in a CI / pipe scenario)
        # - output format is human (JSON callers expect deterministic output)
        chosen_profile = profile
        if interactive and chosen_profile is None and not yes and sys.stdin.isatty() and fmt == "human":
            preview_plan = build_init_plan(
                target=target_path,
                forced_profile=None,
                forced_platform=platform,
                fail_on=fail_on,
                output_dir=output_dir,
                with_waivers=with_waivers,
                with_evidence=with_evidence,
                with_workflow=with_workflow,
                force=force,
                dry_run=True,
            )
            recommended = preview_plan.profile
            stderr_console().print(f"\n[cyan]Detected platform:[/cyan] {preview_plan.platform or 'unknown'}")
            stderr_console().print(f"[cyan]Recommended profile:[/cyan] {recommended}")
            response = typer.prompt(
                "Use this profile (press Enter to accept, or type a different profile id)",
                default=recommended,
                show_default=True,
            )
            chosen_profile = response.strip() or recommended

        plan = build_init_plan(
            target=target_path,
            forced_profile=chosen_profile,
            forced_platform=platform,
            fail_on=fail_on,
            output_dir=output_dir,
            with_waivers=with_waivers,
            with_evidence=with_evidence,
            with_workflow=with_workflow,
            force=force,
            dry_run=dry_run,
        )
        # OP-001: when dry-run targets a path that does not yet exist, surface
        # the fact explicitly so adopters know they will need to create it
        # before running init without --dry-run.
        if dry_run and not target_pre_existed:
            plan.notes.append(
                f"Target directory does not exist yet: {target_path}. "
                "Running init without --dry-run will require you to create it first."
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
