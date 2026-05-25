"""`diff-reports` subcommand: drift between two evaluation reports."""

from __future__ import annotations

from pathlib import Path

import typer

from oss_policy_kit.application.drift import compute_drift, load_report_json
from oss_policy_kit.application.reporting import render_drift_report
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.common import (
    app,
    stderr_console,
    write_stdout_text,
)
from oss_policy_kit.cli.help_text import CMD_PANEL_EVALUATE, DIFF_REPORTS_EPILOG
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError


@app.command("diff-reports", epilog=DIFF_REPORTS_EPILOG, rich_help_panel=CMD_PANEL_EVALUATE)
def diff_reports_cmd(
    before: Path = typer.Option(..., "--before", help="Path to the earlier evaluation-report.json."),
    after: Path = typer.Option(..., "--after", help="Path to the more recent evaluation-report.json."),
    fmt: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json, markdown.",
        case_sensitive=False,
    ),
    fail_on_regression: bool = typer.Option(
        True,
        "--fail-on-regression/--no-fail-on-regression",
        help="Exit with code 1 when regressions are present (default: enabled).",
    ),
) -> None:
    """Compare two evaluation reports and show posture drift."""

    try:
        if not before.is_file():
            raise InvalidInputError(f"--before not found: {before}")
        if not after.is_file():
            raise InvalidInputError(f"--after not found: {after}")
        b = load_report_json(before)
        a = load_report_json(after)
        drift = compute_drift(b, a)
        if drift.profile_mismatch:
            stderr_console().print(
                "[yellow]Warning:[/yellow] profiles differ "
                f"([cyan]{drift.before_profile_id}[/cyan] → [cyan]{drift.after_profile_id}[/cyan]). "
                "Controls listed under 'New in after' or 'Removed from after' may reflect "
                "a profile scope change rather than a posture change."
            )
        text = render_drift_report(drift, fmt, color=terminal_ui.human_tty_stdout())
        write_stdout_text(text)
        if drift.has_regressions and fail_on_regression:
            raise typer.Exit(code=1)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except ValueError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # noqa: BLE001
        stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc
