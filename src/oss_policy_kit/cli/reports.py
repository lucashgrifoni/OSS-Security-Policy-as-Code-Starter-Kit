"""`diff-reports` subcommand: drift between two evaluation reports."""

from __future__ import annotations

from pathlib import Path

import typer

from oss_policy_kit.application.drift import (
    UNVERIFIED_DIGEST_KEY,
    DriftReport,
    compute_drift,
    load_report_json,
)
from oss_policy_kit.application.reporting import render_drift_report
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.common import app, exit_for_unexpected, markup_safe, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_EVALUATE, DIFF_REPORTS_EPILOG
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError

# Formats accepted by render_drift_report. Validated here (consistent with the other
# subcommands) so a typo like ``--format markdwn`` fails loudly with exit 2 instead of
# silently falling back to the Rich table and corrupting a CI artifact.
_DIFF_FORMATS: tuple[str, ...] = ("table", "json", "markdown", "md")


def _guard_target_mismatch(drift: DriftReport, *, allow_different_targets: bool) -> None:
    """Refuse (exit 2) to present two repositories as one repository's posture drift.

    ``--before vulnerable-repo --after hardened-repo`` exited 0 through v10.0.6 and
    announced eleven improvements, none of which happened: nothing improved, the operator
    simply pointed the command at two unrelated repositories. Every field of that answer —
    the regression count the gate keys on, the improvement list, the "new"/"removed"
    controls — is a comparison of two repositories wearing the vocabulary of change over
    time, and nothing in the output said so.

    Refusing rather than warning is deliberate. The rendered artifact is the thing that
    travels: ``--format markdown`` exists to be pasted into a PR comment and ``--format
    json`` to be archived by CI, and a warning printed on stderr does not reach either of
    them. Exit 2 is the contract's "these inputs do not go together", and the one
    legitimate reading — deliberately comparing two repositories — is available by naming
    it, which also puts an intent on the record for whoever reads the CI log later.

    The refusal fires only when both reports name a repository and the names differ (see
    :func:`~oss_policy_kit.application.drift.target_identity`), so the everyday case of one
    target evaluated twice is untouched.
    """

    if not drift.target_mismatch:
        return
    before = drift.before_target or "?"
    after = drift.after_target or "?"
    if allow_different_targets:
        stderr_console().print(
            "[yellow]Warning:[/yellow] these reports describe different targets "
            f"([cyan]{markup_safe(before)}[/cyan] -> [cyan]{markup_safe(after)}[/cyan]), and "
            "--allow-different-targets was passed. Every line below is a difference between "
            "two repositories, not a posture change over time."
        )
        return
    raise InvalidInputError(
        f"--before and --after describe different targets ('{before}' -> '{after}'). "
        "Drift is the posture change of one target between two runs; across two "
        "repositories every difference between them is reported as a regression or an "
        "improvement that never happened. Pass two reports for the same target, or "
        "--allow-different-targets if comparing two repositories is what you meant."
    )


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
    allow_different_targets: bool = typer.Option(
        False,
        "--allow-different-targets",
        help=(
            "Diff two reports that were produced against different repositories. Refused by "
            "default: drift is the posture change of ONE target between two runs, so across "
            "two repositories every difference between them is reported as if the posture had "
            "moved. Use this only when comparing two repositories is what you actually meant "
            "(a fork against its upstream, a candidate against a reference repository)."
        ),
    ),
    include_absolute_path: bool = typer.Option(
        False,
        "--include-absolute-path",
        help=(
            "Keep the full absolute input paths in the rendered drift report. Default is "
            "privacy-by-default: the Before/After paths are sanitized to the report file's "
            "basename. Use this flag only when downstream tooling specifically expects an "
            "absolute path; the markdown output is meant to be pasted into a PR comment, "
            "and absolute paths there leak the auditor's home directory or username."
        ),
    ),
) -> None:
    """Compare two evaluation reports and show posture drift."""

    try:
        if fmt.strip().lower() not in _DIFF_FORMATS:
            raise InvalidInputError(f"--format must be one of: {', '.join(_DIFF_FORMATS)} (got {fmt!r}).")
        if not before.is_file():
            raise InvalidInputError(f"--before not found: {before}")
        if not after.is_file():
            raise InvalidInputError(f"--after not found: {after}")
        # The label names the side, so a malformed --before and a malformed --after can no
        # longer produce byte-identical rejections ("Expecting value: line 1 column 1").
        b = load_report_json(before, label="--before report")
        a = load_report_json(after, label="--after report")
        for side, payload in (("--before", b), ("--after", a)):
            unverified = payload.get(UNVERIFIED_DIGEST_KEY)
            if unverified:
                stderr_console().print(
                    f"[yellow]Warning:[/yellow] {markup_safe(side)} report: {markup_safe(str(unverified))}"
                )
        drift = compute_drift(b, a, include_absolute_path=include_absolute_path)
        _guard_target_mismatch(drift, allow_different_targets=allow_different_targets)
        if drift.profile_mismatch:
            stderr_console().print(
                "[yellow]Warning:[/yellow] profiles differ "
                f"([cyan]{markup_safe(drift.before_profile_id)}[/cyan] → "
                f"[cyan]{markup_safe(drift.after_profile_id)}[/cyan]). "
                "Controls listed under 'New in after' or 'Removed from after' may reflect "
                "a profile scope change rather than a posture change."
            )
        text = render_drift_report(drift, fmt, color=terminal_ui.human_tty_stdout())
        write_stdout_text(text)
        if drift.has_regressions and fail_on_regression:
            raise typer.Exit(code=1)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except ValueError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc)}")
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # noqa: BLE001
        exit_for_unexpected(exc)
