"""`evaluate` subcommand and root-callback compatibility entry."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from typer import Context

from oss_policy_kit import __version__ as kit_version
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.common import (
    app,
    execute_evaluate,
    stderr_console,
)
from oss_policy_kit.cli.help_text import EVALUATE_EPILOG
from oss_policy_kit.cli.profiles import _print_profiles_table
from oss_policy_kit.domain.errors import LoadError


@app.callback(invoke_without_command=True)
def cli_root(
    ctx: Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show kit version and exit.",
        is_eager=True,
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help=(
            "Profile ID (e.g. github-level-1) or path to an external YAML profile (e.g. ./my-profile.yaml). "
            "External YAML required fields: id, title, controls (list of control IDs). "
            "Use the 'profiles' subcommand to list built-in options."
        ),
    ),
    show_profiles: bool = typer.Option(
        False,
        "--show-profiles",
        "-sp",
        help="Show bundled profiles with full audience and description details, and exit.",
    ),
    output_dir: Path = typer.Option(
        Path("out"),
        "--output-dir",
        "-o",
        help="Directory where evaluation-report.json and evaluation-report.md will be written.",
    ),
    waivers: Path | None = typer.Option(
        None,
        "--waivers",
        "-w",
        help="Optional waivers YAML file.",
    ),
    scorecard_json: Path | None = typer.Option(
        None,
        "--scorecard-json",
        "-sj",
        help="Optional OpenSSF Scorecard export used as supplemental evidence.",
    ),
    kit_root: Path | None = typer.Option(
        None,
        "--kit-root",
        "-k",
        help="Override the bundled controls/ and profiles/ directory.",
    ),
    target_opt: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help="Repository root to evaluate.",
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        "-f",
        help=(
            "Stdout summary format: human (default) or json. "
            "In json mode, a compact summary is written to stdout and file-write confirmations go to stderr. "
            "Aliases: table, compact, detailed -> human layout."
        ),
        case_sensitive=False,
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        "-so",
        help="Print only the summary on stdout.",
    ),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        "-fo",
        help=(
            "CI gate mode: none, fail, or degraded. "
            "none=never fail from result statuses; fail=exit 1 on any fail; "
            "degraded=exit 1 on fail or manual-review-required. "
            "Operational warnings alone do not trigger this gate."
        ),
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Print per-control evaluation lines to stdout (dim), pipe-friendly.",
    ),
    report_json_contract: str = typer.Option(
        "1.0",
        "--report-json-contract",
        help=(
            "evaluation-report.json contract: 1.0 (default, structured evidence), 0.3, or 0.2. '0.1' was removed in v5."
        ),
        case_sensitive=False,
    ),
    sarif_output: Path | None = typer.Option(
        None,
        "--sarif-output",
        help=(
            "Optional SARIF 2.1.0 output path. If relative, resolved under --output-dir. "
            "Emits one SARIF result per fail or manual-review-required finding."
        ),
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress operational warning lines on stderr while keeping normal stdout output.",
    ),
) -> None:
    """Evaluate without typing `evaluate` (same flags as the subcommand)."""

    if version:
        typer.echo(kit_version)
        raise typer.Exit(0)
    if show_profiles:
        try:
            _print_profiles_table(detailed=True, compact_layout=False)
        except LoadError as exc:
            stderr_console().print(f"[red]Error:[/red] {exc.message}")
            raise typer.Exit(code=2) from exc
        raise typer.Exit(0)
    if ctx.invoked_subcommand is not None:
        return
    if profile is None:
        err = (
            "--profile is required when running without the `evaluate` subcommand "
            "(for example: `python -m oss_policy_kit --target . --profile github-level-1`)."
        )
        wrapped = terminal_ui.human_wrap_lines(err, stream=sys.stderr, subtract=10)
        wlines = wrapped.split("\n")
        stderr_console().print(f"[red]Error:[/red] {wlines[0]}")
        for ln in wlines[1:]:
            stderr_console().print(ln)
        raise typer.Exit(code=2)
    execute_evaluate(
        target_pos=None,
        target_opt=target_opt,
        profile=profile,
        output_dir=output_dir,
        waivers=waivers,
        scorecard_json=scorecard_json,
        kit_root=kit_root,
        output_format=output_format.lower(),
        summary_only=summary_only,
        fail_on=fail_on.lower(),
        verbose=verbose,
        sarif_output=sarif_output,
        quiet=quiet,
        report_json_contract=report_json_contract.strip().lower().removeprefix("v"),
    )


@app.command("evaluate", epilog=EVALUATE_EPILOG)
def evaluate_cmd(
    target_pos: str | None = typer.Argument(
        default=None,
        help="Repository root. Prefer --target/-t if the path contains spaces.",
    ),
    profile: str = typer.Option(
        ...,
        "--profile",
        "-p",
        help=(
            "Profile ID (e.g. github-level-1) or path to an external YAML profile (e.g. ./my-profile.yaml). "
            "External YAML required fields: id, title, controls (list of control IDs). "
            "Use the 'profiles' subcommand to list built-in options."
        ),
    ),
    output_dir: Path = typer.Option(
        Path("out"),
        "--output-dir",
        "-o",
        help="Directory where evaluation-report.json and evaluation-report.md will be written.",
    ),
    waivers: Path | None = typer.Option(
        None,
        "--waivers",
        "-w",
        help="Optional waivers YAML file.",
    ),
    scorecard_json: Path | None = typer.Option(
        None,
        "--scorecard-json",
        "-sj",
        help="Optional OpenSSF Scorecard export used as supplemental evidence.",
    ),
    kit_root: Path | None = typer.Option(
        None,
        "--kit-root",
        "-k",
        help="Override the bundled controls/ and profiles/ directory.",
    ),
    target_opt: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help="Repository root to evaluate.",
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        "-f",
        help=(
            "Stdout summary format: human (default) or json. "
            "In json mode, stdout is JSON only; where files were written is repeated on stderr. "
            "Aliases: table, compact, detailed -> human layout."
        ),
        case_sensitive=False,
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        "-so",
        help="Print only the summary on stdout.",
    ),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        "-fo",
        help=(
            "CI gate mode: none, fail, or degraded. "
            "none=never fail from result statuses; fail=exit 1 on any fail; "
            "degraded=exit 1 on fail or manual-review-required. "
            "Operational warnings alone do not trigger this gate."
        ),
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Print per-control evaluation lines to stdout (dim); json mode unchanged.",
    ),
    report_json_contract: str = typer.Option(
        "1.0",
        "--report-json-contract",
        help=(
            "evaluation-report.json contract: 1.0 (default, structured evidence), 0.3, or 0.2. '0.1' was removed in v5."
        ),
        case_sensitive=False,
    ),
    sarif_output: Path | None = typer.Option(
        None,
        "--sarif-output",
        help=(
            "Optional SARIF 2.1.0 output path. If relative, resolved under --output-dir. "
            "Emits one SARIF result per fail or manual-review-required finding."
        ),
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress operational warning lines on stderr while keeping normal stdout output.",
    ),
) -> None:
    """Evaluate a local repository clone against a bundled profile.

    Use this command when you want a full evaluation report written to disk.

    Preferred form:
      python -m oss_policy_kit evaluate --target <repo> --profile <profile>

    You can also pass the repository path positionally:
      python -m oss_policy_kit evaluate <repo> --profile <profile>

    Outputs:
      - evaluation-report.json
      - evaluation-report.md
      - evaluation-report.sarif (only when --sarif-output is set)
    """

    execute_evaluate(
        target_pos=target_pos,
        target_opt=target_opt,
        profile=profile,
        output_dir=output_dir,
        waivers=waivers,
        scorecard_json=scorecard_json,
        kit_root=kit_root,
        output_format=output_format,
        summary_only=summary_only,
        fail_on=fail_on,
        verbose=verbose,
        quiet=quiet,
        report_json_contract=report_json_contract.strip().lower().removeprefix("v"),
        sarif_output=sarif_output,
    )
