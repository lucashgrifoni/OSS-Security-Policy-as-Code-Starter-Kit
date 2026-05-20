"""`evaluate` subcommand and root-callback compatibility entry."""

from __future__ import annotations

from pathlib import Path

import typer
from typer import Context

from oss_policy_kit import __version__ as kit_version
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
        help=(
            "DEPRECATED — use the 'profiles' subcommand. Show bundled profiles with full "
            "audience and description details, and exit."
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
        help=("evaluation-report.json contract: 1.0 (default), 2.0, 0.3, or 0.2. '0.1' was removed in v5."),
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
        stderr_console().print(
            "[yellow]Deprecation:[/yellow] --show-profiles is deprecated; "
            "use the 'profiles' subcommand "
            "(e.g. `python -m oss_policy_kit profiles`)."
        )
        try:
            _print_profiles_table(detailed=True, compact_layout=False)
        except LoadError as exc:
            stderr_console().print(f"[red]Error:[/red] {exc.message}")
            raise typer.Exit(code=2) from exc
        raise typer.Exit(0)
    if ctx.invoked_subcommand is not None:
        return
    # ``profile`` may be ``None`` here: ``execute_evaluate`` will look for
    # ``oss-policy-kit.yaml`` under the resolved target and either use its
    # profile or raise a clean InvalidInputError when neither is present.
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
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help=(
            "Profile ID (e.g. github-level-1) or path to an external YAML profile. "
            "When omitted, evaluate looks for oss-policy-kit.yaml under --target and uses "
            "the profile recorded there (run `oss-policy-kit init` to create it). "
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
        help=("evaluation-report.json contract: 1.0 (default), 2.0, 0.3, or 0.2. '0.1' was removed in v5."),
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
    include_absolute_path: bool = typer.Option(
        False,
        "--include-absolute-path",
        help=(
            "Keep the full absolute path in target_path of the JSON/Markdown reports. "
            "Default is privacy-by-default: target_path is sanitized to the target's basename "
            "(or '.' when the target is the current working directory). Use this flag only "
            "when downstream tooling specifically expects an absolute path; sharing reports "
            "publicly with absolute paths leaks the auditor's home directory or username."
        ),
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
        include_absolute_path=include_absolute_path,
    )
