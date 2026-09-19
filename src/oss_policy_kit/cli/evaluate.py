"""`evaluate` subcommand and root-callback compatibility entry."""

from __future__ import annotations

from pathlib import Path

import typer
from typer import Context

from oss_policy_kit import __version__ as kit_version
from oss_policy_kit.cli.common import (
    EvaluateRequest,
    NonEmptyPath,
    app,
    enable_debug_logging,
    execute_evaluate,
    markup_safe,
    stderr_console,
)
from oss_policy_kit.cli.help_text import (
    CMD_PANEL_EVALUATE,
    EVALUATE_EPILOG,
    OPT_PANEL_CI,
    OPT_PANEL_CORE,
    OPT_PANEL_DIAGNOSTICS,
    OPT_PANEL_EVIDENCE,
    OPT_PANEL_META,
    OPT_PANEL_OUTPUT,
)
from oss_policy_kit.cli.profiles import _print_profiles_table
from oss_policy_kit.domain.errors import LoadError


def _flag_was_provided(ctx: Context, name: str) -> bool:
    """Return True when the user passed CLI option *name* (not the typer default).

    Uses Click's parameter-source provenance so an explicit flag can be told apart
    from its default even when the value coincides (``--fail-on none`` vs. omission).
    Any non-``DEFAULT`` source (command line, env var, prompt) counts as provided so
    the project config only fills genuinely-unset options (X5-03). Falls back to
    ``False`` (= "let the config decide") if provenance is unavailable, which is the
    behavior the user expects when they did not type the flag.

    The source is compared by enum ``name`` rather than by importing a
    ``ParameterSource`` class: Typer vendors its own Click (``typer._click``), so a
    ``ParameterSource`` imported from top-level ``click`` can be a *different* class
    than the one the runtime returns, making ``!=`` always true. The ``.name`` string
    is stable across both.
    """

    try:
        source = ctx.get_parameter_source(name)
    except Exception:  # noqa: BLE001 - provenance is best-effort; never crash the CLI
        return False
    if source is None:
        return False
    return getattr(source, "name", "") != "DEFAULT"


@app.callback(invoke_without_command=True)
def cli_root(
    ctx: Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show kit version and exit.",
        is_eager=True,
        rich_help_panel=OPT_PANEL_META,
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
        rich_help_panel=OPT_PANEL_CORE,
    ),
    show_profiles: bool = typer.Option(
        False,
        "--show-profiles",
        "-sp",
        help=(
            "DEPRECATED — use the 'profiles' subcommand. Show bundled profiles with full "
            "audience and description details, and exit."
        ),
        rich_help_panel=OPT_PANEL_META,
    ),
    output_dir: Path = typer.Option(
        Path("out"),
        "--output-dir",
        "-o",
        click_type=NonEmptyPath(),
        help="Directory where evaluation-report.json and evaluation-report.md will be written.",
        rich_help_panel=OPT_PANEL_OUTPUT,
    ),
    waivers: Path | None = typer.Option(
        None,
        "--waivers",
        "-w",
        help="Optional waivers YAML file.",
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    scorecard_json: Path | None = typer.Option(
        None,
        "--scorecard-json",
        "-sj",
        help="Optional OpenSSF Scorecard export used as supplemental evidence.",
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    kit_root: Path | None = typer.Option(
        None,
        "--kit-root",
        "-k",
        help="Override the bundled controls/ and profiles/ directory.",
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    target_opt: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help="Repository root to evaluate.",
        rich_help_panel=OPT_PANEL_CORE,
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
        rich_help_panel=OPT_PANEL_OUTPUT,
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        "-so",
        help=(
            "Print only the summary on stdout. Also silences the stderr file-write confirmations, "
            "and under --format json the operational-warning summary, so '--format json --summary-only' "
            "stays parseable JSON even with stderr merged into stdout (--verbose/--debug still write "
            "there). Drop --summary-only to see them."
        ),
        rich_help_panel=OPT_PANEL_OUTPUT,
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
        rich_help_panel=OPT_PANEL_CI,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help=(
            "Print per-control evaluation lines (dim), pipe-friendly. Human mode writes them "
            "to stdout; under --format json they go to stderr so stdout stays parseable JSON."
        ),
        rich_help_panel=OPT_PANEL_DIAGNOSTICS,
    ),
    report_json_contract: str = typer.Option(
        "2.0",
        "--report-json-contract",
        help=(
            "evaluation-report.json contract: only '2.0' is valid since v9.0.0 (ADR-043). "
            "The value is normalized before checking (case-insensitive, surrounding whitespace "
            "trimmed, an optional leading 'v' dropped), so '2.0', 'V2.0', and ' v2.0 ' are all "
            "accepted as 2.0. Any value that does not normalize to '2.0' (incl. the removed "
            "0.1/0.2/0.3/1.0) exits 2."
        ),
        case_sensitive=False,
        rich_help_panel=OPT_PANEL_OUTPUT,
    ),
    sarif_output: Path | None = typer.Option(
        None,
        "--sarif-output",
        help=(
            "Optional SARIF 2.1.0 output path. If relative, resolved under --output-dir. "
            "Emits one SARIF result per fail or manual-review-required finding."
        ),
        rich_help_panel=OPT_PANEL_OUTPUT,
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress operational warning lines on stderr while keeping normal stdout output.",
        rich_help_panel=OPT_PANEL_DIAGNOSTICS,
    ),
    use_insights_evidence: bool = typer.Option(
        False,
        "--use-insights-evidence",
        help=(
            "Opt-in (ADR-033): treat a target's SECURITY-INSIGHTS.yml as self-attested evidence "
            "for disclosure controls GOV-DISC-013, CRA-ART14-COORD-002, GOV-DISC-065. "
            "Self-reported only; never overrides a deterministic fail. Default off."
        ),
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    applicability_engine: bool = typer.Option(
        True,
        "--applicability-engine/--no-applicability-engine",
        help=(
            "Default on since v8.0.0 (ADR-041): resolve controls that declare a precondition to "
            "NOT_APPLICABLE consistently when it is unmet, instead of per-evaluator ad-hoc handling. "
            "Use --no-applicability-engine to opt out for one deprecation cycle; never changes a "
            "control whose precondition is met."
        ),
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    enable_attested: bool = typer.Option(
        True,
        "--enable-attested/--no-enable-attested",
        help=(
            "Default on since v8.0.0 (ADR-041): when a control's pass is anchored on a verified "
            "attestation record (PROV-VERIFY-061: transparency-log inclusion + fresh verified_at), "
            "resolve it to ATTESTED instead of PASS. Use --no-enable-attested to opt out for one "
            "deprecation cycle; never relaxes a FAIL/MRR."
        ),
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    with_findings_summary: bool = typer.Option(
        False,
        "--with-findings-summary",
        help=(
            "Embed an additive extensions.findings_summary block (correlated scanner-finding "
            "counts), computed in-process from this same run. Never changes control states, "
            "summary, digest, or exit codes."
        ),
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help=(
            "Emit detailed diagnostics to stderr (which evaluator ran, each outcome and its "
            "evidence). Opt-in; stdout output is unchanged. Place before a subcommand, e.g. "
            "`oss-policy-kit --debug evaluate ...`."
        ),
        rich_help_panel=OPT_PANEL_DIAGNOSTICS,
    ),
) -> None:
    """Evaluate without typing `evaluate` (same flags as the subcommand)."""

    if debug:
        enable_debug_logging()
    if version:
        typer.echo(kit_version)
        raise typer.Exit(0)
    if show_profiles:
        stderr_console().print(
            "[yellow]Deprecation:[/yellow] --show-profiles is deprecated; "
            "use the 'profiles' subcommand "
            "(e.g. `python -P -m oss_policy_kit profiles`)."
        )
        try:
            _print_profiles_table(detailed=True, compact_layout=False)
        except LoadError as exc:
            stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
            raise typer.Exit(code=2) from exc
        raise typer.Exit(0)
    if ctx.invoked_subcommand is not None:
        return
    # ``profile`` may be ``None`` here: ``execute_evaluate`` will look for
    # ``oss-policy-kit.yaml`` under the resolved target and either use its
    # profile or raise a clean InvalidInputError when neither is present.
    execute_evaluate(
        EvaluateRequest(
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
            # Passed through verbatim: ``report_json_schema_url`` owns the single
            # normalization pass. Pre-normalizing here made it run twice, so 'vv2.0'
            # was accepted despite the documented single optional leading 'v', and the
            # rejection message quoted a value the user never typed.
            report_json_contract=report_json_contract,
            use_insights_evidence=use_insights_evidence,
            applicability_engine=applicability_engine,
            enable_attested=enable_attested,
            with_findings_summary=with_findings_summary,
            fail_on_provided=_flag_was_provided(ctx, "fail_on"),
            output_dir_provided=_flag_was_provided(ctx, "output_dir"),
            report_json_contract_provided=_flag_was_provided(ctx, "report_json_contract"),
        )
    )


@app.command("evaluate", epilog=EVALUATE_EPILOG, rich_help_panel=CMD_PANEL_EVALUATE)
def evaluate_cmd(
    ctx: Context,
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
        rich_help_panel=OPT_PANEL_CORE,
    ),
    output_dir: Path = typer.Option(
        Path("out"),
        "--output-dir",
        "-o",
        click_type=NonEmptyPath(),
        help="Directory where evaluation-report.json and evaluation-report.md will be written.",
        rich_help_panel=OPT_PANEL_OUTPUT,
    ),
    waivers: Path | None = typer.Option(
        None,
        "--waivers",
        "-w",
        help="Optional waivers YAML file.",
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    scorecard_json: Path | None = typer.Option(
        None,
        "--scorecard-json",
        "-sj",
        help="Optional OpenSSF Scorecard export used as supplemental evidence.",
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    kit_root: Path | None = typer.Option(
        None,
        "--kit-root",
        "-k",
        help="Override the bundled controls/ and profiles/ directory.",
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    target_opt: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help="Repository root to evaluate.",
        rich_help_panel=OPT_PANEL_CORE,
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
        rich_help_panel=OPT_PANEL_OUTPUT,
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        "-so",
        help=(
            "Print only the summary on stdout. Also silences the stderr file-write confirmations, "
            "and under --format json the operational-warning summary, so '--format json --summary-only' "
            "stays parseable JSON even with stderr merged into stdout (--verbose/--debug still write "
            "there). Drop --summary-only to see them."
        ),
        rich_help_panel=OPT_PANEL_OUTPUT,
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
        rich_help_panel=OPT_PANEL_CI,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help=(
            "Print per-control evaluation lines (dim), pipe-friendly. Human mode writes them "
            "to stdout; under --format json they go to stderr so stdout stays parseable JSON."
        ),
        rich_help_panel=OPT_PANEL_DIAGNOSTICS,
    ),
    report_json_contract: str = typer.Option(
        "2.0",
        "--report-json-contract",
        help=(
            "evaluation-report.json contract: only '2.0' is valid since v9.0.0 (ADR-043). "
            "The value is normalized before checking (case-insensitive, surrounding whitespace "
            "trimmed, an optional leading 'v' dropped), so '2.0', 'V2.0', and ' v2.0 ' are all "
            "accepted as 2.0. Any value that does not normalize to '2.0' (incl. the removed "
            "0.1/0.2/0.3/1.0) exits 2."
        ),
        case_sensitive=False,
        rich_help_panel=OPT_PANEL_OUTPUT,
    ),
    sarif_output: Path | None = typer.Option(
        None,
        "--sarif-output",
        help=(
            "Optional SARIF 2.1.0 output path. If relative, resolved under --output-dir. "
            "Emits one SARIF result per fail or manual-review-required finding."
        ),
        rich_help_panel=OPT_PANEL_OUTPUT,
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress operational warning lines on stderr while keeping normal stdout output.",
        rich_help_panel=OPT_PANEL_DIAGNOSTICS,
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
        rich_help_panel=OPT_PANEL_OUTPUT,
    ),
    use_insights_evidence: bool = typer.Option(
        False,
        "--use-insights-evidence",
        help=(
            "Opt-in (ADR-033): treat a target's SECURITY-INSIGHTS.yml as self-attested evidence "
            "for disclosure controls GOV-DISC-013, CRA-ART14-COORD-002, GOV-DISC-065. "
            "Self-reported only; never overrides a deterministic fail. Default off."
        ),
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    applicability_engine: bool = typer.Option(
        True,
        "--applicability-engine/--no-applicability-engine",
        help=(
            "Default on since v8.0.0 (ADR-041): resolve controls that declare a precondition to "
            "NOT_APPLICABLE consistently when it is unmet, instead of per-evaluator ad-hoc handling. "
            "Use --no-applicability-engine to opt out for one deprecation cycle; never changes a "
            "control whose precondition is met."
        ),
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    enable_attested: bool = typer.Option(
        True,
        "--enable-attested/--no-enable-attested",
        help=(
            "Default on since v8.0.0 (ADR-041): when a control's pass is anchored on a verified "
            "attestation record (PROV-VERIFY-061: transparency-log inclusion + fresh verified_at), "
            "resolve it to ATTESTED instead of PASS. Use --no-enable-attested to opt out for one "
            "deprecation cycle; never relaxes a FAIL/MRR."
        ),
        rich_help_panel=OPT_PANEL_EVIDENCE,
    ),
    with_findings_summary: bool = typer.Option(
        False,
        "--with-findings-summary",
        help=(
            "Embed an additive extensions.findings_summary block (correlated scanner-finding "
            "counts), computed in-process from this same run. Never changes control states, "
            "summary, digest, or exit codes."
        ),
    ),
) -> None:
    """Evaluate a local repository clone against a bundled profile.

    Use this command when you want a full evaluation report written to disk.

    Preferred form:
      python -P -m oss_policy_kit evaluate --target <repo> --profile <profile>

    You can also pass the repository path positionally:
      python -P -m oss_policy_kit evaluate <repo> --profile <profile>

    Outputs:
      - evaluation-report.json
      - evaluation-report.md
      - evaluation-report.sarif (only when --sarif-output is set)
    """

    execute_evaluate(
        EvaluateRequest(
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
            # Passed through verbatim: ``report_json_schema_url`` owns the single
            # normalization pass. Pre-normalizing here made it run twice, so 'vv2.0'
            # was accepted despite the documented single optional leading 'v', and the
            # rejection message quoted a value the user never typed.
            report_json_contract=report_json_contract,
            sarif_output=sarif_output,
            include_absolute_path=include_absolute_path,
            use_insights_evidence=use_insights_evidence,
            applicability_engine=applicability_engine,
            enable_attested=enable_attested,
            with_findings_summary=with_findings_summary,
            fail_on_provided=_flag_was_provided(ctx, "fail_on"),
            output_dir_provided=_flag_was_provided(ctx, "output_dir"),
            report_json_contract_provided=_flag_was_provided(ctx, "report_json_contract"),
        )
    )
