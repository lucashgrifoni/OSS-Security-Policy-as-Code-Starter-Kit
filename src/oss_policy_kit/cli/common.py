"""Shared Typer app, console plumbing, and `evaluate` shared implementation."""

from __future__ import annotations

import json
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import cast

import click
import typer
from rich.console import Console
from typer.core import HAS_RICH, TyperGroup

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.adapters.scorecard_json import load_scorecard_auto
from oss_policy_kit.application.cli_output import FailOnPolicy, fail_on_violated, print_stdout_summary
from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import (
    load_catalog,
    load_profile_by_id,
    merge_kit_root,
)
from oss_policy_kit.application.reporting import write_reports
from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.help_text import ROOT_CLI_EPILOG
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError


class OssPolicyKitTyperGroup(TyperGroup):
    """Root Click group: prepend the ASCII banner before Typer plain or Rich help."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        use_rich = bool(HAS_RICH and self.rich_markup_mode is not None)
        if not use_rich:
            terminal_ui.write_cli_banner_to_formatter(formatter)
            return super().format_help(ctx, formatter)

        terminal_ui.print_cli_banner_before_typer_rich_help()
        from typer import rich_utils as typer_rich_utils

        rich_mode = self.rich_markup_mode
        if rich_mode is None:
            return super().format_help(ctx, formatter)
        return typer_rich_utils.rich_format_help(
            obj=self,
            ctx=ctx,
            markup_mode=rich_mode,
        )


app = typer.Typer(
    name="oss-policy-kit",
    cls=OssPolicyKitTyperGroup,
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["--help", "-h"]},
    help=(
        "Evaluate a local repository clone against bundled OSS security profiles.\n\n"
        "Preferred usage:\n"
        "  python -m oss_policy_kit evaluate --target <repo> --profile <profile>\n\n"
        "Compatibility usage:\n"
        "  python -m oss_policy_kit --target <repo> --profile <profile>"
    ),
    epilog=ROOT_CLI_EPILOG,
)


def stderr_console() -> Console:
    """Rich console for stderr human messages (rebuilt so width tracks current ``sys.stderr``)."""

    return terminal_ui.build_stderr_console()


def write_stdout_text(text: str) -> None:
    """Write *text* to stdout; fall back to UTF-8 bytes when the console codepage cannot encode symbols."""

    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        buf = getattr(sys.stdout, "buffer", None)
        if buf is None:
            raise
        buf.write(text.encode("utf-8", errors="replace"))
        buf.flush()


def write_wrapped_stdout_block(prefix: str, body: str, continuation: str) -> None:
    """Write ``body`` to stdout wrapped to ``terminal_width``, preserving ``prefix`` on first line."""

    tw = max(20, terminal_ui.terminal_width(sys.stdout))
    chunk = max(12, tw - len(prefix))
    parts = textwrap.wrap(body, width=chunk, break_long_words=True, break_on_hyphens=False)
    if not parts:
        return
    sys.stdout.write(f"{prefix}{parts[0]}\n")
    for ln in parts[1:]:
        sys.stdout.write(f"{continuation}{ln}\n")


def normalize_evaluate_format(raw: str) -> str:
    """Map evaluate ``--format`` aliases to ``human`` or ``json``."""

    f = raw.lower().strip()
    if f == "json":
        return "json"
    if f in {"human", "table", "compact", "detailed"}:
        return "human"
    raise InvalidInputError(
        "--format must be human or json (aliases: table, compact, detailed all map to human stdout layout)."
    )


def normalize_profiles_format(raw: str) -> str:
    """Map profiles ``--format`` aliases to table/compact/detailed/json."""

    f = raw.lower().strip()
    if f == "human":
        return "compact"
    if f == "verbose":
        return "detailed"
    if f in {"detailed", "compact", "table", "json"}:
        return f
    raise InvalidInputError(
        "profiles --format must be one of: detailed, compact, table, json "
        "(aliases: human -> compact, verbose -> detailed)."
    )


def normalize_recommend_format(raw: str) -> str:
    """Map recommend-profile ``--format`` aliases."""

    f = raw.lower().strip()
    if f in {"human", "table", "compact"}:
        return "human"
    if f == "json":
        return "json"
    raise InvalidInputError("recommend-profile --format must be human or json (aliases: table, compact map to human).")


def warn_if_batch_skipped_directories(batch_json_path: Path) -> None:
    """Print a short stderr summary when the consolidated batch skipped one or more directories.

    Reads the batch JSON that `evaluate-many` just wrote and, if `skipped_directories` is non-empty,
    emits a single yellow line pointing operators at `evaluation-batch.json.skipped_directories`.
    Does not alter the batch JSON, the exit code, or the batch contract; fails silently if the file
    cannot be read for any reason (the main flow is the source of truth).
    """

    try:
        with batch_json_path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return
    skipped = payload.get("skipped_directories")
    if not isinstance(skipped, list) or not skipped:
        return
    count = len(skipped)
    suffix = "y" if count == 1 else "ies"
    stderr_console().print(
        f"[yellow]Skipped {count} director{suffix}[/yellow] under --skip-non-repos "
        f"(see {batch_json_path.name}.skipped_directories for details)."
    )


def print_operational_warning_summary(warnings: list[str]) -> None:
    """Surface a short warning summary on stderr without changing exit semantics."""

    if not warnings:
        return
    count = len(warnings)
    c = stderr_console()
    c.print(f"[dim]Operational warnings ({count})[/dim] [dim]-- see Markdown/JSON reports[/dim]")
    for msg in warnings[:3]:
        wrapped = terminal_ui.human_wrap_lines(msg, stream=sys.stderr, subtract=4)
        lines = wrapped.split("\n")
        if not lines:
            continue
        c.print(f"[dim]-[/dim] [dim]{lines[0]}[/dim]")
        for cont in lines[1:]:
            c.print(f"[dim]  {cont}[/dim]")


def prepare_cli_args(args: list[str]) -> list[str]:
    """Normalize argv so a leading repository path dispatches to the `evaluate` subcommand.

    Click/Typer parses optional group-level positionals before subcommand names. A bare
    ``python -m oss_policy_kit ./repo --profile ...`` would otherwise steal ``evaluate`` as a
    positional. Inserting ``evaluate`` keeps shell, subprocess, and CliRunner behavior aligned
    when the first token is a path-like argument (not an option and not already ``evaluate``).
    """

    if not args:
        return args
    first = args[0]
    if first in {
        "evaluate",
        "profiles",
        "evaluate-many",
        "scaffold-evidence",
        "collect-evidence",
        "diff-reports",
        "recommend-profile",
    }:
        return args
    if first in ("--help", "-h", "--version", "-V"):
        return args
    if first.startswith("-"):
        return args
    return ["evaluate", *args]


def execute_evaluate(
    target_pos: str | None,
    target_opt: str | None,
    profile: str,
    output_dir: Path,
    waivers: Path | None,
    scorecard_json: Path | None,
    kit_root: Path | None,
    *,
    output_format: str,
    summary_only: bool,
    fail_on: str,
    verbose: bool = False,
    quiet: bool = False,
    report_json_contract: str = "1.0",
    sarif_output: Path | None = None,
) -> None:
    """Shared implementation for root-level and `evaluate` subcommand invocations."""

    try:
        fmt = normalize_evaluate_format(output_format)
        policy = fail_on.lower()
        if policy not in {"none", "fail", "degraded"}:
            raise InvalidInputError("--fail-on must be one of: none, fail, degraded.")

        chosen = target_opt or target_pos
        if not chosen:
            raise InvalidInputError("Provide a repository path as TARGET or via --target/-t.")
        repo_root = resolve_existing_dir(chosen)
        root = merge_kit_root(kit_root)
        catalog_path = root / "controls" / "catalog.yaml"
        catalog = load_catalog(catalog_path)
        prof = load_profile_by_id(root, profile)

        waiver_outcome = None
        if waivers is not None:
            wp = Path(waivers)
            if not wp.is_file():
                raise InvalidInputError(f"Waivers file not found: {wp}")
            waiver_outcome = parse_waivers_file(wp)

        scorecard = None
        if scorecard_json is not None:
            sp = Path(scorecard_json)
            if not sp.is_file():
                raise InvalidInputError(f"Scorecard file not found: {sp}")
            scorecard = load_scorecard_auto(sp)

        ext_waiver = str(Path(waivers).resolve()) if waivers is not None else None
        emit: Callable[[str], None] | None
        if verbose:
            _verbose_console = terminal_ui.build_stdout_console()

            def emit(line: str) -> None:
                with _verbose_console.capture() as _cap:
                    _verbose_console.print(line)
                write_stdout_text(_cap.get())
        else:
            emit = None
        report = evaluate_repository(
            repo_root=repo_root,
            profile=prof,
            catalog=catalog,
            waiver_outcome=waiver_outcome,
            scorecard=scorecard,
            external_waiver_path=ext_waiver,
            verbose_emit=emit,
            report_json_contract=report_json_contract,
        )
        out = output_dir.resolve()
        json_path, md_path = write_reports(report, out)
        sarif_path: Path | None = None
        if sarif_output is not None:
            from oss_policy_kit.application.sarif_writer import write_sarif_report

            sarif_path = sarif_output if sarif_output.is_absolute() else out / sarif_output
            write_sarif_report(report, sarif_path)
            if not summary_only and output_format != "json":
                stderr_console().print(f"[green]Wrote[/green] {sarif_path}")
        machine_stdout = fmt == "json"
        if not summary_only and not machine_stdout:
            stderr_console().print(f"[green]Wrote[/green] {json_path}")
            stderr_console().print(f"[green]Wrote[/green] {md_path}")
        warnings = report.operational_warnings
        if machine_stdout:
            # ``--summary-only --format json``: stdout is the only user-facing channel (pure JSON).
            if not summary_only:
                stderr_console().print(f"[dim]Reports written to: {out}[/dim]")
                print_stdout_summary(report, output_format="json")
                if not quiet:
                    print_operational_warning_summary(warnings)
            else:
                print_stdout_summary(report, output_format="json")
        elif summary_only:
            print_stdout_summary(report, output_format="human")
            if not quiet:
                print_operational_warning_summary(warnings)
        else:
            if terminal_ui.human_tty_stdout():
                terminal_ui.print_evaluate_executive_preface(
                    report,
                    unicode_icons=terminal_ui.stream_supports_unicode(sys.stdout),
                )
            table = terminal_ui.render_eval_results_table(
                report,
                unicode_icons=terminal_ui.stream_supports_unicode(sys.stdout),
            )
            stdout_console = terminal_ui.build_stdout_console()
            with stdout_console.capture() as cap:
                stdout_console.print(table)
                status_str = "  ".join(f"{k}={v}" for k, v in sorted(report.summary_by_status.items()))
                stdout_console.print(
                    f"\n[dim]Summary: {status_str} | Controls: {len(report.results)} | Reports: {out}[/dim]"
                )
            write_stdout_text(cap.get())
            if not quiet:
                print_operational_warning_summary(warnings)
        if fail_on_violated(cast(FailOnPolicy, policy), report.summary_by_status):
            raise typer.Exit(code=1)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort user message
        stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc
