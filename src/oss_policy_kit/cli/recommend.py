"""`recommend-profile` subcommand: heuristic guidance from repo layout."""

from __future__ import annotations

import json
import sys

import typer

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.application.profile_hints import ProfileRecommendation, build_profile_recommendation
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.common import (
    app,
    normalize_recommend_format,
    stderr_console,
    write_wrapped_stdout_block,
)
from oss_policy_kit.cli.help_text import CMD_PANEL_DISCOVER
from oss_policy_kit.domain.errors import OssPolicyKitError


def _write_recommend_text(rec: ProfileRecommendation) -> None:
    """Write the plain-text (non-TTY) profile recommendation block to stdout."""

    sys.stdout.write("Profile suggestions (heuristic, not a compliance decision):\n")
    for s in rec.suggestions:
        sys.stdout.write(f"  {s['profile_id']}\n")
        write_wrapped_stdout_block("    -> ", s["rationale"], "       ")
    if rec.signals_detected:
        sys.stdout.write("\nObserved signals:\n")
        for sig in rec.signals_detected:
            prefix = f"  - [{sig['id']}] "
            write_wrapped_stdout_block(prefix, str(sig["detail"]), " " * len(prefix))
    if rec.notes:
        sys.stdout.write("\nNotes:\n")
        for note in rec.notes:
            write_wrapped_stdout_block("  - ", str(note), "    ")


@app.command("recommend-profile", rich_help_panel=CMD_PANEL_DISCOVER)
def recommend_profile_cmd(
    target: str = typer.Option(..., "--target", "-t", help="Repository root to inspect for CI platform signals."),
    output_format: str = typer.Option(
        "human",
        "--format",
        "-f",
        help="human (default) or json on stdout; aliases table, compact -> human.",
        case_sensitive=False,
    ),
) -> None:
    """Suggest starter profiles from repository layout (heuristic; not a compliance decision)."""

    try:
        fmt = normalize_recommend_format(output_format)
        repo = resolve_existing_dir(target)
        rec = build_profile_recommendation(repo)
        if fmt == "json":
            sys.stdout.write(json.dumps(rec.to_json_dict(), ensure_ascii=False, indent=2) + "\n")
        elif terminal_ui.human_tty_stdout():
            terminal_ui.print_recommend_profile_human_rich(rec, repo_root=repo)
        else:
            _write_recommend_text(rec)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
