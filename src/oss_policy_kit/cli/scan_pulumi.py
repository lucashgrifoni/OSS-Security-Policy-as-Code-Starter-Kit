"""``oss-policy-kit scan-pulumi`` subcommand.

Discovers Pulumi Python programs under the target, runs the bundled
``IAC-PUL-*`` rule pack, and writes
``.oss-policy-kit/evidence/iac-pulumi.json`` (schema
``oss-policy-kit/evidence/iac-pulumi/v1``).

Pulumi TypeScript / Go / .NET programs are out of scope for v5.7.0.
"""

from __future__ import annotations

import json
import sys

import typer

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.cli.common import app, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_SCAN
from oss_policy_kit.domain.errors import OssPolicyKitError
from oss_policy_kit.infrastructure.iac.pulumi.scanner import (
    DEFAULT_INCLUDE_GLOBS,
    DEFAULT_TIMEOUT_SECONDS,
    EVIDENCE_FILENAME,
    render_evidence_payload,
    run_scan,
    write_evidence,
)


@app.command("scan-pulumi", rich_help_panel=CMD_PANEL_SCAN)
def scan_pulumi_cmd(
    target: str = typer.Option(
        ".",
        "--target",
        "-t",
        help="Repository root to scan for Pulumi Python programs. Defaults to the current directory.",
    ),
    include: str = typer.Option(
        ",".join(DEFAULT_INCLUDE_GLOBS),
        "--include",
        help="Comma-separated glob patterns for source files. Defaults to '**/*.py'.",
    ),
    exclude: str = typer.Option(
        "",
        "--exclude",
        help="Comma-separated glob patterns to skip (matched against full paths).",
    ),
    timeout: int = typer.Option(
        DEFAULT_TIMEOUT_SECONDS,
        "--timeout",
        help="Wall-clock timeout for the parser, in seconds.",
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        help="Stdout format for the summary line: human or json.",
        case_sensitive=False,
    ),
) -> None:
    """Run the bundled Pulumi rule pack and write IAC-PUL-* evidence."""

    fmt = output_format.strip().lower()
    if fmt not in {"human", "json"}:
        raise typer.BadParameter("--format must be human or json.")

    try:
        repo = resolve_existing_dir(target)
        include_tuple = tuple(g.strip() for g in include.split(",") if g.strip())
        if not include_tuple:
            include_tuple = DEFAULT_INCLUDE_GLOBS
        exclude_tuple = tuple(g.strip() for g in exclude.split(",") if g.strip()) or None

        outcome = run_scan(
            repo,
            include_globs=include_tuple,
            exclude_globs=exclude_tuple,
            timeout_seconds=timeout,
        )
        payload = render_evidence_payload(outcome, target=repo)
        evidence_path = write_evidence(payload, repo_root=repo, filename=EVIDENCE_FILENAME)

        if outcome.status == "error":
            stderr_console().print(
                f"[red]Pulumi scan failed:[/red] see diagnostics in {evidence_path.name}.",
            )
            raise typer.Exit(code=2)

        if fmt == "json":
            sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        else:
            write_stdout_text(
                f"scan-pulumi: {outcome.status} -- "
                f"files={len(outcome.files_scanned)} "
                f"findings={len(outcome.findings)} "
                f"-> {evidence_path}\n",
            )
            if outcome.parse_errors:
                stderr_console().print(
                    f"[yellow]{len(outcome.parse_errors)} file(s) failed to parse[/yellow]; "
                    "see diagnostics.parse_errors in the evidence file.",
                )

    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except OSError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # noqa: BLE001 - last-resort user message
        stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc
