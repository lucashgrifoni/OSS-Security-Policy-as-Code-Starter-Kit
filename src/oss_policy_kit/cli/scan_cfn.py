"""``oss-policy-kit scan-cfn`` subcommand.

Discovers CloudFormation templates under the target, runs the bundled
``IAC-CFN-*`` rule pack, and writes
``.oss-policy-kit/evidence/iac-cfn.json`` (schema
``oss-policy-kit/evidence/iac-cfn/v1``). Each ``IAC-CFN-*`` control reads
that file on the next ``evaluate`` run.

Mirrors the design of ``scan-iac`` (Terraform) and ``scan-k8s``.
"""

from __future__ import annotations

import json
import sys

import typer

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.cli.common import (
    app,
    display_path,
    exit_for_unexpected,
    markup_safe,
    stderr_console,
    write_stdout_text,
)
from oss_policy_kit.cli.help_text import CMD_PANEL_SCAN
from oss_policy_kit.cli.scan_errors import exit_for_unwritable_evidence
from oss_policy_kit.domain.errors import OssPolicyKitError
from oss_policy_kit.infrastructure.iac.cfn.scanner import (
    DEFAULT_INCLUDE_GLOBS,
    DEFAULT_TIMEOUT_SECONDS,
    EVIDENCE_FILENAME,
    render_evidence_payload,
    run_scan,
    write_evidence,
)


@app.command("scan-cfn", rich_help_panel=CMD_PANEL_SCAN)
def scan_cfn_cmd(
    target: str = typer.Option(
        ".",
        "--target",
        "-t",
        help="Repository root to scan for CloudFormation templates. Defaults to the current directory.",
    ),
    include: str = typer.Option(
        ",".join(DEFAULT_INCLUDE_GLOBS),
        "--include",
        help=(
            "Comma-separated glob patterns for source files. Defaults to '**/*.yaml,**/*.yml,**/*.json,**/*.template'."
        ),
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
    """Run the bundled CloudFormation rule pack and write IAC-CFN-* evidence.

    Exit codes:

    - 0: Scan completed.
    - 2: User-correctable error (bad target).
    - 3: Unexpected error (re-raised stack trace inside the kit).
    """

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
                f"[red]CloudFormation scan failed:[/red] see diagnostics in {evidence_path.name}.",
            )
            raise typer.Exit(code=2)

        if fmt == "json":
            sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        else:
            write_stdout_text(
                f"scan-cfn: {outcome.status} -- "
                f"files={len(outcome.files_scanned)} "
                f"findings={len(outcome.findings)} "
                f"-> {display_path(evidence_path, root=repo)}\n",
            )
            if outcome.parse_errors:
                stderr_console().print(
                    f"[yellow]{len(outcome.parse_errors)} file(s) failed to parse[/yellow]; "
                    "see diagnostics.parse_errors in the evidence file.",
                )

    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except OSError as exc:
        exit_for_unwritable_evidence(exc)
    except Exception as exc:  # noqa: BLE001 - last-resort user message
        exit_for_unexpected(exc)
