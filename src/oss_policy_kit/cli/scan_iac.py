"""``oss-policy-kit scan-iac`` subcommand.

Discovers ``*.tf`` files under the target, runs the bundled
Terraform / OpenTofu rule pack, and writes
``.oss-policy-kit/evidence/iac-terraform.json`` (schema
``oss-policy-kit/evidence/iac-terraform/v1``). Each ``IAC-TF-*`` control
reads that file on the next ``evaluate`` run.

Mirrors the design of ``scan-sast``:
- exit 0 even when ``python-hcl2`` is missing -- evidence is written with
  ``status: not_available`` so the next ``evaluate`` surfaces the gap;
- exit 2 on user-correctable errors (bad target);
- exit 3 on unexpected errors (re-raised stack trace).
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
from oss_policy_kit.infrastructure.iac.scanner import (
    DEFAULT_INCLUDE_GLOBS,
    DEFAULT_TIMEOUT_SECONDS,
    EVIDENCE_FILENAME,
    render_evidence_payload,
    run_scan,
    write_evidence,
)

# Rich parses ``[iac]`` as a markup tag and silently drops it, which turned the
# remediation into the no-op ``pip install 'oss-policy-kit'``. ``\[`` is Rich's
# literal-bracket escape, so the printed command matches the JSON diagnostics.
_IAC_EXTRA_INSTALL_CMD = r"pip install 'oss-policy-kit\[iac]'"


@app.command("scan-iac", rich_help_panel=CMD_PANEL_SCAN)
def scan_iac_cmd(
    target: str = typer.Option(
        ".",
        "--target",
        "-t",
        help="Repository root to scan for Terraform / OpenTofu files. Defaults to the current directory.",
    ),
    include: str = typer.Option(
        ",".join(DEFAULT_INCLUDE_GLOBS),
        "--include",
        help="Comma-separated glob patterns for source files. Defaults to '**/*.tf'.",
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
    """Run the bundled Terraform / OpenTofu rule pack and write IAC-TF-* evidence.

    Exit codes:

    - 0: Scan completed (or python-hcl2 is not installed -- evidence still
      written with ``status: not_available`` so the next ``evaluate``
      surfaces the gap honestly).
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
            # Name the containing directory, not just the file: `write_evidence` always
            # writes under `.oss-policy-kit/evidence/`, a dot-directory the operator has
            # no reason to guess. Kept repo-relative so no host path reaches stderr.
            stderr_console().print(
                f"[red]Terraform scan failed:[/red] see diagnostics in "
                f".oss-policy-kit/evidence/{evidence_path.name} (relative to --target).",
            )
            raise typer.Exit(code=2)

        if fmt == "json":
            sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        else:
            # `write_evidence` returns the resolved path, and echoing it answered a relative
            # --target with the host layout on a clean run -- the common case, not the rare
            # one (M-002). `redact_home` is not the guard here: it rewrites paths under HOME
            # and leaves every other absolute path whole, so a target outside HOME shipped
            # the lot. Rendered at the point of display, so the write keeps its own contract.
            write_stdout_text(
                f"scan-iac: {outcome.status} -- "
                f"files={len(outcome.files_scanned)} "
                f"findings={len(outcome.findings)} "
                f"-> {display_path(evidence_path, root=repo)}\n",
            )
            if outcome.status == "not_available":
                stderr_console().print(
                    "[yellow]python-hcl2 is not installed.[/yellow] "
                    f"Install the iac extra with `{_IAC_EXTRA_INSTALL_CMD}` to enable real findings.",
                )
            elif outcome.parse_errors:
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
