"""``oss-policy-kit scan-sast`` subcommand.

Runs the bundled SAST adapter (currently Semgrep) against the target and
writes a normalized evidence file under ``.oss-policy-kit/evidence/``.
The control ``SAST-SEMGREP-064`` consumes that evidence on the next
``evaluate`` run.

Design choices:

- Subcommand is intentionally small and Unix-y: scan, write evidence,
  print a one-line summary on stderr. Heavy formatting belongs to
  ``evaluate``, which already knows how to surface findings to operators.
- Failure modes are explicit: missing Semgrep -> exit 0 (evidence still
  written, status ``not_available``), scanner error -> exit 2, unexpected
  error -> exit 3. We do **not** trip ``--fail-on``-like behavior here:
  this command produces evidence; gating decisions live in ``evaluate``.
"""

from __future__ import annotations

import json
import sys

import typer

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.cli.common import (
    app,
    stderr_console,
    write_stdout_text,
)
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError
from oss_policy_kit.infrastructure.scanners.semgrep_adapter import (
    DEFAULT_RULESETS,
    DEFAULT_TIMEOUT_SECONDS,
    EVIDENCE_FILENAME,
    render_evidence_payload,
    run_semgrep,
    write_evidence,
)


@app.command("scan-sast")
def scan_sast_cmd(
    target: str = typer.Option(
        ".",
        "--target",
        "-t",
        help="Repository root to scan with Semgrep. Defaults to the current directory.",
    ),
    rulesets: str = typer.Option(
        ",".join(DEFAULT_RULESETS),
        "--rulesets",
        help=("Comma-separated list of Semgrep rulesets (e.g. auto, p/owasp-top-ten). Defaults to 'auto'."),
    ),
    timeout: int = typer.Option(
        DEFAULT_TIMEOUT_SECONDS,
        "--timeout",
        help="Wall-clock timeout for the Semgrep run, in seconds.",
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        help="Stdout format for the summary line: human or json.",
        case_sensitive=False,
    ),
) -> None:
    """Run Semgrep and write an evidence file for SAST-SEMGREP-064.

    Exit codes:

    - 0: Scan completed (or Semgrep is not installed -- evidence still
      written with ``status: not_available`` so the next ``evaluate``
      surfaces the gap honestly).
    - 2: User-correctable error (bad target, bad rulesets, scanner crash).
    - 3: Unexpected error (re-raised stack trace inside the kit).
    """

    fmt = output_format.strip().lower()
    if fmt not in {"human", "json"}:
        raise typer.BadParameter("--format must be human or json.")

    try:
        repo = resolve_existing_dir(target)
        ruleset_tuple = tuple(r.strip() for r in rulesets.split(",") if r.strip())
        if not ruleset_tuple:
            raise InvalidInputError(
                "--rulesets must contain at least one Semgrep ruleset (e.g. auto).",
            )

        outcome = run_semgrep(
            repo,
            rulesets=ruleset_tuple,
            timeout_seconds=timeout,
        )
        payload = render_evidence_payload(outcome, target=repo)
        evidence_path = write_evidence(payload, repo_root=repo, filename=EVIDENCE_FILENAME)

        if outcome.status == "error":
            stderr_console().print(
                f"[red]Semgrep failed:[/red] see diagnostics in {evidence_path.name}.",
            )
            raise typer.Exit(code=2)

        # ``not_available`` and ``timeout`` are valid evidence states: the
        # next evaluate run will report them as manual-review-required.
        if fmt == "json":
            sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        else:
            write_stdout_text(
                f"scan-sast: {outcome.status} -- "
                f"findings={len(outcome.findings)} "
                f"rulesets={','.join(outcome.rulesets)} "
                f"-> {evidence_path}\n",
            )
            if outcome.status == "not_available":
                stderr_console().print(
                    "[yellow]Semgrep is not installed.[/yellow] "
                    "Install it with `pip install semgrep` (3.12+) to populate real findings.",
                )
            elif outcome.status == "timeout":
                stderr_console().print(
                    f"[yellow]Semgrep timed out after {timeout}s[/yellow]; "
                    "consider tightening rulesets or raising --timeout.",
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
