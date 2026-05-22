"""``oss-policy-kit scan-k8s`` subcommand.

Discovers ``*.yaml`` / ``*.yml`` files under the target, runs the bundled
Kubernetes rule pack, and writes
``.oss-policy-kit/evidence/k8s-baseline.json`` (schema
``oss-policy-kit/evidence/k8s-baseline/v1``). Each ``K8S-*`` control
reads that file on the next ``evaluate`` run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.cli.common import app, stderr_console, write_stdout_text
from oss_policy_kit.domain.errors import OssPolicyKitError
from oss_policy_kit.infrastructure.k8s.scanner import (
    DEFAULT_INCLUDE_GLOBS,
    DEFAULT_TIMEOUT_SECONDS,
    EVIDENCE_FILENAME,
    K8sScanOutcome,
    render_evidence_payload,
    run_scan,
    write_evidence,
)


def _emit_scan_k8s_human(outcome: K8sScanOutcome, evidence_path: Path) -> None:
    """Write the human-format scan-k8s summary line plus helm/parse diagnostics to the console."""

    write_stdout_text(
        f"scan-k8s: {outcome.status} -- "
        f"files={len(outcome.files_scanned)} "
        f"helm_skipped={len(outcome.helm_templates_skipped)} "
        f"findings={len(outcome.findings)} "
        f"-> {evidence_path}\n",
    )
    if outcome.helm_render_attempted and not outcome.helm_available:
        stderr_console().print(
            "[yellow]--helm-render requested but the `helm` CLI was not on PATH[/yellow]; "
            "scan continued without rendering charts. Install Helm 3.x to enable the pre-pass."
        )
    if outcome.helm_render_attempted and outcome.helm_render_errors:
        stderr_console().print(
            f"[yellow]{len(outcome.helm_render_errors)} chart(s) failed to render[/yellow]; "
            "see helm_render_errors in the evidence file."
        )
    if outcome.helm_render_attempted and outcome.helm_charts_rendered:
        stderr_console().print(
            f"[green]Rendered {len(outcome.helm_charts_rendered)} Helm chart(s)[/green] "
            "and merged the manifests into the scan."
        )
    if outcome.helm_templates_skipped:
        stderr_console().print(
            f"[yellow]{len(outcome.helm_templates_skipped)} Helm template(s) skipped[/yellow] "
            "(contain {{ ... }} markers); pass --helm-render to render them before scanning."
        )
    if outcome.parse_errors:
        stderr_console().print(
            f"[yellow]{len(outcome.parse_errors)} file(s) failed to parse[/yellow]; "
            "see diagnostics.parse_errors in the evidence file."
        )


def _run_scan_k8s(target: str, include: str, exclude: str, timeout: int, *, helm_render: bool, fmt: str) -> None:
    """Resolve target, run the K8s scan, write evidence, and emit the chosen output format."""

    repo = resolve_existing_dir(target)
    include_tuple = tuple(g.strip() for g in include.split(",") if g.strip()) or DEFAULT_INCLUDE_GLOBS
    exclude_tuple = tuple(g.strip() for g in exclude.split(",") if g.strip()) or None
    outcome = run_scan(
        repo,
        include_globs=include_tuple,
        exclude_globs=exclude_tuple,
        timeout_seconds=timeout,
        helm_render=helm_render,
    )
    payload = render_evidence_payload(outcome, target=repo)
    evidence_path = write_evidence(payload, repo_root=repo, filename=EVIDENCE_FILENAME)
    if outcome.status == "error":
        stderr_console().print(f"[red]Kubernetes scan failed:[/red] see diagnostics in {evidence_path.name}.")
        raise typer.Exit(code=2)
    if fmt == "json":
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    else:
        _emit_scan_k8s_human(outcome, evidence_path)


@app.command("scan-k8s")
def scan_k8s_cmd(
    target: str = typer.Option(
        ".",
        "--target",
        "-t",
        help="Repository root to scan for Kubernetes manifests. Defaults to the current directory.",
    ),
    include: str = typer.Option(
        ",".join(DEFAULT_INCLUDE_GLOBS),
        "--include",
        help="Comma-separated glob patterns for source files. Defaults to '**/*.yaml,**/*.yml'.",
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
    helm_render: bool = typer.Option(
        False,
        "--helm-render/--no-helm-render",
        help=(
            "Opt-in pre-pass: run `helm template` against every Chart.yaml under the target and "
            "scan the rendered manifests alongside regular YAML. Requires the `helm` CLI (3.x) on PATH; "
            "without it the scan continues and records a diagnostic. Off by default."
        ),
    ),
) -> None:
    """Run the bundled Kubernetes rule pack and write K8S-* evidence.

    Exit codes:

    - 0: Scan completed.
    - 2: User-correctable error (bad target).
    - 3: Unexpected error (re-raised stack trace inside the kit).
    """

    fmt = output_format.strip().lower()
    if fmt not in {"human", "json"}:
        raise typer.BadParameter("--format must be human or json.")

    try:
        _run_scan_k8s(target, include, exclude, timeout, helm_render=helm_render, fmt=fmt)
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
