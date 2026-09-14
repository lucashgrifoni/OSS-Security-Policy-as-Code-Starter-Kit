"""`evaluate-many` subcommand for monorepo / multi-app roots."""

from __future__ import annotations

from pathlib import Path

import typer

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.application.batch_evaluate import run_batch_evaluation
from oss_policy_kit.cli.common import (
    _output_child_display,
    app,
    display_path,
    exit_for_unexpected,
    markup_safe,
    stderr_console,
    warn_if_batch_skipped_directories,
)
from oss_policy_kit.cli.help_text import CMD_PANEL_EVALUATE, EVALUATE_MANY_EPILOG
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError


@app.command("evaluate-many", epilog=EVALUATE_MANY_EPILOG, rich_help_panel=CMD_PANEL_EVALUATE)
def evaluate_many_cmd(
    target_root: Path = typer.Option(
        ...,
        "--target-root",
        help="Directory whose immediate child folders are evaluated as separate repositories.",
    ),
    profiles: str = typer.Option(
        ...,
        "--profiles",
        "-p",
        help="Comma-separated profile ids (for example: github-level-1,azure-level-1).",
    ),
    output_dir: Path = typer.Option(
        Path("out"),
        "--output-dir",
        "-o",
        help="Directory for consolidated batch reports and per-target subfolders.",
    ),
    kit_root: Path | None = typer.Option(None, "--kit-root", "-k", help="Override bundled controls/ and profiles/."),
    include: str | None = typer.Option(
        None,
        "--include",
        help="Optional fnmatch pattern applied to child directory names (for example: lab-*).",
    ),
    exclude: str | None = typer.Option(
        None,
        "--exclude",
        help="Optional fnmatch pattern applied to child directory names to skip.",
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
    skip_non_repos: bool = typer.Option(
        False,
        "--skip-non-repos",
        help=(
            "Skip child directories that don't look like a repository root. "
            "Detection requires at least one primary signal: .git, a build "
            "manifest (package.json, pyproject.toml, requirements.txt, go.mod, "
            "Cargo.toml, pom.xml, etc.), a CI file (.github/workflows/, "
            "azure-pipelines.yml, pipelines/azure/*.yml, buildspec.yml), or a Dockerfile. "
            "README.md alone is NOT sufficient. Output / build / cache directories "
            "(out, dist, build, _output, .tmp, node_modules, venv, .venv, target, site, "
            "coverage, htmlcov, plus out-* / build-* / dist-* / output-* prefixes) "
            "are also skipped even when they happen to contain a manifest."
        ),
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress incremental stderr progress lines; keep final batch summary writes.",
    ),
    include_absolute_path: bool = typer.Option(
        False,
        "--include-absolute-path",
        help=(
            "Keep full absolute paths in the batch reports (target_root, per-run target_path, "
            "report artifact paths, skipped-directory paths). Default is privacy-by-default: "
            "every path is sanitized to a basename so shared batch artifacts do not leak the "
            "auditor's home directory or username. Use only when downstream tooling expects "
            "absolute paths."
        ),
    ),
) -> None:
    """Evaluate many repository clones under one parent directory (monorepo / multi-app root)."""

    try:
        root = resolve_existing_dir(str(target_root))
        profile_ids = [p.strip() for p in profiles.split(",") if p.strip()]
        if not profile_ids:
            raise InvalidInputError("Provide at least one profile in --profiles.")
        policy = fail_on.lower()
        if policy not in {"none", "fail", "degraded"}:
            raise InvalidInputError("--fail-on must be one of: none, fail, degraded.")

        progress_cb = None
        if not quiet:
            cons = stderr_console()

            def progress_cb(repo_name: str, current: int, total: int) -> None:
                # The directory name is the operator's, not ours: a child called
                # ``[bold]repo-a`` reached the console as ``repo-a``. The consolidated
                # ``evaluation-batch.json`` records it correctly, but the progress stream
                # is the only place anyone watches during a long batch.
                cons.print(f"[dim]  [{current}/{total}][/dim] {markup_safe(repo_name)}")

        batch = run_batch_evaluation(
            target_root=root,
            profile_ids=profile_ids,
            output_dir=output_dir.resolve(),
            kit_root=kit_root,
            include=include,
            exclude=exclude,
            fail_on=policy,
            skip_non_repos=skip_non_repos,
            progress_callback=progress_cb,
            include_absolute_path=include_absolute_path,
        )
        # The operator reads back the ``--output-dir`` they typed, never the resolved host
        # path. These two lines answered a relative ``--output-dir ./batch`` with
        # ``C:\...\batch\evaluation-batch.json``, which on a real machine carries the account
        # name into every CI log the batch runs in -- and there is no flag to suppress it
        # without losing the confirmation. `evaluate` has echoed it relative since M-002; this
        # is the same two lines in the batch command, built the same way.
        out_display = display_path(output_dir)
        stderr_console().print(
            f"[green]Wrote[/green] {markup_safe(_output_child_display(out_display, batch.batch_json))}"
        )
        stderr_console().print(
            f"[green]Wrote[/green] {markup_safe(_output_child_display(out_display, batch.batch_md))}"
        )
        if not quiet:
            warn_if_batch_skipped_directories(batch.batch_json)
        if batch.failed_count:
            # A repository the batch was asked to evaluate and could not is an incomplete
            # run, not a policy outcome, so it exits 2 rather than 1 -- and it is checked
            # BEFORE the gate, because reporting a gate verdict computed over the targets
            # that happened to succeed is the failure this replaces. `evaluate-many`
            # previously printed "CI gate: PASSED" over zero runs when every repository
            # had failed.
            noun = "repository" if batch.failed_count == 1 else "repositories"
            stderr_console().print(
                f"[red]Error:[/red] {batch.failed_count} {noun} could not be evaluated; "
                "the batch is incomplete. See failed_directories in the batch report."
            )
            raise typer.Exit(code=2)
        if batch.gate_violated:
            raise typer.Exit(code=1)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        exit_for_unexpected(exc)
