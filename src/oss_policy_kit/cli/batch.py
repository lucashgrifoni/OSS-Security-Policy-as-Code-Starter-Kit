"""`evaluate-many` subcommand for monorepo / multi-app roots."""

from __future__ import annotations

from pathlib import Path

import typer

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.application.batch_evaluate import run_batch_evaluation
from oss_policy_kit.cli.common import (
    app,
    stderr_console,
    warn_if_batch_skipped_directories,
)
from oss_policy_kit.cli.help_text import EVALUATE_MANY_EPILOG
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError


@app.command("evaluate-many", epilog=EVALUATE_MANY_EPILOG)
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
            "README.md alone is NOT sufficient."
        ),
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress incremental stderr progress lines; keep final batch summary writes.",
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
                cons.print(f"[dim]  [{current}/{total}][/dim] {repo_name}")

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
        )
        stderr_console().print(f"[green]Wrote[/green] {batch.batch_json.resolve()}")
        stderr_console().print(f"[green]Wrote[/green] {batch.batch_md.resolve()}")
        if not quiet:
            warn_if_batch_skipped_directories(batch.batch_json)
        if batch.gate_violated:
            raise typer.Exit(code=1)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc
