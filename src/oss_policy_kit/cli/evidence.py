"""`scaffold-evidence` and `collect-evidence` subcommands."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import typer
from rich.table import Table

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.application.evidence_scaffold import scaffold_evidence_files
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.common import (
    NonEmptyPath,
    app,
    display_path,
    exit_for_unexpected,
    markup_safe,
    stderr_console,
    write_wrapped_stdout_block,
)
from oss_policy_kit.cli.help_text import CMD_PANEL_COLLECT
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError
from oss_policy_kit.infrastructure.collectors.aws_collector import AWSEvidenceCollector
from oss_policy_kit.infrastructure.collectors.azure_collector import AzureDevOpsEvidenceCollector
from oss_policy_kit.infrastructure.collectors.github_collector import GitHubEvidenceCollector
from oss_policy_kit.infrastructure.collectors.gitlab_collector import (
    GITLAB_DEFAULT_URL,
    GitLabEvidenceCollector,
)
from oss_policy_kit.infrastructure.git_remote import read_github_repo_slug_from_git_config

# Single source of truth for the platforms collect-evidence supports. Used to reject
# unknown --platform values early — including under --dry-run, which previously skipped
# validation and printed a misleading empty preview (exit 0) for a typo like "githhub",
# even though a real run would reject it with exit 2.
_COLLECT_PLATFORMS: tuple[str, ...] = ("github", "gitlab", "azure", "aws")

_COLLECT_PREVIEW: dict[str, list[tuple[str, str]]] = {
    "github": [
        ("branch-protection.json", "GET /repos/{owner}/{repo}/branches/{default}/protection"),
        ("github-rulesets.json", "GET /repos/{owner}/{repo}/rulesets"),
        ("github-secret-scanning.json", "GET /repos/{owner}/{repo} (security_and_analysis)"),
        ("github-environment-protection.json", "GET /repos/{owner}/{repo}/environments"),
        ("github-release-immutability.json", "GET /repos/{owner}/{repo}/releases (latest immutable flag)"),
        ("github-actions-policy.json", "GET /orgs/{owner}/actions/permissions (admin:org; skipped otherwise)"),
    ],
    "gitlab": [
        ("branch-protection.json", "GET /api/v4/projects/{id}/protected_branches (+ /approvals)"),
        ("gitlab-mr-rules.json", "GET /api/v4/projects/{id}/approval_rules (+ /approvals)"),
        ("org-mfa-posture.json", "GET /api/v4/groups/{group} (require_two_factor_authentication)"),
    ],
    "azure": [
        ("azure-branch-policies.json", "GET /{org}/{project}/_apis/policy/configurations?api-version=7.1"),
        ("azure-pipeline-governance.json", "GET /{org}/{project}/_apis/pipelines?api-version=7.1"),
    ],
    "aws": [
        ("aws-codebuild-project.json", "codebuild.batch_get_projects (when AWS_CODEBUILD_PROJECT is set)"),
        ("aws-codepipeline.json", "codepipeline.get_pipeline (when AWS_CODEPIPELINE_NAME is set)"),
    ],
}

_COLLECT_REQUIRED_ENV: dict[str, list[str]] = {
    "github": ["GITHUB_TOKEN"],
    "gitlab": ["GITLAB_TOKEN", "GITLAB_URL optional (defaults to https://gitlab.com)"],
    "azure": ["AZURE_DEVOPS_ORG", "AZURE_DEVOPS_TOKEN"],
    "aws": ["AWS credential chain (boto3)", "AWS_CODEBUILD_PROJECT and/or AWS_CODEPIPELINE_NAME optional"],
}

# Environment variables whose presence (not their secret value) is reported in the dry-run preview so
# operators can confirm their local shell is ready before committing to a live collection.
_COLLECT_ENV_PROBES: dict[str, tuple[str, ...]] = {
    "github": ("GITHUB_TOKEN",),
    "gitlab": ("GITLAB_TOKEN", "GITLAB_URL", "GITLAB_PROJECT"),
    "azure": ("AZURE_DEVOPS_ORG", "AZURE_DEVOPS_TOKEN"),
    "aws": (
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_PROFILE",
        "AWS_CODEBUILD_PROJECT",
        "AWS_CODEPIPELINE_NAME",
    ),
}


#: Where both evidence commands put their files when ``--output-dir`` is not given.
_EVIDENCE_SUBDIR = Path(".oss-policy-kit") / "evidence"


def _evidence_dir_display(target_display: str) -> str:
    """Name the default evidence directory under the target as the operator wrote it."""

    return display_path(Path(target_display) / _EVIDENCE_SUBDIR)


def _env_probe_status(name: str) -> str:
    """Return ``set`` / ``not set`` for *name* without ever echoing the variable value."""

    raw = os.environ.get(name)
    return "set" if raw is not None and raw.strip() else "not set"


def _print_collect_dry_run_preview(
    *,
    target: Path,
    target_display: str,
    platform: str,
    repo_slug: str | None,
    output_dir: Path | None,
) -> None:
    """Print what ``collect-evidence`` would collect without API calls or credentials.

    Never prints secret values; only whether each known credential-related variable is populated.

    ``target`` is the resolved path the preview reads from (the git config lives there);
    ``target_display`` is what the operator typed, and it is the only one that reaches the
    screen. Answering ``--target .`` with the full host path is the M-002 leak this
    preview used to commit eight times in a row.
    """

    out_display = display_path(output_dir) if output_dir is not None else _evidence_dir_display(target_display)
    detected_slug: str | None = None
    if repo_slug is None and platform == "github":
        detected_slug = read_github_repo_slug_from_git_config(target)
    effective_slug = (repo_slug or "").strip() or detected_slug
    console = terminal_ui.build_stdout_console()
    console.print(
        f"\n[bold cyan]collect-evidence dry-run[/bold cyan] -- platform: [bold]{markup_safe(platform)}[/bold]"
    )
    console.print(f"  Target:     {markup_safe(display_path(target_display))}")
    console.print(f"  Output dir: {markup_safe(out_display)}")
    # The placeholder is bracketed, so it must be escaped like any other interpolation:
    # unescaped, Rich read ``[not detected ...]`` as a style tag and printed an empty
    # "Repo slug:" line, hiding the one instruction the operator needed.
    slug_display = effective_slug if effective_slug else "[not detected -- pass --repo where needed]"
    console.print(f"  Repo slug:  {markup_safe(slug_display)}")
    env_vars = _COLLECT_REQUIRED_ENV.get(platform, [])
    console.print(f"  Credentials (needed without --dry-run): {markup_safe(', '.join(env_vars))}")
    probes = _COLLECT_ENV_PROBES.get(platform, ())
    if probes:
        console.print("  Environment probe (values are not printed):")
        for name in probes:
            console.print(f"    - {markup_safe(name)}: {_env_probe_status(name)}")
    entries = _COLLECT_PREVIEW.get(platform, [])
    if entries:
        console.print("\n[bold]Would create:[/bold]")
        for fname, endpoint in entries:
            console.print(f"  [green]+[/green] {markup_safe(display_path(Path(out_display) / fname))}")
            console.print(f"    [dim]via {markup_safe(endpoint)}[/dim]")
    console.print("\n[dim]Run without --dry-run to execute (credentials required).[/dim]")


@app.command("scaffold-evidence", rich_help_panel=CMD_PANEL_COLLECT)
def scaffold_evidence_cmd(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help=(
            "Repository root where .oss-policy-kit/ will be created. "
            "The directory is created if missing (parents=True)."
        ),
    ),
    platform: str = typer.Option(
        ...,
        "--platform",
        help="github, gitlab, azure, or aws -- selects which evidence JSON templates to emit.",
        case_sensitive=False,
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing evidence files and README (default: skip existing files).",
    ),
) -> None:
    """Create `.oss-policy-kit/evidence/` with schema-shaped JSON templates for release-hardening workflows.

    Manual evidence mode: generates template JSON files that must be filled in by hand.
    For automatic evidence collection via platform APIs, use ``collect-evidence`` instead.

    The `--target` directory is auto-created (with parents) when missing. A short stderr note is
    emitted in that case so CI logs reflect the side effect explicitly.
    """

    try:
        candidate = Path(target).expanduser()
        if not candidate.exists():
            try:
                candidate.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                # ``str(OSError)`` renders the offending filename through repr, so
                # interpolating ``exc`` put the resolved path -- home directory and OS
                # account name -- into the message. ``strerror`` carries the reason
                # without the path, the same idiom the handler at the end of this
                # function already uses (M-002).
                raise InvalidInputError(
                    f"Could not create --target directory {display_path(candidate)}: "
                    f"{exc.strerror or 'filesystem error'}"
                ) from exc
            stderr_console().print(
                f"[yellow]Note:[/yellow] created missing --target directory: {markup_safe(display_path(candidate))}"
            )
        repo = resolve_existing_dir(target)
        outcome = scaffold_evidence_files(repo, platform, force=force)
        sys.stdout.write("scaffold-evidence summary:\n")
        sys.stdout.write(f"  created: {len(outcome.created)}\n")
        sys.stdout.write(f"  skipped (existing): {len(outcome.skipped)}\n")
        sys.stdout.write(f"  overwritten: {len(outcome.overwritten)}\n")
        # Each of the eight lines is named relative to the current directory, falling back
        # to relative-to-target: `--target .` used to answer with eight fully-qualified
        # paths carrying the home directory and the OS account name (M-002).
        for p in outcome.created:
            write_wrapped_stdout_block("  + ", display_path(p, root=repo), "    ")
        for p in outcome.skipped:
            write_wrapped_stdout_block("  = ", f"{display_path(p, root=repo)} (unchanged)", "    ")
        for p in outcome.overwritten:
            write_wrapped_stdout_block("  ! ", f"{display_path(p, root=repo)} (replaced)", "    ")
        if not force and outcome.skipped:
            sys.stdout.write("  (re-run with --force to replace existing files)\n")
        tail = (
            "Manual mode: replace placeholders before relying on results. "
            "For API-backed evidence, use collect-evidence. "
            "Existing files were preserved unless --force was set."
        )
        wrapped = terminal_ui.human_wrap_lines(tail, stream=sys.stderr, subtract=2)
        lines = wrapped.split("\n")
        stderr_console().print(f"[green]Scaffold complete.[/green] {markup_safe(lines[0])}")
        for ln in lines[1:]:
            stderr_console().print(markup_safe(ln))
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except OSError as exc:
        # A filesystem error on a user-supplied --target (e.g. .oss-policy-kit
        # pre-exists as a file so mkdir fails) is a usage error, not internal.
        # Use exc.strerror so the absolute path / username is never echoed.
        #
        # Escaped exactly once, at the interpolation. It used to be escaped into ``detail``
        # and then escaped again on the way in, so a strerror carrying a bracket reached
        # the operator with a literal backslash in front of it -- a character they never
        # typed, in the one line they are being asked to read.
        detail = exc.strerror or "filesystem error"
        stderr_console().print(f"[red]Error:[/red] cannot write output ({markup_safe(detail)}).")
        raise typer.Exit(code=2) from exc
    # Last-resort user message, no traceback leak.
    except Exception as exc:  # noqa: BLE001
        exit_for_unexpected(exc)


def _build_evidence_collector(
    plat: str,
    platform: str,
    repo: Path,
    repo_slug: str | None,
) -> tuple[
    GitHubEvidenceCollector | GitLabEvidenceCollector | AzureDevOpsEvidenceCollector | AWSEvidenceCollector,
    str,
]:
    """Build the platform collector and resolve its repo slug (validates required credentials)."""

    if plat == "github":
        return _github_collector(repo, repo_slug)
    if plat == "gitlab":
        return _gitlab_collector(repo_slug)
    if plat == "azure":
        return _azure_collector(repo_slug)
    if plat == "aws":
        return _aws_collector(repo_slug)
    raise InvalidInputError(f"Unsupported --platform {platform!r}; use github, gitlab, azure, or aws.")


def _github_collector(repo: Path, repo_slug: str | None) -> tuple[GitHubEvidenceCollector, str]:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        raise OSError(
            "GITHUB_TOKEN is not set. Export a token with permission to read the repository "
            "(and security analysis where applicable)."
        )
    slug = (repo_slug or "").strip() or read_github_repo_slug_from_git_config(repo) or ""
    if not slug:
        raise InvalidInputError(
            "Could not determine GitHub repo slug; pass --repo org/repo or add an origin remote pointing to GitHub."
        )
    return GitHubEvidenceCollector(token), slug


def _gitlab_collector(repo_slug: str | None) -> tuple[GitLabEvidenceCollector, str]:
    token = os.environ.get("GITLAB_TOKEN", "").strip()
    if not token:
        raise OSError(
            "GITLAB_TOKEN is not set. Export a token with read access to the project "
            "(read_api covers protected branches and approvals; group read is needed for MFA posture)."
        )
    base_url = os.environ.get("GITLAB_URL", "").strip() or GITLAB_DEFAULT_URL
    slug = (repo_slug or "").strip() or os.environ.get("GITLAB_PROJECT", "").strip()
    if not slug:
        raise InvalidInputError(
            "GitLab requires --repo group/project (or a numeric project id), "
            "or the GITLAB_PROJECT environment variable."
        )
    return GitLabEvidenceCollector(token, base_url=base_url), slug


def _azure_collector(repo_slug: str | None) -> tuple[AzureDevOpsEvidenceCollector, str]:
    org = os.environ.get("AZURE_DEVOPS_ORG", "").strip()
    pat = os.environ.get("AZURE_DEVOPS_TOKEN", "").strip()
    if not org or not pat:
        raise OSError(
            "AZURE_DEVOPS_ORG and AZURE_DEVOPS_TOKEN must be set for Azure DevOps collection "
            "(PAT with Code, Build, and Project read access)."
        )
    slug = (repo_slug or "").strip()
    if not slug:
        raise InvalidInputError("Azure DevOps requires --repo ProjectName/repoName (no automatic slug detection yet).")
    return AzureDevOpsEvidenceCollector(organization=org, personal_access_token=pat), slug


def _aws_collector(repo_slug: str | None) -> tuple[AWSEvidenceCollector, str]:
    build_n = os.environ.get("AWS_CODEBUILD_PROJECT", "").strip()
    pipe_n = os.environ.get("AWS_CODEPIPELINE_NAME", "").strip()
    if not build_n and not pipe_n:
        raise InvalidInputError("For AWS, set AWS_CODEBUILD_PROJECT and/or AWS_CODEPIPELINE_NAME in the environment.")
    return AWSEvidenceCollector(), (repo_slug or "").strip()


def _write_collected_evidence(
    rows: list[Any], *, plat: str, output_dir: Path | None, repo: Path, target_display: str
) -> None:
    """Write each collected evidence row to disk and print a summary table."""

    table = Table(title=f"collect-evidence ({plat})", show_lines=True)
    table.add_column("Evidence file", style="cyan", no_wrap=True)
    table.add_column("Source", style="dim")
    dest = (output_dir or (repo / ".oss-policy-kit" / "evidence")).resolve()
    dest_display = display_path(output_dir) if output_dir is not None else _evidence_dir_display(target_display)
    dest.mkdir(parents=True, exist_ok=True)
    for row in rows:
        out_path = dest / f"{row.evidence_key}.json"
        out_path.write_text(json.dumps(row.data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        table.add_row(str(out_path.name), row.source_url)
    stderr_console().print(table)
    stderr_console().print(f"[green]Wrote[/green] {len(rows)} file(s) under {markup_safe(dest_display)}")


@app.command("collect-evidence", rich_help_panel=CMD_PANEL_COLLECT)
def collect_evidence_cmd(
    target: Path = typer.Option(..., "--target", "-t", help="Repository root path."),
    platform: str = typer.Option(
        ...,
        "--platform",
        help="Platform: github, gitlab, azure, or aws (each requires the matching credentials; see command help).",
    ),
    output_dir: Path | None = typer.Option(
        None,
        "--output-dir",
        "-o",
        click_type=NonEmptyPath(),
        help="Directory to write evidence files. Defaults to <target>/.oss-policy-kit/evidence/.",
    ),
    repo_slug: str | None = typer.Option(
        None,
        "--repo",
        help=(
            "Repository slug: GitHub ``org/repo``, GitLab ``group/project`` (or numeric project id), "
            "or Azure DevOps ``ProjectName/repoName``. "
            "Not required for AWS (set AWS_CODEBUILD_PROJECT and/or AWS_CODEPIPELINE_NAME instead)."
        ),
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview files and API surface without calling platforms or requiring credentials.",
    ),
) -> None:
    """Collect platform evidence files automatically via API.

    Writes the same JSON evidence files that scaffold-evidence creates as templates,
    but populated with real data from the platform API.
    """

    try:
        plat = platform.strip().lower()
        if plat not in _COLLECT_PLATFORMS:
            raise InvalidInputError(f"Unsupported --platform {platform!r}; use {', '.join(_COLLECT_PLATFORMS)}.")
        if dry_run:
            # Dry-run never touches the filesystem; do not require the target to exist.
            preview_target = Path(str(target)).expanduser().resolve()
            _print_collect_dry_run_preview(
                target=preview_target,
                target_display=str(target),
                platform=plat,
                repo_slug=repo_slug,
                output_dir=output_dir,
            )
            return
        repo = resolve_existing_dir(str(target))
        collector, slug = _build_evidence_collector(plat, platform, repo, repo_slug)
        try:
            rows = collector.collect(slug)
        except ValueError as exc:
            raise InvalidInputError(str(exc)) from exc
        except RuntimeError as exc:
            if not isinstance(exc.__cause__, ImportError):
                raise
            # Every collector signals "my optional extra is not installed" as
            # ``RuntimeError(...) from ImportError``. That is a user-correctable
            # environment state carrying its own fix (`pip install 'oss-policy-kit[...]'`),
            # exactly like the missing-token checks above, so it exits 2 as a plain
            # "Error:" instead of exit 3 "Unexpected error:" — exit 3 means the kit
            # misbehaved, and nothing here did. The sibling scanners agree in spirit:
            # scan-iac and scan-sast both stay off the internal-error path when their
            # optional tool is absent.
            raise InvalidInputError(str(exc)) from exc
        _write_collected_evidence(rows, plat=plat, output_dir=output_dir, repo=repo, target_display=str(target))
    except OSError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.strerror or exc)}")
        raise typer.Exit(code=2) from exc
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        exit_for_unexpected(exc)
