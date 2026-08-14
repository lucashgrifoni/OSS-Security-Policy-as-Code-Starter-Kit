"""Evaluate multiple repository roots against one or more profiles (monorepo / batch)."""

from __future__ import annotations

import fnmatch
import json
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import oss_policy_kit
from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.application.cli_output import FailOnPolicy, fail_on_violated
from oss_policy_kit.application.clock import report_generated_at
from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.evaluators_common import as_mapping
from oss_policy_kit.application.loader import load_catalog, load_profile_by_id, merge_kit_root
from oss_policy_kit.application.reporting import (
    _sanitize_target_path_for_payload,
    compute_priority_insights,
    report_to_dict,
    write_markdown_report,
)
from oss_policy_kit.domain.errors import InvalidInputError

_REPO_PRIMARY_SIGNALS: tuple[str, ...] = (
    ".git",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "go.mod",
    "pom.xml",
    "Cargo.toml",
    "build.gradle",
    "build.gradle.kts",
    "buildspec.yml",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
)

_REPO_GLOB_PRIMARY: tuple[str, ...] = (
    "*.csproj",
    "*.sln",
    "buildspec*.yml",
    "pipelines/azure/*.yml",
    "pipelines/azure/*.yaml",
    ".azure-pipelines/*.yml",
    ".azure-pipelines/*.yaml",
    # GitHub Actions workflow files count as a repository signal: a `.github/workflows/`
    # directory alone is not enough (a parent project might just hold a templates folder),
    # but at least one workflow YAML inside it is a strong indicator that this directory
    # is a CI-bearing repository root.
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
)

REPO_SIGNALS = _REPO_PRIMARY_SIGNALS

# Directory names that should be skipped even when --skip-non-repos is set
# because they are output, build, or meta directories rather than projects.
# Compared case-insensitively. Adopters can still force-evaluate by removing
# --skip-non-repos and naming the directory directly.
_META_DIR_NAMES: frozenset[str] = frozenset(
    {
        "out",
        "output",
        "dist",
        "build",
        "_build",
        "_output",
        ".out",
        "target",  # rust/java build output
        "node_modules",
        "vendor",
        "venv",
        ".venv",
        "site",  # mkdocs / static site builds
        "coverage",
        "htmlcov",
    }
)

# Directory name prefixes that should be skipped: matches "out-*", "out_*",
# "build-*", "_output-*", etc. — frequent in build/run artifact folders.
_META_DIR_PREFIXES: tuple[str, ...] = (
    "out-",
    "out_",
    "output-",
    "_output",
    "build-",
    "dist-",
    ".tmp",
)


def _ensure_batch_dir(directory: Path) -> None:
    """Create *directory* (parents ok, idempotent), mapping a bad path to a usage error.

    ``evaluate-many`` writes under a user-supplied ``--output-dir``. When that path (or a
    per-target subfolder created mid-batch) already exists as a FILE, is under a file, or
    is otherwise not creatable, ``mkdir`` raises ``OSError``. Left unguarded it reaches the
    CLI's last-resort handler as exit 3 and leaks the absolute path / username. Raising
    ``InvalidInputError`` routes it to exit 2 with an ``exc.strerror``-only message (M-002),
    matching single ``evaluate``'s ``--output-dir`` handling.
    """

    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise InvalidInputError(f"Cannot write to --output-dir: {exc.strerror or 'filesystem error'}") from exc


def _is_meta_directory(name: str) -> bool:
    """Return True when *name* looks like an output / build / cache directory
    that should never be evaluated as a project, even via --skip-non-repos."""
    low = name.lower()
    if low in _META_DIR_NAMES:
        return True
    return any(low.startswith(p) for p in _META_DIR_PREFIXES)


def _quiet_probe(probe: Callable[[], bool]) -> bool:
    """Run a filesystem existence/type check, reading permission-denied as ``False``.

    ``Path.exists`` and ``Path.is_dir`` re-raise ``PermissionError`` (EACCES /
    WinError 5 is not in pathlib's ignored-error set), so probing a child directory
    the auditor cannot read used to abort the whole ``evaluate-many`` discovery with
    exit 3. A directory we cannot inspect simply shows us no repository signal.
    """

    try:
        return probe()
    except OSError:
        return False


def _glob_has_match(path: Path, pattern: str) -> bool:
    """True if ``path.glob(pattern)`` yields at least one entry (OSError treated as no match)."""

    try:
        return next(iter(path.glob(pattern)), None) is not None
    except OSError:
        return False


def is_likely_repository(path: Path) -> tuple[bool, str]:
    """Return ``(True, signal_found)`` when *path* looks like a repository root.

    Requires at least one primary signal (build manifest, CI file, Dockerfile, or ``.git``).
    ``README.md`` alone is not sufficient to avoid false positives from utility subdirectories
    in monorepos. As a fallback for monorepo-style layouts where signals live one or two
    directories deep (e.g. ``infra/k8s-manifests/*.yaml``, ``targets/*/Dockerfile``),
    also accept signals at depth 1 or 2 from the candidate root.

    Every probe is permission-tolerant: this runs over directories the auditor may
    not be allowed to read, and an unreadable candidate must not abort discovery.
    """

    for signal in _REPO_PRIMARY_SIGNALS:
        if _quiet_probe((path / signal).exists):
            return True, signal
    for pattern in _REPO_GLOB_PRIMARY:
        if _glob_has_match(path, pattern):
            return True, pattern
    deep = _repo_signal_at_depth(path)
    if deep is not None:
        return True, deep
    k8s = _repo_k8s_manifest_signal(path)
    if k8s is not None:
        return True, k8s
    return False, ""


def _repo_signal_at_depth(path: Path) -> str | None:
    """Monorepo fallback: a primary repo signal one or two directories deep."""

    for depth_pattern in ("*", "*/*"):
        for signal in _REPO_PRIMARY_SIGNALS:
            if _glob_has_match(path, f"{depth_pattern}/{signal}"):
                return f"{depth_pattern}/{signal}"
    return None


def _repo_k8s_manifest_signal(path: Path) -> str | None:
    """Accept Kubernetes manifests one or two levels deep (infra/ deploy/ manifests/ layouts)."""

    for k8s_pattern in ("*/k8s-manifests/*.yaml", "*/*/k8s-manifests/*.yaml", "*/manifests/*.yaml"):
        if _glob_has_match(path, k8s_pattern):
            return k8s_pattern
    return None


def _batch_failure_counts(fails_by_target: dict[str, int]) -> list[int]:
    return list(fails_by_target.values())


def _failure_distribution_bucketing(fail_counts: list[int]) -> dict[str, int]:
    buckets = {"0": 0, "1-5": 0, "6-10": 0, "11+": 0}
    for n in fail_counts:
        if n == 0:
            buckets["0"] += 1
        elif n <= 5:
            buckets["1-5"] += 1
        elif n <= 10:
            buckets["6-10"] += 1
        else:
            buckets["11+"] += 1
    return buckets


def _gate_violated_for_batch(policy: FailOnPolicy, summaries: list[dict[str, int]]) -> bool:
    if policy == "none":
        return False
    return any(fail_on_violated(policy, s) for s in summaries)


@dataclass(slots=True)
class BatchRunRow:
    """One target × profile evaluation summary."""

    target_name: str
    target_path: str
    profile_id: str
    summary_by_status: dict[str, int]
    report_path_json: str
    report_path_md: str


@dataclass(slots=True)
class BatchResult:
    """Paths to consolidated batch artifacts plus CI gate outcome."""

    batch_json: Path
    batch_md: Path
    gate_violated: bool
    #: Targets that ARE repositories and could not be evaluated. Distinct from a skipped
    #: directory, which is a child the batch was never asked to evaluate. A batch that
    #: could not evaluate what it queued is incomplete, and reporting a gate result over
    #: the remainder as though it covered everything is the silent-success this field
    #: exists to prevent.
    failed_count: int = 0


def discover_batch_targets(
    target_root: Path,
    *,
    include: str | None,
    exclude: str | None,
) -> list[Path]:
    """Return immediate child directories of *target_root* suitable as repo roots."""

    try:
        children = sorted(target_root.iterdir(), key=lambda p: p.name.lower())
    except OSError as exc:
        # An unlistable --target-root is an operational condition, not an internal
        # defect: exit 2 with the OS error only, never the resolved path (M-002).
        raise InvalidInputError(
            f"Cannot list --target-root '{target_root.name}': {exc.strerror or 'unreadable'}"
        ) from exc
    out: list[Path] = []
    for child in children:
        if not _quiet_probe(child.is_dir):
            continue
        if child.name.startswith("."):
            continue
        if include and not fnmatch.fnmatch(child.name, include):
            continue
        if exclude and fnmatch.fnmatch(child.name, exclude):
            continue
        out.append(child)
    return out


def _build_eval_queue(
    targets: list[Path], *, skip_non_repos: bool, include_absolute_path: bool = False
) -> tuple[list[tuple[Path, bool]], list[dict[str, str]]]:
    """Filter discovered child dirs into ``(eval_queue, skipped_dirs)`` honoring ``--skip-non-repos``.

    ``skipped_directories[].path`` is sanitized to the child basename by default
    (M-002) so the shareable batch JSON never leaks the auditor's home directory
    or username; ``include_absolute_path=True`` restores the full resolved path.
    """

    skipped_dirs: list[dict[str, str]] = []
    eval_queue: list[tuple[Path, bool]] = []
    for child in targets:
        skipped_path = _sanitize_target_path_for_payload(str(child.resolve()), include_absolute=include_absolute_path)
        # Even without --skip-non-repos, output / build directories should not be treated as
        # evaluable projects. Adopters can still target them explicitly via `evaluate --target`.
        if skip_non_repos and _is_meta_directory(child.name):
            skipped_dirs.append(
                {
                    "name": child.name,
                    "path": skipped_path,
                    "reason": "Looks like an output / build / cache directory (matches meta-directory name pattern).",
                }
            )
            continue
        likely, _sig = is_likely_repository(child)
        if skip_non_repos and not likely:
            skipped_dirs.append(
                {
                    "name": child.name,
                    "path": skipped_path,
                    "reason": "No repository root signals (.git, manifest, CI file, Dockerfile, etc.).",
                }
            )
            continue
        eval_queue.append((child, likely))
    return eval_queue, skipped_dirs


def _execute_one_run(
    target: Path,
    likely_repo: bool,
    pid: str,
    *,
    repo: Path,
    safe_name: str,
    root: Path,
    catalog: Any,
    output_dir: Path,
    skip_non_repos: bool,
    include_absolute_path: bool = False,
) -> tuple[BatchRunRow, dict[str, Any], dict[str, int]]:
    """Evaluate one target against one profile; write reports and return (row, payload, summary).

    Serialized paths (``runs[].target_path`` and ``runs[].reports.{json,markdown}``)
    are sanitized to basenames by default (M-002) so the shareable batch JSON never
    leaks the auditor's home directory or username. Per-run reports themselves inherit
    the same ``include_absolute_path`` privacy default via ``report_to_dict`` /
    ``write_markdown_report``.
    """

    profile = load_profile_by_id(root, pid)
    report = evaluate_repository(repo_root=repo, profile=profile, catalog=catalog, waiver_outcome=None, scorecard=None)
    dest = output_dir / safe_name / pid
    _ensure_batch_dir(dest)
    json_path = dest / "evaluation-report.json"
    md_path = dest / "evaluation-report.md"
    # Output failures are converted before they can reach the caller's `except OSError`,
    # which exists to skip targets that cannot be READ. A full disk or a revoked
    # --output-dir is not a property of this target: left as an OSError it would be
    # recorded as "skipped directory" and the batch would exit 0 having written
    # nothing, which is the silent-success failure this project refuses to ship.
    try:
        json_path.write_text(
            json.dumps(
                report_to_dict(report, include_absolute_path=include_absolute_path), indent=2, ensure_ascii=False
            )
            + "\n",
            encoding="utf-8",
        )
        write_markdown_report(report, md_path, include_absolute_path=include_absolute_path)
    except OSError as exc:
        raise InvalidInputError(
            f"Cannot write the report for '{target.name}': {exc.strerror or 'filesystem error'}"
        ) from exc
    target_path_display = _sanitize_target_path_for_payload(str(repo.resolve()), include_absolute=include_absolute_path)
    json_report_display = _sanitize_target_path_for_payload(
        str(json_path.resolve()), include_absolute=include_absolute_path
    )
    md_report_display = _sanitize_target_path_for_payload(
        str(md_path.resolve()), include_absolute=include_absolute_path
    )
    row = BatchRunRow(
        target_name=target.name,
        target_path=target_path_display,
        profile_id=pid,
        summary_by_status=dict(report.summary_by_status),
        # Kept as the real resolved path: consumed internally by the batch Markdown
        # artifact-lines renderer to compute a path relative to the output directory.
        report_path_json=str(json_path.resolve()),
        report_path_md=str(md_path.resolve()),
    )
    payload: dict[str, Any] = {
        "target_name": target.name,
        "target_path": target_path_display,
        "profile_id": pid,
        "summary_by_status": report.summary_by_status,
        "action_insights": compute_priority_insights(report),
        "reports": {"json": json_report_display, "markdown": md_report_display},
    }
    if not skip_non_repos and not likely_repo:
        payload["likely_not_a_repository"] = True
    return row, payload, dict(report.summary_by_status)


@dataclass(slots=True)
class _BatchRunOutcome:
    """Everything one pass over the evaluation queue produced."""

    rows: list[BatchRunRow]
    consolidated_reports: list[dict[str, Any]]
    summaries_for_gate: list[dict[str, int]]
    skipped: list[dict[str, str]]
    #: Queued targets that raised during evaluation. Kept apart from ``skipped``: one
    #: means "not a repository", the other means "a repository we failed on", and
    #: merging them let a batch where EVERY repository failed report the gate as PASSED
    #: over zero runs.
    failed: list[dict[str, str]]


def _execute_batch_runs(
    eval_queue: list[tuple[Path, bool]],
    profile_ids: list[str],
    *,
    root: Path,
    catalog: Any,
    output_dir: Path,
    skip_non_repos: bool,
    progress_callback: Callable[[str, int, int], None] | None,
    include_absolute_path: bool = False,
) -> _BatchRunOutcome:
    """Run every (target × profile) evaluation, degrading past targets we cannot read.

    A repository the process has no permission to read is an ordinary operational
    condition in a monorepo scan, not a defect: it is recorded in ``skipped`` and the
    batch continues. Before this guard a single unreadable file anywhere under one
    child aborted the whole run with exit 3 and discarded every result already
    computed. Usage errors (an unknown profile id, an unwritable ``--output-dir``)
    still abort, because they are wrong for every target alike.

    The guard covers the INPUT side only. ``_execute_one_run`` converts its own write
    failures to ``InvalidInputError`` before they get here, so a full disk mid-batch
    aborts with exit 2 instead of being filed as a per-target skip.
    """

    outcome = _BatchRunOutcome(rows=[], consolidated_reports=[], summaries_for_gate=[], skipped=[], failed=[])
    total_runs = len(eval_queue) * len(profile_ids)
    run_index = 0
    for target, likely_repo in eval_queue:
        safe_name = target.name.replace("/", "_").replace("\\", "_")
        for pid in profile_ids:
            run_index += 1
            if progress_callback is not None:
                progress_callback(target.name, run_index, total_runs)
            try:
                row, payload, summary = _execute_one_run(
                    target,
                    likely_repo,
                    pid,
                    repo=resolve_existing_dir(str(target)),
                    safe_name=safe_name,
                    root=root,
                    catalog=catalog,
                    output_dir=output_dir,
                    skip_non_repos=skip_non_repos,
                    include_absolute_path=include_absolute_path,
                )
            except OSError as exc:
                outcome.failed.append(_unreadable_target_record(target, pid, exc, include_absolute_path))
                continue
            outcome.rows.append(row)
            outcome.consolidated_reports.append(payload)
            outcome.summaries_for_gate.append(summary)
    return outcome


def _unreadable_target_record(target: Path, pid: str, exc: OSError, include_absolute_path: bool) -> dict[str, str]:
    """Describe a target the batch had to skip, without leaking where it lives.

    ``str(exc)`` and the ``OSError`` repr both embed the absolute filename, so only
    ``strerror`` is reported and the path goes through the same basename sanitizer
    as every other emitted path (M-002).
    """

    return {
        "name": target.name,
        "path": _sanitize_target_path_for_payload(str(target.resolve()), include_absolute=include_absolute_path),
        "reason": f"Could not be evaluated against profile '{pid}': {exc.strerror or 'filesystem error'}.",
    }


def run_batch_evaluation(  # noqa: C901
    *,
    target_root: Path,
    profile_ids: list[str],
    output_dir: Path,
    kit_root: Path | None,
    include: str | None,
    exclude: str | None,
    fail_on: str = "none",
    skip_non_repos: bool = False,
    progress_callback: Callable[[str, int, int], None] | None = None,
    include_absolute_path: bool = False,
) -> BatchResult:
    """Evaluate each discovered child of *target_root* against every *profile_id*.

    Writes per-run ``evaluation-report.{json,md}`` under
    ``output_dir / <sanitized_target_name> / <profile_id> /`` plus consolidated
    ``evaluation-batch.json`` and ``evaluation-batch.md`` at *output_dir*.

    ``include_absolute_path`` mirrors single ``evaluate`` (M-002): by default every
    emitted path (``target_root``, ``runs[].target_path``, report artifact paths,
    ``skipped_directories[].path``) is sanitized to a basename so the shareable batch
    artifacts never leak the auditor's home directory or username. Pass ``True`` to
    restore full absolute paths for downstream tooling.
    """

    policy = cast(FailOnPolicy, fail_on.lower())
    root = merge_kit_root(kit_root)
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    targets = discover_batch_targets(target_root, include=include, exclude=exclude)
    if not targets:
        raise InvalidInputError(f"No subdirectories to evaluate under {target_root}")

    eval_queue, skipped_dirs = _build_eval_queue(
        targets, skip_non_repos=skip_non_repos, include_absolute_path=include_absolute_path
    )
    if not eval_queue:
        raise InvalidInputError(
            "No repositories to evaluate after filtering. Remove --skip-non-repos or add include/exclude patterns."
        )

    _ensure_batch_dir(output_dir)
    outcome = _execute_batch_runs(
        eval_queue,
        profile_ids,
        root=root,
        catalog=catalog,
        output_dir=output_dir,
        skip_non_repos=skip_non_repos,
        progress_callback=progress_callback,
        include_absolute_path=include_absolute_path,
    )
    rows = outcome.rows
    consolidated_reports = outcome.consolidated_reports
    skipped_dirs.extend(outcome.skipped)
    failed_dirs = outcome.failed

    generated_at = report_generated_at()
    gate_violated = _gate_violated_for_batch(policy, outcome.summaries_for_gate)
    stats = _compute_batch_stats(rows, consolidated_reports)

    batch_payload: dict[str, Any] = {
        "schema_version": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/batch/0.1",
        "generated_at": generated_at,
        "kit_version": oss_policy_kit.__version__,
        "target_root": _sanitize_target_path_for_payload(
            str(target_root.resolve()), include_absolute=include_absolute_path
        ),
        "profile_ids": profile_ids,
        "gate_violated": gate_violated,
        "fail_on": policy,
        "all_tied": stats.all_tied,
        "common_fail_count": stats.common_fail_count,
        "failure_distribution": stats.dist,
        "runs": consolidated_reports,
    }
    if skipped_dirs:
        batch_payload["skipped_directories"] = skipped_dirs
    if failed_dirs:
        # Deliberately a separate key from ``skipped_directories``. A consumer reading
        # only ``gate_violated`` would otherwise conclude the batch covered everything.
        batch_payload["failed_directories"] = failed_dirs
        batch_payload["batch_complete"] = False

    batch_json = output_dir / "evaluation-batch.json"
    batch_json.write_text(json.dumps(batch_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    batch_md = output_dir / "evaluation-batch.md"
    batch_md.write_text(
        _render_batch_markdown(
            rows,
            generated_at=generated_at,
            target_root=target_root,
            profile_ids=profile_ids,
            eval_queue_len=len(eval_queue),
            gate_violated=gate_violated,
            policy=policy,
            stats=stats,
            skipped_dirs=skipped_dirs,
            output_dir=output_dir,
            include_absolute_path=include_absolute_path,
        ),
        encoding="utf-8",
    )
    return BatchResult(
        batch_json=batch_json,
        batch_md=batch_md,
        gate_violated=gate_violated,
        failed_count=len(failed_dirs),
    )


@dataclass(slots=True)
class _BatchStats:
    """Aggregated counts for the consolidated batch report."""

    totals: dict[str, int]
    dist: dict[str, int]
    comparison_lines: list[str]
    gap_hits: Counter[str]
    all_tied: bool
    common_fail_count: int | None


def _batch_comparison_lines(
    fails_by_target: dict[str, int], all_tied: bool, common_fail_count: int | None
) -> list[str]:
    """Quick best/worst comparison lines across targets (empty when no targets)."""

    if not fails_by_target:
        return []
    if all_tied:
        return [
            f"All **{len(fails_by_target)}** repositories share the same failure count "
            f"({common_fail_count}) — no clear best or worst performer."
        ]
    max_f = max(fails_by_target.values())
    min_f = min(fails_by_target.values())
    worst = sorted(n for n, c in fails_by_target.items() if c == max_f)
    best = sorted(n for n, c in fails_by_target.items() if c == min_f)
    return [
        f"- **Most failures (tie-break: lexicographic name)**: {', '.join(f'`{n}`' for n in worst)}",
        f"- **Fewest failures**: {', '.join(f'`{n}`' for n in best)}",
    ]


def _compute_batch_stats(rows: list[BatchRunRow], consolidated_reports: list[dict[str, Any]]) -> _BatchStats:
    """Aggregate totals, failure distribution, comparison lines, and repeated-control hits."""

    totals: dict[str, int] = defaultdict(int)
    fails_by_target: dict[str, int] = defaultdict(int)
    for row in rows:
        for k, v in row.summary_by_status.items():
            totals[k] += v
        fails_by_target[row.target_name] += row.summary_by_status.get("fail", 0)
    fc_values = _batch_failure_counts(fails_by_target)
    all_tied = len(fails_by_target) >= 2 and len(set(fc_values)) == 1
    common_fail_count: int | None = fc_values[0] if all_tied else None
    gap_hits: Counter[str] = Counter()
    for cr in consolidated_reports:
        ac = as_mapping(cr.get("action_insights"))
        for ids in as_mapping(ac.get("failing_controls_by_category")).values():
            for cid in ids:
                gap_hits[str(cid)] += 1
    return _BatchStats(
        totals=dict(totals),
        dist=_failure_distribution_bucketing(fc_values),
        comparison_lines=_batch_comparison_lines(fails_by_target, all_tied, common_fail_count),
        gap_hits=gap_hits,
        all_tied=all_tied,
        common_fail_count=common_fail_count,
    )


def _batch_md_matrix_lines(rows: list[BatchRunRow]) -> list[str]:
    """Markdown matrix table (one row per target × profile)."""

    out = [
        "## Matrix (per target folder)",
        "",
        "| Target | Profile | fail | manual-review | pass | other |",
        "| --- | --- | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        summary = row.summary_by_status
        other = sum(v for k, v in summary.items() if k not in {"fail", "manual-review-required", "pass"})
        out.append(
            f"| `{row.target_name}` | `{row.profile_id}` | {summary.get('fail', 0)} | "
            f"{summary.get('manual-review-required', 0)} | {summary.get('pass', 0)} | {other} |"
        )
    out.append("")
    return out


def _batch_md_artifact_lines(
    rows: list[BatchRunRow], output_dir: Path, *, include_absolute_path: bool = False
) -> list[str]:
    """Markdown list of per-run report artifact paths (relative to the batch output dir).

    Paths render relative to *output_dir* in the normal flow. The rare
    ``ValueError`` fallback (a report outside the output directory) is sanitized to
    a basename by default (M-002) so the shareable batch Markdown never leaks an
    absolute path / username; ``include_absolute_path=True`` restores the full path.
    """

    out = ["## Report artifacts (paths relative to batch output directory)", ""]
    out_abs = output_dir.resolve()
    for row in rows:
        jp = Path(row.report_path_json).resolve()
        mp = Path(row.report_path_md).resolve()
        try:
            j_show, m_show = jp.relative_to(out_abs).as_posix(), mp.relative_to(out_abs).as_posix()
        except ValueError:
            j_show = _sanitize_target_path_for_payload(str(jp), include_absolute=include_absolute_path)
            m_show = _sanitize_target_path_for_payload(str(mp), include_absolute=include_absolute_path)
        out.append(f"- `{row.target_name}` x `{row.profile_id}` -> `{j_show}` , `{m_show}`")
    return out


def _render_batch_markdown(
    rows: list[BatchRunRow],
    *,
    generated_at: str,
    target_root: Path,
    profile_ids: list[str],
    eval_queue_len: int,
    gate_violated: bool,
    policy: FailOnPolicy,
    stats: _BatchStats,
    skipped_dirs: list[dict[str, str]],
    output_dir: Path,
    include_absolute_path: bool = False,
) -> str:
    """Render the consolidated batch Markdown report."""

    target_root_display = _sanitize_target_path_for_payload(
        str(target_root.resolve()), include_absolute=include_absolute_path
    )
    md_lines = [
        "# OSS Policy Kit - batch evaluation",
        "",
        f"- **Generated (UTC)**: `{generated_at}`",
        f"- **Kit version**: `{oss_policy_kit.__version__}`",
        f"- **Target root**: `{target_root_display}`",
        f"- **Profiles**: {', '.join(f'`{p}`' for p in profile_ids)}",
        (
            f"- **Targets evaluated**: {eval_queue_len} child folder(s) x {len(profile_ids)} "
            f"profile(s) = {len(rows)} run(s)"
        ),
        "",
        "## Consolidated status totals (all runs)",
        "",
    ]
    md_lines.extend(f"- `{status}`: **{stats.totals[status]}**" for status in sorted(stats.totals))
    gate_state = "**VIOLATED**" if gate_violated else "**PASSED**"
    md_lines.extend(["", f"- **CI gate (`--fail-on: {policy}`)**: {gate_state}", ""])

    dist = stats.dist
    md_lines.extend(
        [
            "## Failure distribution (per target, total `fail` across profiles)",
            "",
            "| Fail count range | Repositories |",
            "| --- | ---: |",
            f"| 0 | {dist['0']} |",
            f"| 1-5 | {dist['1-5']} |",
            f"| 6-10 | {dist['6-10']} |",
            f"| 11+ | {dist['11+']} |",
            "",
        ]
    )

    if stats.comparison_lines:
        md_lines.extend(["## Quick comparison (by total `fail` counts across profiles)", ""])
        md_lines.extend(f"- {ln}" if ln.startswith("All **") else ln for ln in stats.comparison_lines)
        md_lines.append("")

    if skipped_dirs:
        md_lines.extend(["## Skipped directories", ""])
        md_lines.extend(f"- `{s['name']}` — {s['reason']}" for s in skipped_dirs)
        md_lines.append("")

    md_lines.extend(_batch_md_matrix_lines(rows))
    if stats.gap_hits:
        md_lines.extend(
            ["## Repeated failing controls (across runs)", "", "| Control id | Runs (count) |", "| --- | ---: |"]
        )
        md_lines.extend(f"| `{cid}` | {n} |" for cid, n in stats.gap_hits.most_common(15))
        md_lines.append("")
    md_lines.extend(_batch_md_artifact_lines(rows, output_dir, include_absolute_path=include_absolute_path))
    return "\n".join(md_lines)
