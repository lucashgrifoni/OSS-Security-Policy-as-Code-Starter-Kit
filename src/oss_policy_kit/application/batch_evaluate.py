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
from oss_policy_kit.application.loader import load_catalog, load_profile_by_id, merge_kit_root
from oss_policy_kit.application.reporting import compute_priority_insights, report_to_dict, write_markdown_report
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


def is_likely_repository(path: Path) -> tuple[bool, str]:
    """Return ``(True, signal_found)`` when *path* looks like a repository root.

    Requires at least one primary signal (build manifest, CI file, Dockerfile, or ``.git``).
    ``README.md`` alone is not sufficient to avoid false positives from utility subdirectories
    in monorepos. As a fallback for monorepo-style layouts where signals live one or two
    directories deep (e.g. ``infra/k8s-manifests/*.yaml``, ``targets/*/Dockerfile``),
    also accept signals at depth 1 or 2 from the candidate root.
    """

    for signal in _REPO_PRIMARY_SIGNALS:
        if (path / signal).exists():
            return True, signal
    for pattern in _REPO_GLOB_PRIMARY:
        if list(path.glob(pattern)):
            return True, pattern
    # Monorepo fallback: look for primary signals at depth 1 or 2.
    for depth_pattern in ("*", "*/*"):
        for signal in _REPO_PRIMARY_SIGNALS:
            try:
                if next(iter(path.glob(f"{depth_pattern}/{signal}")), None) is not None:
                    return True, f"{depth_pattern}/{signal}"
            except OSError:
                continue
    # Also accept Kubernetes manifests one or two levels deep — common for cloud-native
    # repositories that hold manifests under ``infra/``, ``deploy/``, ``manifests/``.
    for k8s_pattern in ("*/k8s-manifests/*.yaml", "*/*/k8s-manifests/*.yaml", "*/manifests/*.yaml"):
        try:
            if next(iter(path.glob(k8s_pattern)), None) is not None:
                return True, k8s_pattern
        except OSError:
            continue
    return False, ""


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


def discover_batch_targets(
    target_root: Path,
    *,
    include: str | None,
    exclude: str | None,
) -> list[Path]:
    """Return immediate child directories of *target_root* suitable as repo roots."""

    out: list[Path] = []
    for child in sorted(target_root.iterdir(), key=lambda p: p.name.lower()):
        if not child.is_dir():
            continue
        if child.name.startswith("."):
            continue
        if include and not fnmatch.fnmatch(child.name, include):
            continue
        if exclude and fnmatch.fnmatch(child.name, exclude):
            continue
        out.append(child)
    return out


def run_batch_evaluation(
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
) -> BatchResult:
    """Evaluate each discovered child of *target_root* against every *profile_id*.

    Writes per-run ``evaluation-report.{json,md}`` under
    ``output_dir / <sanitized_target_name> / <profile_id> /`` plus consolidated
    ``evaluation-batch.json`` and ``evaluation-batch.md`` at *output_dir*.
    """

    policy = cast(FailOnPolicy, fail_on.lower())
    root = merge_kit_root(kit_root)
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    targets = discover_batch_targets(target_root, include=include, exclude=exclude)
    if not targets:
        raise InvalidInputError(f"No subdirectories to evaluate under {target_root}")

    skipped_dirs: list[dict[str, str]] = []
    eval_queue: list[tuple[Path, bool]] = []
    for child in targets:
        likely, _sig = is_likely_repository(child)
        if skip_non_repos and not likely:
            skipped_dirs.append(
                {
                    "name": child.name,
                    "path": str(child.resolve()),
                    "reason": "No repository root signals (.git, manifest, CI file, Dockerfile, etc.).",
                }
            )
            continue
        eval_queue.append((child, likely))

    if not eval_queue:
        raise InvalidInputError(
            "No repositories to evaluate after filtering. Remove --skip-non-repos or add include/exclude patterns."
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[BatchRunRow] = []
    consolidated_reports: list[dict[str, Any]] = []
    summaries_for_gate: list[dict[str, int]] = []
    total_runs = len(eval_queue) * len(profile_ids)
    run_index = 0

    for target, likely_repo in eval_queue:
        repo = resolve_existing_dir(str(target))
        safe_name = target.name.replace("/", "_").replace("\\", "_")
        for pid in profile_ids:
            run_index += 1
            if progress_callback is not None:
                progress_callback(target.name, run_index, total_runs)
            profile = load_profile_by_id(root, pid)
            report = evaluate_repository(
                repo_root=repo,
                profile=profile,
                catalog=catalog,
                waiver_outcome=None,
                scorecard=None,
            )
            dest = output_dir / safe_name / pid
            dest.mkdir(parents=True, exist_ok=True)
            json_path = dest / "evaluation-report.json"
            md_path = dest / "evaluation-report.md"
            json_path.write_text(
                json.dumps(report_to_dict(report), indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            write_markdown_report(report, md_path)
            rows.append(
                BatchRunRow(
                    target_name=target.name,
                    target_path=str(repo.resolve()),
                    profile_id=pid,
                    summary_by_status=dict(report.summary_by_status),
                    report_path_json=str(json_path.resolve()),
                    report_path_md=str(md_path.resolve()),
                )
            )
            summaries_for_gate.append(dict(report.summary_by_status))
            run_payload: dict[str, Any] = {
                "target_name": target.name,
                "target_path": str(repo.resolve()),
                "profile_id": pid,
                "summary_by_status": report.summary_by_status,
                "action_insights": compute_priority_insights(report),
                "reports": {"json": str(json_path.resolve()), "markdown": str(md_path.resolve())},
            }
            if not skip_non_repos and not likely_repo:
                run_payload["likely_not_a_repository"] = True
            consolidated_reports.append(run_payload)

    generated_at = report_generated_at()
    gate_violated = _gate_violated_for_batch(policy, summaries_for_gate)

    totals: dict[str, int] = defaultdict(int)
    for row in rows:
        for k, v in row.summary_by_status.items():
            totals[k] += v

    fails_by_target: dict[str, int] = defaultdict(int)
    for row in rows:
        fails_by_target[row.target_name] += row.summary_by_status.get("fail", 0)

    fc_values = _batch_failure_counts(fails_by_target)
    all_tied = len(fails_by_target) >= 2 and len(set(fc_values)) == 1
    common_fail_count: int | None = fc_values[0] if all_tied else None

    comparison_lines: list[str] = []
    if fails_by_target:
        if all_tied:
            comparison_lines.append(
                f"All **{len(fails_by_target)}** repositories share the same failure count "
                f"({common_fail_count}) — no clear best or worst performer."
            )
        else:
            max_f = max(fails_by_target.values())
            min_f = min(fails_by_target.values())
            worst_targets = sorted(n for n, c in fails_by_target.items() if c == max_f)
            best_targets = sorted(n for n, c in fails_by_target.items() if c == min_f)
            comparison_lines.append(
                f"- **Most failures (tie-break: lexicographic name)**: {', '.join(f'`{n}`' for n in worst_targets)}"
            )
            comparison_lines.append(f"- **Fewest failures**: {', '.join(f'`{n}`' for n in best_targets)}")

    dist = _failure_distribution_bucketing(fc_values)

    gap_hits: Counter[str] = Counter()
    for cr in consolidated_reports:
        ac = cr.get("action_insights") or {}
        for ids in (ac.get("failing_controls_by_category") or {}).values():
            for cid in ids:
                gap_hits[str(cid)] += 1

    batch_payload: dict[str, Any] = {
        "schema_version": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/batch/0.1",
        "generated_at": generated_at,
        "kit_version": oss_policy_kit.__version__,
        "target_root": str(target_root.resolve()),
        "profile_ids": profile_ids,
        "gate_violated": gate_violated,
        "fail_on": policy,
        "all_tied": all_tied,
        "common_fail_count": common_fail_count,
        "failure_distribution": dist,
        "runs": consolidated_reports,
    }
    if skipped_dirs:
        batch_payload["skipped_directories"] = skipped_dirs

    batch_json = output_dir / "evaluation-batch.json"
    batch_json.write_text(json.dumps(batch_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md_lines = [
        "# OSS Policy Kit - batch evaluation",
        "",
        f"- **Generated (UTC)**: `{generated_at}`",
        f"- **Kit version**: `{oss_policy_kit.__version__}`",
        f"- **Target root**: `{target_root.resolve()}`",
        f"- **Profiles**: {', '.join(f'`{p}`' for p in profile_ids)}",
        (
            f"- **Targets evaluated**: {len(eval_queue)} child folder(s) x {len(profile_ids)} "
            f"profile(s) = {len(rows)} run(s)"
        ),
        "",
        "## Consolidated status totals (all runs)",
        "",
    ]
    for status in sorted(totals.keys()):
        md_lines.append(f"- `{status}`: **{totals[status]}**")
    md_lines.append("")

    label = policy
    gate_state = "**VIOLATED**" if gate_violated else "**PASSED**"
    md_lines.append(f"- **CI gate (`--fail-on: {label}`)**: {gate_state}")
    md_lines.append("")

    md_lines.append("## Failure distribution (per target, total `fail` across profiles)")
    md_lines.append("")
    md_lines.append("| Fail count range | Repositories |")
    md_lines.append("| --- | ---: |")
    md_lines.append(f"| 0 | {dist['0']} |")
    md_lines.append(f"| 1-5 | {dist['1-5']} |")
    md_lines.append(f"| 6-10 | {dist['6-10']} |")
    md_lines.append(f"| 11+ | {dist['11+']} |")
    md_lines.append("")

    if comparison_lines:
        md_lines.append("## Quick comparison (by total `fail` counts across profiles)")
        md_lines.append("")
        for ln in comparison_lines:
            if ln.startswith("All **"):
                md_lines.append(f"- {ln}")
            else:
                md_lines.append(ln)
        md_lines.append("")

    if skipped_dirs:
        md_lines.append("## Skipped directories")
        md_lines.append("")
        for s in skipped_dirs:
            md_lines.append(f"- `{s['name']}` — {s['reason']}")
        md_lines.append("")

    md_lines.extend(
        [
            "## Matrix (per target folder)",
            "",
            "| Target | Profile | fail | manual-review | pass | other |",
            "| --- | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for row in rows:
        summary = row.summary_by_status
        fails = summary.get("fail", 0)
        mrr = summary.get("manual-review-required", 0)
        passes = summary.get("pass", 0)
        other = sum(v for k, v in summary.items() if k not in {"fail", "manual-review-required", "pass"})
        md_lines.append(f"| `{row.target_name}` | `{row.profile_id}` | {fails} | {mrr} | {passes} | {other} |")
    md_lines.append("")
    if gap_hits:
        md_lines.append("## Repeated failing controls (across runs)")
        md_lines.append("")
        md_lines.append("| Control id | Runs (count) |")
        md_lines.append("| --- | ---: |")
        for cid, n in gap_hits.most_common(15):
            md_lines.append(f"| `{cid}` | {n} |")
        md_lines.append("")
    md_lines.append("## Report artifacts (paths relative to batch output directory)")
    md_lines.append("")
    out_abs = output_dir.resolve()
    for row in rows:
        jp = Path(row.report_path_json).resolve()
        mp = Path(row.report_path_md).resolve()
        try:
            rel_json = jp.relative_to(out_abs)
            rel_md = mp.relative_to(out_abs)
            j_show, m_show = rel_json.as_posix(), rel_md.as_posix()
        except ValueError:
            j_show, m_show = str(jp), str(mp)
        md_lines.append(f"- `{row.target_name}` x `{row.profile_id}` -> `{j_show}` , `{m_show}`")
    batch_md = output_dir / "evaluation-batch.md"
    batch_md.write_text("\n".join(md_lines), encoding="utf-8")

    return BatchResult(batch_json=batch_json, batch_md=batch_md, gate_violated=gate_violated)
