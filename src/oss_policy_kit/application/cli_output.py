"""CLI stdout helpers for automation-friendly summaries."""

from __future__ import annotations

import json
import sys
import textwrap
from typing import Literal

from oss_policy_kit.application.reporting import _sanitize_target_path_for_payload, compute_priority_insights
from oss_policy_kit.cli.terminal_ui import (
    human_tty_stdout,
    max_gap_line_chars,
    print_interactive_stdout_summary,
    terminal_width,
    write_to_stdout,
)
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport

OutputFormat = Literal["human", "json"]
FailOnPolicy = Literal["none", "fail", "degraded"]
STATUS_ORDER: tuple[str, ...] = (
    "pass",
    "attested",
    "fail",
    "manual-review-required",
    "self-attested",
    "not-evaluated",
    "waived",
    "not-observable",
    "not-applicable",
)


def _ordered_summary(summary_by_status: dict[str, int]) -> dict[str, int]:
    """Return status counts in a stable, policy-oriented order."""

    ordered: dict[str, int] = {}
    for status in STATUS_ORDER:
        if status in summary_by_status:
            ordered[status] = summary_by_status[status]
    # Preserve forward compatibility for any future status keys.
    for status, count in summary_by_status.items():
        if status not in ordered:
            ordered[status] = count
    return ordered


def _human_primary_gap_line(result: ControlResult, *, max_len: int) -> str:
    """Build a short, failure-oriented gap line (avoid catalog titles that read like successes)."""

    reason = (result.reason or "").strip().replace("\n", " ")
    if reason:
        if len(reason) > max_len:
            return reason[: max_len - 1].rstrip() + "..."
        return reason
    return f"{result.control_id}: action required (see report for details)."


def fail_on_violated(policy: FailOnPolicy, summary_by_status: dict[str, int]) -> bool:
    """Return True when the run should exit with code 1 for policy reasons."""

    if policy == "none":
        return False
    fails = summary_by_status.get("fail", 0)
    if policy == "fail":
        return fails > 0
    if policy == "degraded":
        manual = summary_by_status.get("manual-review-required", 0)
        return fails > 0 or manual > 0
    raise ValueError(f"Unknown fail-on policy: {policy!r}")


def _collect_gap_lines(report: ExecutionReport, *, gap_max: int) -> list[str]:
    fails = [r for r in report.results if r.status == ControlStatus.FAIL]
    mrr = [r for r in report.results if r.status == ControlStatus.MANUAL_REVIEW_REQUIRED]
    gap_lines: list[str] = []
    seen: set[str] = set()
    for r in fails + mrr:
        line = _human_primary_gap_line(r, max_len=gap_max)
        if line in seen:
            continue
        gap_lines.append(line)
        seen.add(line)
        if len(gap_lines) >= 3:
            break
    if not gap_lines:
        insights = compute_priority_insights(report)
        for row in insights["top_structural_causes"][:3]:
            bucket = str(row["bucket"])
            if bucket not in seen:
                gap_lines.append(f"{bucket} ({row['count']} control(s))")
                seen.add(bucket)
            if len(gap_lines) >= 3:
                break
    return gap_lines


def _print_stdout_summary_plain(report: ExecutionReport) -> None:
    """Stable plaintext summary for pipes, tests, and non-interactive stdout."""

    ordered_summary = _ordered_summary(report.summary_by_status)
    tw = max(20, terminal_width(sys.stdout))
    gap_max = max_gap_line_chars(stream=sys.stdout)
    lines: list[str] = []
    lines.append(f"Profile: {report.profile_id}")
    lines.append(f"Target: {report.target_path}")
    status_bits = [f"{k}={v}" for k, v in ordered_summary.items() if v]
    lines.append("Outcome: " + (", ".join(status_bits) if status_bits else "(no counts)"))
    total_c = sum(ordered_summary.values())
    warn_c = len(report.operational_warnings)
    lines.append(f"Controls: {total_c} | Operational warnings: {warn_c}")
    if report.weighted_score is not None:
        ws = report.weighted_score
        lines.append(f"Weighted score: {ws.earned}/{ws.possible} ({ws.percent}%)")

    gap_lines = _collect_gap_lines(report, gap_max=gap_max)
    lines.append("")
    lines.append("Top gaps:")
    bullet_w = max(12, tw - 4)
    for g in gap_lines[:3]:
        wrapped = textwrap.wrap(
            g,
            width=bullet_w,
            break_long_words=True,
            break_on_hyphens=False,
        )
        if not wrapped:
            continue
        lines.append(f"  - {wrapped[0]}")
        lines.extend(f"    {ln}" for ln in wrapped[1:])

    insights = compute_priority_insights(report)
    next_step = (
        insights["recommended_actions"][0]
        if insights["recommended_actions"]
        else "Revise o relatório Markdown/JSON para priorizar correções."
    )
    lines.append("")
    lines.append("Suggested next step:")
    step_w = max(12, tw - 2)
    lines.extend(textwrap.wrap(next_step, width=step_w, break_long_words=True, break_on_hyphens=False))

    if report.external_waiver_path:
        lines.append("")
        note = (
            "Waiver note: an external file was loaded via --waivers; "
            "this does not change GOV-WAIV-014 (versioned waivers in the repository)."
        )
        lines.extend(textwrap.wrap(note, width=tw, break_long_words=True, break_on_hyphens=False))
        path_prefix = "  Path: "
        path_rest = report.external_waiver_path
        if len(path_prefix) + len(path_rest) <= tw:
            lines.append(path_prefix + path_rest)
        else:
            lines.append(path_prefix.rstrip())
            path_w = max(12, tw - 4)
            lines.extend(f"    {pl}" for pl in textwrap.wrap(path_rest, width=path_w, break_long_words=True))

    write_to_stdout("\n".join(lines) + "\n")


def print_stdout_summary(
    report: ExecutionReport,
    *,
    output_format: OutputFormat,
    include_absolute_path: bool = False,
) -> None:
    """Emit a compact machine- or human-readable summary line to stdout (for piping).

    ``include_absolute_path`` mirrors the report writers (M-002): the ``json``
    stdout payload sanitizes ``target_path`` to the target's basename by default
    so a piped/redirected summary never leaks the auditor's home directory or
    username. Pass ``True`` to keep the engine-resolved absolute path.
    """

    if output_format == "json":
        ordered_summary = _ordered_summary(report.summary_by_status)
        payload = {
            "schema_version": report.schema_version,
            "kit_version": report.kit_version,
            "profile_id": report.profile_id,
            "target_path": _sanitize_target_path_for_payload(
                report.target_path, include_absolute=include_absolute_path
            ),
            "summary_by_status": ordered_summary,
            "controls_total": sum(ordered_summary.values()),
            "operational_warnings_count": len(report.operational_warnings),
        }
        if report.weighted_score is not None:
            ws = report.weighted_score
            payload["weighted_score"] = {"earned": ws.earned, "possible": ws.possible, "percent": ws.percent}
        if report.scorecard_supplemental is not None:
            payload["scorecard_supplemental"] = report.scorecard_supplemental
        write_to_stdout(json.dumps(payload, ensure_ascii=False) + "\n")
        return

    if human_tty_stdout():
        gap_max = max_gap_line_chars(stream=sys.stdout)
        gap_lines = _collect_gap_lines(report, gap_max=gap_max)
        insights = compute_priority_insights(report)
        next_step = (
            insights["recommended_actions"][0]
            if insights["recommended_actions"]
            else "Revise o relatório Markdown/JSON para priorizar correções."
        )
        print_interactive_stdout_summary(report, gap_lines=gap_lines, next_step=next_step)
        if report.external_waiver_path:
            tw = max(20, terminal_width(sys.stdout))
            wlines: list[str] = []
            note = (
                "Waiver note: an external file was loaded via --waivers; "
                "this does not change GOV-WAIV-014 (versioned waivers in the repository)."
            )
            wlines.extend(textwrap.wrap(note, width=tw, break_long_words=True, break_on_hyphens=False))
            path_prefix = "  Path: "
            path_rest = report.external_waiver_path
            if len(path_prefix) + len(path_rest) <= tw:
                wlines.append(path_prefix + path_rest)
            else:
                wlines.append(path_prefix.rstrip())
                path_w = max(12, tw - 4)
                wlines.extend(f"    {pl}" for pl in textwrap.wrap(path_rest, width=path_w, break_long_words=True))
            write_to_stdout("\n" + "\n".join(wlines) + "\n")
        return

    _print_stdout_summary_plain(report)
