"""Text the kit did not write must not become Markdown in the reports it writes.

`evaluate-many` prints the name of every directory it scanned, `evaluate` prints the target
path and every evidence reference it followed, and `diff-reports` prints the two report paths
it compared. None of that belongs to the kit: it comes from the filesystem being scanned and
from files inside it.

Each of those values was wrapped in a single pair of backticks, and a value can close that.
A directory called ``evil`name[click](x)`` ends the span at its own backtick, leaving
``name[click](x)`` outside it, and the batch report rendered five links the kit never wrote,
each pointing wherever the directory name said. The person reading the report has no way to
tell those from the report's own text.

CommonMark supplies the fix rather than an escape: a code span opened with a run of N
backticks closes on the next run of exactly N, so a fence one backtick longer than the longest
run inside the value cannot be closed from inside it.

These tests go through the report builders rather than the helper, so they state what a reader
of the report sees, and so they fail on the commit before the fix by assertion instead of
failing to import.
"""

from __future__ import annotations

import html
from collections import Counter
from pathlib import Path

import pytest
from markdown_it import MarkdownIt

from oss_policy_kit.application.batch_evaluate import (
    BatchRunRow,
    _BatchStats,
    _render_batch_markdown,
)
from oss_policy_kit.application.reporting import _markdown_report_text
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport

#: Names that close the span the report opens around them. A payload without a backtick
#: cannot: whatever else it contains stays inside the span. That is why every case carries
#: one, and why a guard built from link syntax alone would pass on the broken code.
_ESCAPING_NAMES = [
    pytest.param("evil`name[click](x)", id="one-backtick"),
    pytest.param("a``b[click](x)", id="two-backtick-run"),
    pytest.param("`leading[click](x)", id="leading-backtick"),
    pytest.param("trailing[click](x)`", id="trailing-backtick"),
    pytest.param("t`[a](x)`[b](y)", id="two-payloads"),
]


def _links(markdown: str) -> list[str]:
    """Every href a CommonMark reader finds in *markdown*.

    markdown-it-py is the reference implementation's Python port, and it is declared in the
    dev extra for this. Re-deriving the rule here instead would only repeat the reasoning the
    fix is built on, and would agree with it even where both were wrong.
    """

    found: list[str] = []
    for token in MarkdownIt("commonmark").parse(markdown):
        for child in token.children or []:
            if child.type == "link_open":
                found.append(str(child.attrGet("href") or ""))
    return found


def _stats() -> _BatchStats:
    return _BatchStats(
        totals={"pass": 10, "fail": 1},
        dist={"0": 0, "1-5": 1, "6-10": 0, "11+": 0},
        comparison_lines=[],
        gap_hits=Counter(),
        all_tied=True,
        common_fail_count=1,
    )


def _batch_markdown(name: str, tmp_path: Path) -> str:
    row = BatchRunRow(
        target_name=name,
        target_path=f"./{name}",
        profile_id="github-level-2",
        summary_by_status={"pass": 10, "fail": 1},
        report_path_json=str(tmp_path / name / "evaluation-report.json"),
        report_path_md=str(tmp_path / name / "evaluation-report.md"),
    )
    return _render_batch_markdown(
        [row],
        generated_at="2026-09-19T00:00:00Z",
        target_root=tmp_path,
        profile_ids=["github-level-2"],
        eval_queue_len=1,
        gate_violated=False,
        policy="fail",
        stats=_stats(),
        skipped_dirs=[{"name": name, "reason": "not a repository"}],
        failed_dirs=[{"name": name, "reason": "unreadable"}],
        output_dir=tmp_path,
    )


def _report(*, target_path: str = "repo", evidence: list[str] | None = None) -> ExecutionReport:
    result = ControlResult(
        control_id="GOV-SEC-001",
        title="Security policy present",
        category="governance",
        status=ControlStatus.FAIL,
        profile="github-level-1",
        evidence_sources=evidence or [],
        confidence="high",
        reason="no SECURITY.md",
        remediation="add SECURITY.md",
    )
    return ExecutionReport(
        schema_version="https://x/reports/2.0",
        generated_at="2026-09-19T00:00:00Z",
        kit_version="10.0.24",
        target_path=target_path,
        profile_id="github-level-1",
        profile_title="GitHub level 1",
        summary_by_status={"fail": 1},
        results=[result],
        operational_warnings=[],
    )


@pytest.mark.parametrize("name", _ESCAPING_NAMES)
def test_a_directory_name_adds_no_link_to_the_batch_report(name: str, tmp_path: Path) -> None:
    """The name reaches five places in this report; none of them may produce an anchor."""

    assert _links(_batch_markdown(name, tmp_path)) == []


@pytest.mark.parametrize("name", _ESCAPING_NAMES)
def test_the_batch_report_still_says_the_name_that_is_on_disk(name: str, tmp_path: Path) -> None:
    """Deleting the offending characters would silence the payload and the evidence with it.

    An operator reading `evaluate-many` output has to be able to match a row against a
    directory. A fix that stripped backticks would pass the test above and leave the report
    naming a directory that does not exist, so the name is required back verbatim.
    """

    rendered = MarkdownIt("commonmark").render(_batch_markdown(name, tmp_path))
    assert html.escape(name, quote=False) in rendered


def test_a_pipe_in_a_directory_name_stays_inside_its_table_cell(tmp_path: Path) -> None:
    """A pipe ends a cell, so the matrix row would gain columns and shift every value right.

    Not reachable through a directory on Windows, which forbids the character, and perfectly
    reachable on the Linux and macOS runners the kit documents.
    """

    row = next(line for line in _batch_markdown("a|b`c", tmp_path).splitlines() if line.startswith("| `"))
    assert row.count("|") - row.count(r"\|") == 7


@pytest.mark.parametrize("name", _ESCAPING_NAMES)
def test_a_target_path_adds_no_link_to_the_single_report(name: str) -> None:
    assert _links(_markdown_report_text(_report(target_path=name))) == []


@pytest.mark.parametrize("name", _ESCAPING_NAMES)
def test_an_evidence_reference_adds_no_link_to_the_single_report(name: str) -> None:
    """Evidence references name files found inside the target, so the target chooses them."""

    assert _links(_markdown_report_text(_report(evidence=[f"{name}/SECURITY.md"]))) == []
