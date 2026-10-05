"""Tests for scripts/action_summary.py (the composite Action's job summary + annotations)."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parents[2] / "scripts" / "action_summary.py"
_spec = importlib.util.spec_from_file_location("action_summary", _SCRIPT)
assert _spec is not None
assert _spec.loader is not None
action_summary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(action_summary)


def test_summary_has_counts_table_and_failing_section() -> None:
    report = {
        # reports/2.0 embeds the full profile object; the summary must extract its id.
        "profile": {"id": "github-level-1", "title": "GitHub OSS starter baseline (level 1)"},
        "controls": [
            {"id": "A", "state": "PASS"},
            {"id": "B", "state": "FAIL", "message": "missing thing"},
            {"id": "C", "state": "UNKNOWN"},
        ],
    }
    summary = action_summary.build_summary(report)
    assert "`github-level-1`" in summary  # id extracted, not the whole dict
    assert "title" not in summary  # the profile dict is not dumped verbatim
    assert "| PASS | 1 |" in summary
    assert "| FAIL | 1 |" in summary
    assert "### Failing controls" in summary
    assert "`B`" in summary
    assert "missing thing" in summary


def test_annotations_error_for_fail_warning_for_review() -> None:
    report = {
        "controls": [
            {"id": "B", "state": "FAIL", "reason": "bad"},
            {"id": "C", "state": "UNKNOWN", "reason": "review me"},
            {"id": "D", "state": "PASS"},
        ]
    }
    buf = io.StringIO()
    action_summary.emit_annotations(report, buf)
    out = buf.getvalue()
    assert "::error title=B::bad" in out
    assert "::warning title=C::review me" in out
    assert "title=D" not in out  # PASS controls get no annotation


def test_main_writes_to_github_step_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({"profile": "p", "controls": [{"id": "A", "state": "PASS"}]}), encoding="utf-8")
    rc = action_summary.main(["action_summary.py", str(report_file)])
    assert rc == 0
    assert "## oss-policy-kit" in summary_file.read_text(encoding="utf-8")


def test_main_is_non_fatal_on_missing_report(tmp_path: Path) -> None:
    # A missing/unreadable report must not crash the Action (returns 0).
    assert action_summary.main(["action_summary.py", str(tmp_path / "nope.json")]) == 0


def test_a_carriage_return_cannot_start_a_second_workflow_command() -> None:
    """The runner splits commands on a bare CR too; a job name carrying one forged an annotation."""

    report = {"controls": [{"id": "CICD-1", "state": "FAIL", "message": "job x\r::warning::forged %0A"}]}
    buf = io.StringIO()
    action_summary.emit_annotations(report, buf)
    out = buf.getvalue()

    assert out.count("\n") == 1
    assert "\r" not in out
    assert out == "::error title=CICD-1::job x%0D::warning::forged %250A\n"


def test_a_title_property_cannot_end_early() -> None:
    report = {"controls": [{"id": "A,b:c", "state": "UNKNOWN"}]}
    buf = io.StringIO()
    action_summary.emit_annotations(report, buf)
    assert buf.getvalue().startswith("::warning title=A%2Cb%3Ac::")


def test_repository_text_in_the_summary_is_shown_not_rendered() -> None:
    """Job names come from the scanned repository; tags and links in them must stay text."""

    message = 'job <img src="https://x.test/p.png"> [login](https://x.test) | col\nnext'
    summary = action_summary.build_summary({"controls": [{"id": "B", "state": "FAIL", "message": message}]})
    row = next(line for line in summary.splitlines() if line.startswith("| `B`"))

    assert "<img" not in row
    assert "&lt;img" in row
    assert "](" not in row.replace("\\](", "")
    assert "\\[login\\]" in row
    assert row.count("|") == 3  # the pipe and the newline did not add or end a cell
