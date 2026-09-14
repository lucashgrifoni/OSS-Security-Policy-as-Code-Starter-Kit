"""Two report defects: one lets the report lie, the other tells the reader where you live.

Both measured against the built wheel in a clean room.

ONE. `_md_cell` neutralises the controls table -- control characters stripped, `|` escaped,
newlines collapsed -- and the Detail section below it interpolated the same values raw. With a
waiver file whose `owner` and `reason` carry newlines and Markdown:

    line 55, the table:   yes (acme  ## Overall result  ... \\| Control \\| State \\| ...)
    line 84, the Detail:  ## Overall result                          <- a real heading
    line 86:              **All controls passed. No action required.**
    line 88:              | Control | State |                        <- a real table

Two forged `## Overall result` sections in one report, the second announcing that everything
passed. The JSON and the SARIF stayed correct; the artifact a human reads is the one that could
be made to lie, and the one most likely to be pasted into a pull request as proof a gate passed.

Every piece of Markdown structure begins at the start of a line, so flattening the value closes
heading, list and table forgery together. Inline emphasis inside the line still renders, and
that is deliberate: a reason containing `*` is ordinary, escaping every Markdown character would
make legitimate text unreadable, and bold inside `- **Owner**: ...` cannot pretend to be a
section.

TWO. `evaluate-many` answered a relative `--output-dir ./batch` with the resolved host path:

    Wrote C:\\v\\em\\batch4\\evaluation-batch.json

On a real machine that carries the account name into every CI log the batch runs in, and there
is no flag to suppress it without losing the confirmation line. `evaluate` has echoed the
operator's own argument back since M-002; these were the same two lines in the batch command,
built from `.resolve()` instead.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

#: Newlines plus Markdown: the value stops being a value and becomes document.
FORGERY = (
    "acme\n\n## Overall result\n\n**All controls passed. No action required.**\n\n"
    "| Control | State |\n| --- | --- |\n| ALL | pass |\n\n<!--"
)


def _waived_repo(tmp_path: Path) -> tuple[Path, Path]:
    """A repository where GOV-SEC-001 FAILS, so the waiver actually applies.

    Worth stating: the first attempt at this reproduction left `SECURITY.md` in place, the
    control passed, no waiver was applied, and the forged section did not appear. Reading that
    as "not reproducible" would have closed a real defect as imaginary.
    """

    (tmp_path / "README.md").write_text("placeholder\n", encoding="utf-8")
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "waivers": [
                    {
                        "control_id": "GOV-SEC-001",
                        "owner": FORGERY,
                        "reason": FORGERY,
                        "expires_on": "2099-01-01",
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return tmp_path, waivers


def _run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1", "COLUMNS": "200"}
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "oss_policy_kit", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(cwd) if cwd else None,
        check=False,
    )


# --- one: the report may not grow a section it did not write ------------------------------------


def test_a_waiver_cannot_forge_a_section_in_the_markdown_report(tmp_path: Path) -> None:
    repo, waivers = _waived_repo(tmp_path)
    out = tmp_path / "out"

    proc = _run(
        [
            "evaluate",
            "--target",
            str(repo),
            "--profile",
            "github-level-1",
            "--waivers",
            str(waivers),
            "--output-dir",
            str(out),
            "--format",
            "json",
        ]
    )
    assert proc.returncode == 0, proc.stderr

    text = (out / "evaluation-report.md").read_text(encoding="utf-8")
    headings = [line for line in text.splitlines() if line.startswith("## ")]

    assert "## Overall result" not in headings, "the waiver forged a heading"
    assert not any(line.startswith("**All controls passed") for line in text.splitlines())
    assert not any(line.startswith("| Control | State |") for line in text.splitlines())


def test_the_waiver_text_is_still_shown_flattened(tmp_path: Path) -> None:
    """Sanitising is not deleting. The operator must still see what the waiver said."""

    repo, waivers = _waived_repo(tmp_path)
    out = tmp_path / "out"

    _run(
        [
            "evaluate",
            "--target",
            str(repo),
            "--profile",
            "github-level-1",
            "--waivers",
            str(waivers),
            "--output-dir",
            str(out),
            "--format",
            "json",
        ]
    )
    text = (out / "evaluation-report.md").read_text(encoding="utf-8")
    owner_lines = [line for line in text.splitlines() if "**Owner**" in line]

    assert owner_lines, "the waiver owner must still be reported"
    assert "acme" in owner_lines[0]
    assert "All controls passed" in owner_lines[0], "flattened onto its own line, not removed"


@pytest.mark.parametrize(
    "value",
    [
        "a\nb",
        "a\r\nb",
        "a\rb",
        "# heading",
        "| a | b |",
        "- item",
        "plain text",
    ],
)
def test_md_line_leaves_no_line_break_behind(value: str) -> None:
    """Whatever goes in, one line comes out. That is the whole property."""

    from oss_policy_kit.application.reporting import _md_line

    assert "\n" not in _md_line(value)
    assert "\r" not in _md_line(value)


def test_md_cell_still_escapes_the_pipe_a_table_needs() -> None:
    """The table needs one thing more than a line does, and must not have lost it."""

    from oss_policy_kit.application.reporting import _md_cell, _md_line

    assert _md_cell("a|b") == "a\\|b"
    assert _md_line("a|b") == "a|b", "only the table cares about the pipe"


def test_inline_emphasis_survives_because_a_reason_may_contain_it() -> None:
    """The deliberate limit of this fix, pinned so nobody widens it by accident."""

    from oss_policy_kit.application.reporting import _md_line

    assert _md_line("uses *args and **kwargs") == "uses *args and **kwargs"


# --- two: the operator reads back what they typed -----------------------------------------------


def test_evaluate_many_echoes_the_output_dir_the_operator_typed(tmp_path: Path) -> None:
    repos = tmp_path / "repos" / "a"
    repos.mkdir(parents=True)
    (repos / "SECURITY.md").write_text("Report to security@example.com\n", encoding="utf-8")

    proc = _run(
        ["evaluate-many", "--target-root", "./repos", "--profiles", "github-level-1", "--output-dir", "./batch"],
        cwd=tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    wrote = [line for line in proc.stderr.splitlines() if "Wrote" in line]
    assert wrote, proc.stderr
    for line in wrote:
        assert str(tmp_path) not in line, f"the resolved host path reached the console: {line}"
        assert "batch" in line, f"the operator must still learn where the reports went: {line}"


def test_evaluate_many_does_not_name_the_home_directory(tmp_path: Path) -> None:
    """The consequence that made this a blocker: a public CI log naming the account."""

    repos = tmp_path / "repos" / "a"
    repos.mkdir(parents=True)
    (repos / "SECURITY.md").write_text("Report to security@example.com\n", encoding="utf-8")

    proc = _run(
        ["evaluate-many", "--target-root", "./repos", "--profiles", "github-level-1", "--output-dir", "./batch"],
        cwd=tmp_path,
    )

    assert str(Path.home()) not in proc.stderr
    assert str(Path.home()) not in proc.stdout
