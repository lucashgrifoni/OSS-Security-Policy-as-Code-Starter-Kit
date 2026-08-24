"""One unreadable file inside the evaluated repository must not cancel the evaluation.

The kit reads a repository nobody vouched for. A file in it that cannot be read is not a usage
error the operator can fix and not a defect in the kit -- it is the ordinary condition the product
exists to survive. The contract everywhere else in this codebase is that such a file degrades the
control that needed it and the run still produces a report.

Measured across nine hostile shapes planted in an otherwise ordinary target, eight degraded
correctly (exit 1, report written): a `.gitlab-ci.yml` that is a directory, a `.tf` that is a
directory, evidence with the wrong root type, evidence nested 5000 levels, evidence holding a
6000-digit integer, a workflow full of binary bytes, and malformed SARIF. One did not:

    .github/workflows/ci.yml as a directory  ->  exit 2, no report at all
    "Error: input could not be read: it could not be read (Permission denied)"

Same shape, three parsers, one refusing the whole evaluation. The GitHub workflow reader takes its
bytes outside the `try` that guards parsing, so an `OSError` from the read escapes to the CLI's
bad-input handler, which is right about the exception and wrong about the scope: the input it
names is the repository, not the file.

This predates the encoding work in this campaign -- the line was `path.read_text(...)` before it
became `decode_source(path.read_bytes())`, both outside the guard, and both raise `PermissionError`
on an unreadable path. Verified rather than assumed, because "did I cause this" is worth answering
before writing a fix.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

runner = CliRunner()


def _target(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "README.md").write_text("# demo\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _evaluate(target: Path, out: Path) -> object:
    return runner.invoke(
        app, ["evaluate", "--target", str(target), "--profile", "github-level-1", "--output-dir", str(out)]
    )


def test_an_unreadable_workflow_degrades_instead_of_cancelling_the_evaluation(tmp_path: Path) -> None:
    """The reproduction: the run has to finish and say what it could not read."""

    target = _target(tmp_path / "target")
    (target / ".github" / "workflows" / "ci.yml").mkdir(parents=True)
    out = tmp_path / "out"

    result = _evaluate(target, out)

    assert result.exit_code in (0, 1), (  # type: ignore[attr-defined]
        f"one unreadable file ended the whole run with exit {result.exit_code}: {result.output}"  # type: ignore[attr-defined]
    )
    assert (out / "evaluation-report.json").is_file(), "no report was written at all"


def test_the_unreadable_workflow_is_recorded_rather_than_read_as_empty(tmp_path: Path) -> None:
    """Surviving is not enough -- an unread file must not become "this repository has no workflow".

    `parse_errors` is what the controls already consult before claiming absence, so recording it
    here is what keeps a missing read from turning into a positive claim.
    """

    target = _target(tmp_path / "target")
    (target / ".github" / "workflows" / "ci.yml").mkdir(parents=True)

    analysis = analyze_workflows(target)

    assert analysis.parse_errors, "the file was skipped silently"
    assert any("ci.yml" in path.name for path, _ in analysis.parse_errors)


def test_the_recorded_reason_does_not_name_the_host_layout(tmp_path: Path) -> None:
    """`str(OSError)` embeds the absolute filename; the reason is published in the report (M-002).

    The assertion looks for a path SEGMENT rather than the whole path, and that detail is the
    whole test. A first version compared against `str(tmp_path)` and a mutation swapping
    `bad_input_detail` back to `str(exc)` walked straight past it: `OSError.__str__` renders the
    filename through `repr()`, so the message carries doubled backslashes on Windows and a
    single-backslash path never substring-matches. The check passed for a reason unrelated to
    whether anything leaked.
    """

    target = _target(tmp_path / "target")
    (target / ".github" / "workflows" / "ci.yml").mkdir(parents=True)

    analysis = analyze_workflows(target)

    assert analysis.parse_errors, "nothing was recorded, so this proves nothing about the wording"
    assert not any(tmp_path.name in message for _, message in analysis.parse_errors), (
        "the published reason named a directory from the host layout"
    )


def test_a_readable_workflow_is_still_read(tmp_path: Path) -> None:
    """Guarding the read must not make an ordinary workflow look unreadable."""

    target = _target(tmp_path / "target")
    wf = target / ".github" / "workflows"
    wf.mkdir(parents=True)
    wf.joinpath("ci.yml").write_text(
        "name: ci\non:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )

    analysis = analyze_workflows(target)

    assert not analysis.parse_errors
    assert analysis.mutable_action_refs, "the readable workflow stopped being scanned"


@pytest.mark.parametrize("relative", [".gitlab-ci.yml", "main.tf"])
def test_the_parsers_that_already_survived_this_keep_surviving(tmp_path: Path, relative: str) -> None:
    """The contrast that made the finding legible, pinned so the three stay consistent.

    These two took the same hostile shape and answered exit 1 with a report. They are the reason
    the GitHub reader reads as the outlier rather than as the intended behaviour.
    """

    target = _target(tmp_path / relative.replace("/", "-").replace(".", "-"))
    (target / relative).mkdir()
    out = tmp_path / f"out-{relative.replace('/', '-')}"

    result = _evaluate(target, out)

    assert result.exit_code in (0, 1), result.output  # type: ignore[attr-defined]
    report = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
    assert report["controls_total"] > 0
