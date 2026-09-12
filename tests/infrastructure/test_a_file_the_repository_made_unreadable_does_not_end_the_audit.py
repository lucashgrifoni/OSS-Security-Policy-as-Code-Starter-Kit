"""One file the audited repository can make unreadable must not end the whole audit.

Both the AWS and the Azure parser read the raw text OUTSIDE the `try` that guards the parse, so
an `OSError` on that line escaped the analysis and nothing above it caught it. Reproduced against
`aws-level-3` with an ACL denying read on a `buildspec.yml` that discovery had already accepted:

    Error: input could not be read: it could not be read (Permission denied)
    exit 2, and no report written at all

Twenty-eight controls lost to one file. On a profile carrying all 222 it would be all of them, and
the file belongs to the repository being audited, which in CI against a fork is written by whoever
opened the pull request.

What does NOT reach that line, and cost an hour to establish: a directory named `buildspec.yml`.
Discovery filters with `is_file()` twice, so the reachable trigger is a real file that then fails
to read -- a denied ACL, a device error, or a file removed between the check and the read. The
first attempt at a repro used a directory, saw exit 0, and nearly concluded the defect was not
real.

The fix does not trade a crash for a false clean, which was the thing worth checking before
keeping it. With the buildspec unreadable, `AWS-SECRET-038` and `AWS-PIPE-042` answer FAIL and six
others answer `manual-review-required`; the one PASS is `AWS-CI-037`, which reports that a
buildspec was *found*, and it was. Restrictive or honest on every control, which is the safe
direction.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.aws_ci_parser import analyze_aws_ci
from oss_policy_kit.infrastructure.azure_pipeline_parser import analyze_azure_pipelines

BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n"
PIPELINE = "trigger:\n  - main\nsteps:\n  - script: echo hi\n"

#: (parser, relative path of the file it reads, label for the failure message)
PARSERS = [
    (analyze_aws_ci, "buildspec.yml", BUILDSPEC),
    (analyze_azure_pipelines, "azure-pipelines.yml", PIPELINE),
]


def _deny_read(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    """Make exactly one file raise on read, leaving every other read alone.

    Patching `Path.read_text` rather than the filesystem keeps the test identical on every
    platform: the condition being asserted is "an OSError on this read does not end the run", and
    which OS produces that error is not the property under test. The real ACL case is covered by
    the end-to-end test below, which runs where chmod means something.
    """

    real = Path.read_text

    def refuse(self: Path, *args: object, **kwargs: object) -> str:
        if self == target:
            raise PermissionError(13, "Permission denied")
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", refuse)


@pytest.mark.parametrize(("analyze", "name", "body"), PARSERS)
def test_an_unreadable_file_is_recorded_rather_than_raised(
    analyze, name: str, body: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The parser must come back with an answer, not with an exception."""

    (tmp_path / name).write_text(body, encoding="utf-8")
    _deny_read(monkeypatch, tmp_path / name)

    result = analyze(tmp_path)

    assert [p.name for p, _ in result.parse_errors] == [name]


@pytest.mark.parametrize(("analyze", "name", "body"), PARSERS)
def test_the_recorded_reason_names_the_file_without_leaking_the_path(
    analyze, name: str, body: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Half of degrading usefully is saying which file, the other half is saying no more than that.

    `str(OSError)` carries the absolute filename, which is how an account name reaches a shareable
    report (M-002). `bad_input_detail` is the project's answer to that and is what this asserts.
    """

    (tmp_path / name).write_text(body, encoding="utf-8")
    _deny_read(monkeypatch, tmp_path / name)

    result = analyze(tmp_path)
    _, reason = result.parse_errors[0]

    assert "could not be read" in reason
    assert str(tmp_path) not in reason
    assert os.sep not in reason


@pytest.mark.parametrize(("analyze", "name", "body"), PARSERS)
def test_a_readable_file_is_unaffected(analyze, name: str, body: str, tmp_path: Path) -> None:
    """The baseline. Without it the tests above could pass on a parser that records everything."""

    (tmp_path / name).write_text(body, encoding="utf-8")

    result = analyze(tmp_path)

    assert result.parse_errors == []


@pytest.mark.skipif(sys.platform == "win32", reason="chmod does not deny read on Windows; ACLs do")
def test_the_evaluation_still_produces_a_report_when_a_real_file_cannot_be_read(tmp_path: Path) -> None:
    """End to end, with the operating system doing the denying rather than a patch.

    This is the shape the defect was found in: `evaluate` exiting 2 with no report on disk. The
    unit tests above prove the handler; this proves nothing above it re-raises.
    """

    import json
    import subprocess

    target = tmp_path / "repo"
    target.mkdir()
    (target / "SECURITY.md").write_text("Report to security@example.com\n", encoding="utf-8")
    spec = target / "buildspec.yml"
    spec.write_text(BUILDSPEC, encoding="utf-8")
    spec.chmod(0o000)
    if os.access(spec, os.R_OK):  # pragma: no cover - running as root, where chmod denies nothing
        pytest.skip("this user can read a 000 file, so the denial did not take")

    out = target / "_out"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(target),
            "--profile",
            "aws-level-3",
            "--output-dir",
            str(out),
            "--format",
            "json",
            "--summary-only",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )
    spec.chmod(0o644)

    assert proc.returncode == 0, f"exit {proc.returncode}: {proc.stderr[-400:]}"
    report = out / "evaluation-report.json"
    assert report.is_file(), "the run finished but wrote no report"
    assert json.loads(report.read_text(encoding="utf-8"))["controls"], "report carries no controls"
