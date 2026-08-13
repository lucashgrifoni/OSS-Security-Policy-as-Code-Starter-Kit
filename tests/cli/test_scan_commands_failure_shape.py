"""What the five scanners say when the scan does not go cleanly.

`scan-cfn`, `scan-bicep`, `scan-pulumi`, `scan-iac` and `scan-sast` share one tail: an `OSError` while
writing evidence is the adopter's to fix and exits 2; anything else is the kit's fault and exits
3 with a message rather than a traceback; and a deliberate exit raised deeper survives both.
Five copies of that tail means five chances for one of them to drift, so all five are asserted.

The parse-error warning is the other half. A scanner that skips files it could not read and says
nothing produces a report an adopter reads as "these templates are clean" -- so when files fail
to parse the count goes to stderr and points at the diagnostics that name them. `scan-sast`
carries the same duty for the two ways Semgrep can fail to produce findings without failing:
absent, and timed out.
"""

from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from oss_policy_kit.cli import scan_bicep, scan_cfn, scan_iac, scan_pulumi, scan_sast
from oss_policy_kit.cli.main import app
from oss_policy_kit.infrastructure.scanners.semgrep_adapter import SemgrepRunOutcome

runner = CliRunner()

_COMMANDS = [
    ("scan-cfn", scan_cfn, "run_scan"),
    ("scan-bicep", scan_bicep, "run_scan"),
    ("scan-pulumi", scan_pulumi, "run_scan"),
    ("scan-iac", scan_iac, "run_scan"),
    ("scan-sast", scan_sast, "run_semgrep"),
]
_IDS = [name for name, _mod, _attr in _COMMANDS]


@pytest.mark.parametrize(("command", "module", "attr"), _COMMANDS, ids=_IDS)
def test_a_filesystem_error_is_the_adopters_to_fix(
    command: str, module: object, attr: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit 2, because an unwritable evidence directory is not the kit misbehaving.

    Raised with its ``errno``, the way a real full disk raises it. The handler reports
    ``exc.strerror`` rather than the exception -- ``str(OSError)`` appends the resolved
    filename, which is how a relative ``--target`` was answered with the host path
    (see ``test_scan_error_sanitisation``) -- so a message-only fake would assert
    against a shape the filesystem never hands these commands.
    """

    def _refuse(*_a: object, **_k: object) -> object:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(module, attr, _refuse)
    result = runner.invoke(app, [command, "--target", str(tmp_path)])

    assert result.exit_code == 2, result.output
    assert "No space left on device" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(("command", "module", "attr"), _COMMANDS, ids=_IDS)
def test_an_unexpected_failure_never_reaches_the_terminal_as_a_traceback(
    command: str, module: object, attr: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit 3 is the kit admitting fault, and it still owes a readable line."""

    def _boom(*_a: object, **_k: object) -> object:
        raise ZeroDivisionError("scanner went sideways")

    monkeypatch.setattr(module, attr, _boom)
    result = runner.invoke(app, [command, "--target", str(tmp_path)])

    assert result.exit_code == 3, result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(("command", "module", "attr"), _COMMANDS, ids=_IDS)
def test_a_deliberate_exit_is_not_relabelled_by_the_broad_handler(
    command: str, module: object, attr: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _exit(*_a: object, **_k: object) -> object:
        raise typer.Exit(code=6)

    monkeypatch.setattr(module, attr, _exit)
    result = runner.invoke(app, [command, "--target", str(tmp_path)])

    assert result.exit_code == 6


# --------------------------------------------------------------------------- #
# Files the scanner could not read
# --------------------------------------------------------------------------- #


def test_cloudformation_templates_that_fail_to_parse_are_counted_out_loud(tmp_path: Path) -> None:
    """Skipping them silently would let the report read as "these templates are clean"."""

    (tmp_path / "broken.yaml").write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: [\n", encoding="utf-8")
    result = runner.invoke(app, ["scan-cfn", "--target", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "failed to parse" in result.output
    assert "diagnostics.parse_errors" in result.output


def test_bicep_templates_the_scanner_cannot_open_are_counted_out_loud(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bicep is read line by line, so the only way in is a file that will not open at all.

    Malformed syntax is not a parse error here -- the scanner extracts what it recognises and
    ignores the rest -- which makes a permission error the case that actually costs coverage of
    a template, and therefore the case that has to be said out loud.
    """

    (tmp_path / "locked.bicep").write_text(
        "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {}\n", encoding="utf-8"
    )
    original = Path.read_text

    def _refuse(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "locked.bicep":
            raise PermissionError("Access is denied")
        return original(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", _refuse)
    result = runner.invoke(app, ["scan-bicep", "--target", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "failed to parse" in result.output


def test_a_clean_scan_says_nothing_about_parse_errors(tmp_path: Path) -> None:
    """The counterpart: a warning printed unconditionally would train adopters to ignore it."""

    (tmp_path / "template.yaml").write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan-cfn", "--target", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "failed to parse" not in result.output


# --------------------------------------------------------------------------- #
# Semgrep ran, or did not
# --------------------------------------------------------------------------- #


def _semgrep_outcome(status: str) -> SemgrepRunOutcome:
    return SemgrepRunOutcome(status=status, version=None, rulesets=["p/ci"], findings=[])


@pytest.mark.parametrize(
    ("status", "fragment"),
    [("not_available", "Semgrep is not installed"), ("timeout", "timed out")],
)
def test_a_scan_that_produced_no_findings_for_the_wrong_reason_says_so(
    status: str, fragment: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zero findings and zero explanation is the shape that reads as a clean codebase."""

    monkeypatch.setattr(scan_sast, "run_semgrep", lambda *_a, **_k: _semgrep_outcome(status))
    result = runner.invoke(app, ["scan-sast", "--target", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert fragment in result.output


def test_a_completed_scan_adds_no_caveat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan_sast, "run_semgrep", lambda *_a, **_k: _semgrep_outcome("ok"))
    result = runner.invoke(app, ["scan-sast", "--target", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "not installed" not in result.output
    assert "timed out" not in result.output


def test_the_json_format_carries_the_same_status_the_human_line_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two renderings of one scan must not disagree about whether Semgrep ran."""

    monkeypatch.setattr(scan_sast, "run_semgrep", lambda *_a, **_k: _semgrep_outcome("timeout"))
    result = runner.invoke(app, ["scan-sast", "--target", str(tmp_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["status"] == "timeout"
