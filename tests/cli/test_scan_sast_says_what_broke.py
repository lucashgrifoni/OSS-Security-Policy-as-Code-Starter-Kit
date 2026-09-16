"""What ``scan-sast`` tells the operator when Semgrep failed before reading anything.

The command used to answer every scanner failure the same way: go and read the evidence file.
For the Windows failure that file contains ``<ERROR: missing output>``, so the operator followed
the pointer and arrived at a dead end. They had no way to learn that no file had been scanned,
and no way to learn where the scan would work.

The classification these tests depend on is held in
``tests/infrastructure/test_the_engine_that_never_started.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import scan_sast as ss
from oss_policy_kit.cli.main import app
from oss_policy_kit.infrastructure.scanners.semgrep_adapter import SemgrepRunOutcome

runner = CliRunner()


def _flat(text: str) -> str:
    """Rich wraps at the terminal width, so a phrase can be split across lines mid-sentence."""

    return re.sub(r"\s+", " ", text)


def _engine_failure(*_a: object, **_k: object) -> SemgrepRunOutcome:
    return SemgrepRunOutcome(
        status="error",
        version="1.177.0",
        rulesets=["p/security-audit"],
        raw_stdout="<ERROR: missing output>\n",
        exit_code=2,
    )


def test_it_says_nothing_was_scanned_rather_than_pointing_at_an_empty_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ss, "run_semgrep", _engine_failure)

    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path)])
    flat = _flat(res.output)

    assert res.exit_code == 2, res.output
    assert "no file was scanned" in flat, res.output
    assert "semgrep-core" in flat, res.output


def test_on_windows_it_names_somewhere_the_scan_would_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A dead end with no way out is the defect; naming a place that works is the fix."""

    monkeypatch.setattr(ss, "run_semgrep", _engine_failure)
    monkeypatch.setattr(ss.sys, "platform", "win32")

    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path)])
    flat = _flat(res.output)

    assert "WSL" in flat, res.output
    assert "Linux" in flat, res.output


def test_it_does_not_send_a_windows_user_to_this_project_s_own_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first draft of this message did, and the image has no scanner in it.

    ``Dockerfile`` installs ``.github/requirements/runtime-all.txt``, the kit's own runtime
    dependencies. ``.github/requirements/semgrep.txt`` is installed by the ``sast-semgrep`` job
    in ``security-ci-cd.yml``, on an Ubuntu runner, and never enters the image. Running
    ``scan-sast`` in the container would report ``not_available``, which is a second dead end
    rather than a way out of the first.
    """

    monkeypatch.setattr(ss, "run_semgrep", _engine_failure)
    monkeypatch.setattr(ss.sys, "platform", "win32")

    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path)])

    assert "ghcr.io" not in _flat(res.output), res.output


def test_off_windows_it_does_not_hand_out_windows_advice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The same engine failure on Linux has a different fix, so the guidance is not universal."""

    monkeypatch.setattr(ss, "run_semgrep", _engine_failure)
    monkeypatch.setattr(ss.sys, "platform", "linux")

    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path)])
    flat = _flat(res.output)

    assert "WSL" not in flat, res.output
    assert "no file was scanned" in flat, res.output


def test_an_ordinary_scanner_error_still_points_at_the_evidence_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The message this adds is narrow; a bad ruleset keeps the answer it already had."""

    def _bad_ruleset(*_a: object, **_k: object) -> SemgrepRunOutcome:
        return SemgrepRunOutcome(
            status="error",
            version="1.177.0",
            rulesets=["p/nope"],
            raw_stderr="Invalid rule schema: unknown key 'patern'",
            exit_code=2,
        )

    monkeypatch.setattr(ss, "run_semgrep", _bad_ruleset)

    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path)])
    flat = _flat(res.output)

    assert res.exit_code == 2
    assert "see diagnostics" in flat, res.output
    assert "no file was scanned" not in flat, res.output
