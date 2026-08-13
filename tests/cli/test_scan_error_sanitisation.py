"""A failed evidence write names the reason, never the host path -- in all six scanners.

The v10.0.7 m002-echo lane caught two error handlers interpolating the ``OSError``
itself, and ``str(OSError)`` renders ``exc.filename``. The six ``scan-*`` commands
carried the same handler and were missed: with ``.oss-policy-kit`` unwritable,
``scan-iac --target ./t`` answered a relative argument with
``Error: [WinError 5] Acesso negado: 'C:\\Users\\<name>\\...\\t\\.oss-policy-kit\\evidence'``
-- the operator's home directory and OS account name, in the line they paste into an
issue, describing a location they never typed.

All six are asserted, not one. Six copies of that handler was six chances to drift, and
a fix that lands in five is the defect coming back.

Two Windows traps shape the assertions here, both inherited from
``test_v10_0_7_relative_paths_stay_relative``:

- an "the absolute path is absent" assertion passes for the wrong reason when 8.3 short
  paths (``LUCASG~1``) rewrite the segments being searched for. Every leak assertion
  below looks for a distinctive, separator-free DIRECTORY NAME the fixture creates,
  which no short-path expansion can rewrite, and the target is always RELATIVE so the
  only way that name reaches the terminal is the kit resolving it.
- a long ``tmp_path`` makes Rich soft-wrap the message mid-phrase, so a substring
  assertion fails on Windows and passes in CI. ``COLUMNS`` is pinned wide and every
  phrase is matched against whitespace-collapsed output.

Every guard here was mutation-tested: the handler was reverted to ``markup_safe(exc)``,
the test was confirmed to fail, and the fix was restored.
"""

from __future__ import annotations

import errno
from pathlib import Path
from types import ModuleType

import pytest
from click.testing import Result
from typer.testing import CliRunner

from oss_policy_kit.cli import scan_bicep, scan_cfn, scan_iac, scan_k8s, scan_pulumi, scan_sast
from oss_policy_kit.cli.main import app

runner = CliRunner()

#: Wide enough that no phrase asserted below straddles a Rich soft-wrap.
_WIDE = "240"

#: A separator-free directory name. If any resolved path reaches the operator, this
#: token appears verbatim; a short-path expansion cannot rewrite it away.
_MARKER = "scanleakmarkerdirectory"

#: The relative target every command is pointed at, mirroring the reproduction.
_TARGET = "./t"

_COMMANDS: list[tuple[str, ModuleType]] = [
    ("scan-iac", scan_iac),
    ("scan-k8s", scan_k8s),
    ("scan-cfn", scan_cfn),
    ("scan-pulumi", scan_pulumi),
    ("scan-bicep", scan_bicep),
    ("scan-sast", scan_sast),
]
_IDS = [name for name, _module in _COMMANDS]


def _flat(text: str) -> str:
    """Collapse soft-wrap whitespace so a phrase can be matched as one unit."""

    return " ".join(text.split())


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A current directory whose name is the leak marker, holding a relative target ``t``."""

    monkeypatch.setenv("COLUMNS", _WIDE)
    root = tmp_path / _MARKER
    (root / "t").mkdir(parents=True)
    monkeypatch.chdir(root)
    return root


@pytest.fixture
def blocked_evidence_dir(workdir: Path) -> Path:
    """Make the real evidence write fail: ``.oss-policy-kit`` is a file, so ``mkdir`` cannot pass it.

    Preferred over ``icacls``/``chmod`` because it fails identically on both platforms and
    leaves nothing behind that a failed test could not clean up. The ``OSError`` it raises
    carries the same two things the denied-permission case carries -- a ``strerror`` and an
    absolute ``filename`` -- which is all this defect ever depended on.
    """

    (workdir / "t" / ".oss-policy-kit").write_text("not a directory\n", encoding="utf-8")
    return workdir


def _run(command: str) -> Result:
    return runner.invoke(app, [command, "--target", _TARGET])


@pytest.mark.parametrize(("command", "module"), _COMMANDS, ids=_IDS)
def test_a_relative_target_is_never_answered_with_the_host_path(
    command: str, module: ModuleType, blocked_evidence_dir: Path
) -> None:
    """The whole defect, against the real filesystem: relative in, relative out.

    ``module`` is unused here on purpose -- this arm patches nothing, so it proves the
    command reaches the sanitised handler through its own real write, not through a
    fake -- but it keeps one table driving every case in this file.
    """

    result = _run(command)

    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output
    # The leak is asserted before the phrasing: it is the defect, and an assertion that
    # never runs because a later-added one failed first has not been mutation-tested.
    assert _MARKER not in result.output, "the resolved evidence path leaked through the OSError"
    assert "cannot write output (" in _flat(result.output)


@pytest.mark.parametrize(("command", "module"), _COMMANDS, ids=_IDS)
def test_the_os_reason_survives_the_path_being_dropped(
    command: str, module: ModuleType, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dropping the path must not cost the reason -- that is what makes the error actionable.

    Raised with an explicit ``strerror`` and ``filename`` because the real OS reason is
    localised (``Acesso negado`` on this machine, ``Permission denied`` in CI): asserting
    the reason survived needs a string that does not move.
    """

    leaked = workdir / "t" / ".oss-policy-kit" / "evidence"

    def _denied(*_args: object, **_kwargs: object) -> Path:
        raise PermissionError(errno.EACCES, "Permission denied", str(leaked))

    monkeypatch.setattr(module, "write_evidence", _denied)
    result = _run(command)

    assert result.exit_code == 2, result.output
    assert "cannot write output (Permission denied)." in _flat(result.output)
    assert _MARKER not in result.output, "the OSError filename leaked the host path"


def test_an_oserror_carrying_no_reason_still_reads_as_a_write_failure(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A message-only ``OSError`` has no ``strerror``; the line must not degrade to ``Error: ``.

    One command is enough: all six route to the same helper, and the parametrised cases
    above are what prove that routing.
    """

    def _bare(*_args: object, **_kwargs: object) -> Path:
        raise OSError("something the platform did not classify")

    monkeypatch.setattr(scan_iac, "write_evidence", _bare)
    result = _run("scan-iac")

    assert result.exit_code == 2, result.output
    assert "cannot write output (filesystem error)." in _flat(result.output)


def test_a_bracketed_reason_reaches_the_operator_exactly_as_the_shell_shows_it(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rich reads ``[evidence]`` as a style tag and drops it; escaped twice it grows a backslash.

    The same one-escape rule ``scaffold-evidence`` had to be corrected for, asserted here
    so the shared helper cannot regress into either failure mode.
    """

    def _bracketed(*_args: object, **_kwargs: object) -> Path:
        raise OSError(errno.EEXIST, "cannot create [evidence] directory")

    monkeypatch.setattr(scan_iac, "write_evidence", _bracketed)
    result = _run("scan-iac")

    assert result.exit_code == 2, result.output
    flat = _flat(result.output)
    assert "cannot create [evidence] directory" in flat
    assert "\\[evidence]" not in flat, "the detail was escaped twice"


def test_a_clean_scan_of_the_same_relative_target_says_nothing_about_a_write_failure(
    workdir: Path,
) -> None:
    """The counterpart: the sanitised line must belong to the failure, not to every run."""

    result = _run("scan-iac")

    assert result.exit_code == 0, result.output
    assert "cannot write output" not in result.output
    assert (workdir / "t" / ".oss-policy-kit" / "evidence" / "iac-terraform.json").is_file()
