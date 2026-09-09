"""The two lines between `python -m oss_policy_kit` and the Typer app.

Everything else in the kit is reachable from `CliRunner`, which calls the app object directly
and skips `main()` entirely. That makes this the one seam the whole test suite would otherwise
step over -- and it is not empty: it re-encodes the streams to UTF-8, rewrites argv so a bare
repository path dispatches to `evaluate`, and wraps stdout so a closed pipe unwinds quietly
instead of being caught by a per-command handler and reported as an internal error.

`runpy` is used rather than a subprocess on purpose: a subprocess runs in an interpreter the
coverage plugin is not watching, so the same assertions would pass while measuring nothing.
"""

from __future__ import annotations

import runpy
import sys
from typing import Any

import pytest

from oss_policy_kit.cli import main as cli_main


def _run_module(name: str, argv: list[str]) -> int:
    sys.argv = [name, *argv]
    try:
        runpy.run_module(name, run_name="__main__")
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def test_python_dash_m_reaches_the_app(capsys: pytest.CaptureFixture[str]) -> None:
    """`python -m oss_policy_kit --version` is the first thing an adopter runs."""

    code = _run_module("oss_policy_kit", ["--version"])

    assert code == 0
    assert capsys.readouterr().out.strip()


@pytest.mark.filterwarnings("ignore:.*found in sys.modules.*:RuntimeWarning")
def test_the_cli_module_is_runnable_in_its_own_right(capsys: pytest.CaptureFixture[str]) -> None:
    """`python -m oss_policy_kit.cli.main` has its own `__main__` guard; it has to work.

    The suppressed warning is runpy telling us the module was already imported, which is true
    of every module in this suite and is the price of measuring the guard at all.
    """

    code = _run_module("oss_policy_kit.cli.main", ["--version"])

    assert code == 0
    assert capsys.readouterr().out.strip()


def test_a_bare_repository_path_is_rewritten_into_an_evaluate_call(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Click would otherwise swallow the path as a group positional and never run evaluate."""

    seen: list[list[str]] = []
    monkeypatch.setattr(cli_main, "app", lambda **_: seen.append(sys.argv[1:]))
    monkeypatch.setattr(sys, "argv", ["oss-policy-kit", str(tmp_path), "--profile", "github-level-1"])

    cli_main.main()

    assert seen == [["evaluate", str(tmp_path), "--profile", "github-level-1"]]


def test_an_empty_command_line_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """The counterpart: with no arguments there is nothing to rewrite, and no path to guess."""

    seen: list[list[str]] = []
    monkeypatch.setattr(cli_main, "app", lambda **_: seen.append(sys.argv[1:]))
    monkeypatch.setattr(sys, "argv", ["oss-policy-kit"])

    cli_main.main()

    assert seen == [[]]


def test_a_reader_closing_the_pipe_is_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """`oss-policy-kit profiles | head` must exit 0, not "Unexpected error" at exit 3."""

    def _closed_pipe(**_: object) -> None:
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(cli_main, "app", _closed_pipe)
    monkeypatch.setattr(sys, "argv", ["oss-policy-kit", "profiles"])

    with pytest.raises(SystemExit) as excinfo:
        cli_main.main()

    assert excinfo.value.code == 0


def test_an_os_error_that_is_not_a_broken_pipe_is_still_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    """The counterpart: swallowing every OSError here would hide real failures as exit 0."""

    def _disk_full(**_: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli_main, "app", _disk_full)
    monkeypatch.setattr(sys, "argv", ["oss-policy-kit", "profiles"])

    with pytest.raises(OSError, match="No space left"):
        cli_main.main()


def test_silencing_stdout_copes_with_an_interpreter_that_has_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """`sys.__stdout__` is None under pythonw and some embedded hosts; that is not a crash."""

    monkeypatch.setattr(sys, "__stdout__", None)
    cli_main._silence_stdout_after_broken_pipe()
