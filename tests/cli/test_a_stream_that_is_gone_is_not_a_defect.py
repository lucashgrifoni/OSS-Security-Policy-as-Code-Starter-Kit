"""Exit 3 is documented as "always a bug in the kit". Two of these were the environment.

Both measured against the built wheel in a clean room.

ONE. `evaluate` with stdout closed (`>&-`):

    stderr: Reports written to: out
    stderr: Unexpected error: 'NoneType' object has no attribute 'write'
    exit 3

Both reports are on disk and complete. The run succeeded and then reported itself as a defect
in the kit. On Windows a closed stdout arrives as `sys.stdout is None`, and four
`sys.stdout.write` calls raise on it. `profiles` and `--version` already survived this, which
is what marked it as an unguarded write rather than a missing capability.

The summary on stdout is a convenience. The reports on disk are the product, and they were
already written, so the exit code must stay whatever the evaluation decided.

TWO. `init --interactive` where stdin has nothing to read:

    Use this profile (press Enter to accept, or type a different profile id) [github-level-1]: Unexpected error:
    exit 3

The message is literally empty, because `typer.prompt` aborts and `str(Abort())` is `""`.
`--dry-run` took the same path, so previewing it safely was closed too.

Two attempts at that one failed before this, and both failures are worth keeping:

* The first added `is_interactive_stream(sys.stdin)` before the prompt. The branch already
  gates on `sys.stdin.isatty()`, and under git-bash on Windows that stays True through
  `< /dev/null` -- so a second copy of the same wrong answer changed nothing.
* The second caught `click.exceptions.Abort`. Typer vendors its own click, so the class it
  raises is `typer._click.exceptions.Abort` and the one imported from the `click` package
  never matches. The run still exited 3 with the same empty message.

Catching `typer.Abort` works because asking for the input is the only way to learn whether
any is there.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_SECURITY = "Report to security@example.com\n"


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "SECURITY.md").write_text(_SECURITY, encoding="utf-8")
    return tmp_path


def _run(args: list[str], *, stdin: int | None = subprocess.DEVNULL, close_stdout: bool = False):
    """Run the CLI as a real process, because a closed stream cannot be simulated in-process."""

    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1", "COLUMNS": "120"}
    stdout = subprocess.DEVNULL if close_stdout else subprocess.PIPE
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "oss_policy_kit", *args],
        stdin=stdin,
        stdout=stdout,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )


# --- one: a missing stdout must not undo a successful run ---------------------------------------


def test_write_to_stdout_reports_failure_instead_of_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    """The unit the whole fix rests on: `sys.stdout is None` is the Windows shape of `>&-`."""

    from oss_policy_kit.cli.terminal_ui import write_to_stdout

    monkeypatch.setattr(sys, "stdout", None)

    assert write_to_stdout("anything\n") is False


def test_write_to_stdout_reports_failure_on_a_closed_stream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The POSIX shape: a real file object that has been closed underneath us."""

    from oss_policy_kit.cli.terminal_ui import write_to_stdout

    handle = (tmp_path / "out.txt").open("w", encoding="utf-8")
    handle.close()
    monkeypatch.setattr(sys, "stdout", handle)

    assert write_to_stdout("anything\n") is False


def test_write_to_stdout_still_writes_when_stdout_works(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The other direction: the summary must still be printed on an ordinary run."""

    from oss_policy_kit.cli.terminal_ui import write_to_stdout

    target = tmp_path / "out.txt"
    with target.open("w", encoding="utf-8") as handle:
        monkeypatch.setattr(sys, "stdout", handle)
        assert write_to_stdout("the summary\n") is True

    assert target.read_text(encoding="utf-8") == "the summary\n"


def test_evaluate_still_succeeds_with_stdout_discarded(tmp_path: Path) -> None:
    """End to end. The reports are the product; stdout is a convenience."""

    repo = _repo(tmp_path)
    out = tmp_path / "out"

    proc = _run(
        [
            "evaluate",
            "--target",
            str(repo),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(out),
            "--format",
            "json",
        ],
        close_stdout=True,
    )

    assert proc.returncode == 0, proc.stderr
    assert "Unexpected error" not in proc.stderr
    assert (out / "evaluation-report.json").is_file(), "the run must still have produced its reports"


def test_evaluate_still_prints_its_summary_when_stdout_works(tmp_path: Path) -> None:
    """The regression the guard could have caused: silence on an ordinary run."""

    repo = _repo(tmp_path)
    out = tmp_path / "out"

    proc = _run(
        ["evaluate", "--target", str(repo), "--profile", "github-level-1", "--output-dir", str(out), "--format", "json"]
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["profile_id"] == "github-level-1"


# --- two: asking for input that is not there ----------------------------------------------------


@pytest.mark.parametrize("extra", [[], ["--dry-run"]])
def test_init_interactive_without_input_never_exits_three(extra: list[str], tmp_path: Path) -> None:
    """Whatever the platform answers here, it may not be exit 3 with an empty message.

    The exit code legitimately differs by operating system, and asserting one of them is how
    this test first failed on CI. With stdin on the null device, Linux reports `isatty()`
    False, so the interactive branch is skipped entirely and `init` proceeds with the
    recommended profile: exit 0. Under git-bash on Windows `isatty()` stays True, the branch
    runs, the prompt has nothing to read, and the new handler answers exit 2.

    Both are correct. The defect was exit 3 with "Unexpected error: " and nothing after it,
    and that is what this pins on every platform. The exit-2 path itself is pinned
    deterministically by the in-process test below, which forces the stdin that lies.
    """

    proc = _run(["init", "--target", str(tmp_path), "--interactive", *extra])

    assert proc.returncode in (0, 2), proc.stderr
    assert "Unexpected error" not in proc.stderr
    if proc.returncode == 2:
        assert "--interactive" in proc.stderr, "the message must name the flag to drop"
        assert "github-level-1" in proc.stderr, "and the profile it would have used"


def test_init_without_interactive_is_unaffected(tmp_path: Path) -> None:
    """The ordinary path, which is what the error message tells the adopter to use."""

    proc = _run(["init", "--target", str(tmp_path)])

    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "oss-policy-kit.yaml").is_file()


def test_the_abort_class_caught_is_the_one_typer_raises() -> None:
    """The second failed attempt, pinned so it cannot come back.

    `click.exceptions.Abort` and `typer.Abort` are different classes, because typer vendors
    its own click. Catching the wrong one is invisible: the code reads correctly and the
    handler never fires.
    """

    import click.exceptions
    import typer

    assert typer.Abort is not click.exceptions.Abort
    assert typer.Abort.__module__.startswith("typer"), "typer.Abort must stay the vendored one"


# --- the same refusal, in process, because subprocess coverage is invisible ----------------------
#
# The end-to-end test above runs a real process, which is the only way to close a stream, and
# coverage does not follow a subprocess -- measured on this repository, wiring that in bought
# 0.31 points for twice the CI time. So the handler needs an in-process exercise too, or it is
# an uncovered branch that happens to work.


def test_init_interactive_refuses_in_process_when_the_prompt_aborts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drive the branch directly: stdin claims to be a terminal and then has nothing to give.

    That combination is not contrived. It is what git-bash on Windows does with `< /dev/null`,
    and it is why checking `isatty()` a second time did not fix this.
    """

    import io

    import typer

    from oss_policy_kit.cli import init as init_module

    class _LyingStdin(io.StringIO):
        """Reports a terminal and has nothing to read, which is the whole bug in one object."""

        def isatty(self) -> bool:
            return True

    def _nothing_to_read(*_args: object, **_kwargs: object) -> str:
        raise typer.Abort

    # Called directly rather than through `CliRunner`, which replaces `sys.stdin` inside its
    # own isolation and would undo the lie this test is built on. Every parameter is passed
    # explicitly, because calling a Typer command as a plain function leaves its defaults as
    # `OptionInfo` objects rather than values -- the first version passed two arguments and
    # got exit 3 from the resulting mess, which would have read as the bug still being there.
    monkeypatch.setattr(sys, "stdin", _LyingStdin())
    monkeypatch.setattr(typer, "prompt", _nothing_to_read)

    with pytest.raises(typer.Exit) as raised:
        init_module.init_cmd(
            target=str(tmp_path),
            profile=None,
            platform=None,
            fail_on="fail",
            output_dir="./oss-policy-reports",
            with_waivers=False,
            with_evidence=False,
            with_workflow=False,
            force=False,
            dry_run=False,
            yes=False,
            interactive=True,
            output_format="human",
        )

    assert raised.value.exit_code == 2
