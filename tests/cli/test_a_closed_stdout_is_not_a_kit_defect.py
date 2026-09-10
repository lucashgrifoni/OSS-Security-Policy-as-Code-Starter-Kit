"""Closing stdout outright must not produce a traceback, a stray exit code, or a leaked path.

`main()` wrapped `sys.stdout` in the broken-pipe guard unconditionally. A caller that closes
the descriptor -- `oss-policy-kit --version >&-` -- leaves `sys.stdout` as None, and the
wrapper delegates every call to it, so each one raised `AttributeError`, including the flush
Python performs at interpreter shutdown.

Measured before the fix:

    python -c "print('x')" >&-        exit 0,   stderr empty
    oss-policy-kit --version >&-      exit 120, 3109 bytes of traceback

Three separate problems in one shape. 120 is outside the documented 0/1/2/3 contract. The
traceback is raw Python reaching an operator. And it printed the absolute path of the
installation, account name included, which is the M-002 class this project redacts everywhere
else.

The CPython baseline is what settles the argument that this is the interpreter's behaviour:
plain Python exits 0 and says nothing. The wrapper was ours.

The broken-pipe case the guard exists for -- `| head`, `| less` -- is a DIFFERENT situation:
there stdout is a real object whose writes fail, and that path is unchanged.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

import pytest

from oss_policy_kit.cli import main as cli_main


def test_a_none_stdout_is_not_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    """The decision itself, asserted on every platform.

    Wrapping is what made a closed descriptor fatal, so the property is that nothing is
    wrapped when there is nothing to wrap -- not merely that this particular command survives.
    """

    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "argv", ["oss-policy-kit", "--version"])

    with pytest.raises(SystemExit) as exit_info:
        cli_main.main()

    assert exit_info.value.code in (0, None), (
        f"exit {exit_info.value.code!r} with stdout closed. The documented contract is 0/1/2/3, "
        "and printing nowhere is not a failure of the audit."
    )
    assert sys.stdout is None, (
        f"stdout was replaced with {type(sys.stdout).__name__} even though there was nothing to "
        "wrap. Every delegated call on that wrapper raises AttributeError, including the flush "
        "at interpreter shutdown."
    )


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell to close a descriptor with >&-")
def test_the_whole_process_stays_quiet_with_the_descriptor_closed() -> None:
    """End to end, because the failing flush happened at interpreter shutdown.

    An in-process check cannot see that: the traceback was printed by Python itself while
    tearing the interpreter down, after the command had already returned.
    """

    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell interpolation of user input
        ["sh", "-c", f'"{sys.executable}" -m oss_policy_kit --version >&-'],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        timeout=120,
        check=False,
    )

    assert completed.returncode == 0, f"exit {completed.returncode} with stdout closed; stderr was:\n{completed.stderr}"
    assert completed.stderr == "", f"the run wrote to stderr with stdout closed:\n{completed.stderr}"
    assert "Traceback" not in completed.stderr
