"""Typer entrypoint for oss-policy-kit.

This module wires the Typer ``app`` together by importing each command module so
its ``@app.command`` / ``@app.callback`` decorators register against the shared
``app`` instance defined in :mod:`oss_policy_kit.cli.common`. Public symbols
``app`` and ``prepare_cli_args`` are re-exported here for backward compatibility
with callers that import them from ``oss_policy_kit.cli.main``.
"""

from __future__ import annotations

import errno
import os
import sys
from contextlib import suppress
from typing import Any

# Importing each module triggers Typer command registration via decorators.
from oss_policy_kit.cli import (  # noqa: F401  (import side-effects: command registration)
    batch,
    correlate_findings,
    diff_catalogs,
    emit_insights,
    emit_vex,
    evaluate,
    evidence,
    export_evidence,
    export_policy,
    ingest_insights,
    ingest_scorecard,
    init,
    osps_coverage,
    profiles,
    recommend,
    reports,
    scan_bicep,
    scan_cfn,
    scan_iac,
    scan_k8s,
    scan_pulumi,
    scan_sast,
)
from oss_policy_kit.cli.common import app, prepare_cli_args

__all__ = ["app", "main", "prepare_cli_args"]

# Deterministic command order for ``--help`` (drives the Rich help-panel order and the
# within-panel order). Decorator registration order is import-order dependent (and
# ``evaluate`` transitively imports ``profiles``), so we sort explicitly instead. Names
# not listed keep their registration order after the listed ones.
_COMMAND_DISPLAY_ORDER: tuple[str, ...] = (
    "evaluate",
    "evaluate-many",
    "diff-reports",
    "profiles",
    "recommend-profile",
    "init",
    "osps-coverage",
    "diff-catalogs",
    "scan-iac",
    "scan-k8s",
    "scan-cfn",
    "scan-pulumi",
    "scan-bicep",
    "scan-sast",
    "scaffold-evidence",
    "collect-evidence",
    "emit-vex",
    "emit-insights",
    "ingest-insights",
    "ingest-scorecard",
    "correlate-findings",
    "export-evidence",
    "export-policy",
)


def _order_registered_commands() -> None:
    rank = {name: i for i, name in enumerate(_COMMAND_DISPLAY_ORDER)}
    fallback = len(rank)
    app.registered_commands.sort(key=lambda info: rank.get(info.name or "", fallback))


_order_registered_commands()


#: errno values that signal the reader closed a pipe we were writing to
#: (``head``/``less`` quitting early). POSIX raises ``EPIPE``; Windows raises
#: ``EINVAL`` for the same "write to a broken pipe" condition.
_BROKEN_PIPE_ERRNOS: frozenset[int] = frozenset({errno.EPIPE, errno.EINVAL})


def _is_broken_pipe(exc: OSError) -> bool:
    """True when ``exc`` is a broken-pipe write error (``head``/``less`` closed the reader)."""

    if isinstance(exc, BrokenPipeError):
        return True
    return exc.errno in _BROKEN_PIPE_ERRNOS


# Control-flow signal, not a user-facing error.
class _BrokenPipeExit(BaseException):  # noqa: N818
    """Raised the first time a stdout write hits a broken pipe, to unwind to ``main()``.

    A plain ``BrokenPipeError``/``OSError`` would be swallowed by the per-command
    ``except Exception`` last-resort handlers (which then print "Unexpected error"
    and exit 3). This subclasses ``BaseException`` (like ``SystemExit`` /
    ``KeyboardInterrupt``) so those ``except Exception`` handlers let it propagate —
    letting ``main()`` convert it into a single clean, quiet exit (X6-04).
    """


class _BrokenPipeGuardedStdout:
    """A stdout proxy that turns a broken-pipe write into a single ``_BrokenPipeExit``.

    Wraps the real ``sys.stdout``. Every attribute except ``write``/``flush`` is
    delegated. On the first broken-pipe write it disables the underlying stream (so
    later writes and the shutdown flush are silently dropped) and raises
    ``_BrokenPipeExit`` once so the pipeline unwinds cleanly to ``main()``.
    """

    def __init__(self, wrapped: Any) -> None:
        self._wrapped = wrapped
        self._broken = False

    def write(self, data: Any) -> int:
        if self._broken:
            return 0
        try:
            return int(self._wrapped.write(data))
        except OSError as exc:
            if not _is_broken_pipe(exc):
                raise
            self._broken = True
            raise _BrokenPipeExit from exc

    def flush(self) -> None:
        if self._broken:
            return
        try:
            self._wrapped.flush()
        except OSError as exc:
            if not _is_broken_pipe(exc):
                raise
            self._broken = True

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


def _silence_stdout_after_broken_pipe() -> None:
    """Redirect ``sys.stdout`` to ``os.devnull`` so interpreter shutdown cannot re-raise."""

    original = sys.__stdout__
    if original is None:
        return
    with suppress(Exception):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, original.fileno())


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            with suppress(Exception):
                stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) > 1:
        sys.argv[1:] = prepare_cli_args(list(sys.argv[1:]))
    # Guard stdout so a downstream reader closing the pipe (``| head``, ``| less``)
    # unwinds via ``_BrokenPipeExit`` instead of being caught by a per-command
    # ``except Exception`` handler that would print "Unexpected error" + exit 3.
    # Only when there IS a stdout. A caller that closes the descriptor outright -- `>&-` --
    # leaves `sys.stdout` as None, and wrapping None made every delegated call raise
    # AttributeError, including the flush at interpreter shutdown. Measured: the kit exited
    # 120, outside the documented 0/1/2/3 contract, after printing a traceback that carried
    # the absolute path of the installation, account name included. Plain CPython in the
    # same situation exits 0 with an empty stderr, so this was ours, not the interpreter's.
    if sys.stdout is not None:
        sys.stdout = _BrokenPipeGuardedStdout(sys.stdout)
    try:
        # `windows_expand_args=False`: on Windows, Click expands globs in argv itself to
        # emulate a POSIX shell, and it does so against the CURRENT WORKING DIRECTORY --
        # not the target. That silently rewrote every pattern-valued option. Measured with
        # identical argv both times (`['--exclude', 'doc*']`), only the cwd differing:
        # from an empty directory `evaluate-many --exclude 'doc*'` audited 1 of 2 repos as
        # asked, and from a directory that merely happened to contain `docsomething` it
        # audited both and exited 0 with no warning. A batch gate that reports green while
        # it evaluated a set the operator excluded is worse than one that fails.
        app(windows_expand_args=False)
    except _BrokenPipeExit:
        _exit_quietly_on_broken_pipe()
    except OSError as exc:
        if not _is_broken_pipe(exc):
            raise
        _exit_quietly_on_broken_pipe()


def _exit_quietly_on_broken_pipe() -> None:
    """Silence stdout and exit 0 without the generic error banner or shutdown noise (X6-04)."""

    _silence_stdout_after_broken_pipe()
    sys.exit(0)


if __name__ == "__main__":
    main()
