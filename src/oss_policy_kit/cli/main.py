"""Typer entrypoint for oss-policy-kit.

This module wires the Typer ``app`` together by importing each command module so
its ``@app.command`` / ``@app.callback`` decorators register against the shared
``app`` instance defined in :mod:`oss_policy_kit.cli.common`. Public symbols
``app`` and ``prepare_cli_args`` are re-exported here for backward compatibility
with callers that import them from ``oss_policy_kit.cli.main``.
"""

from __future__ import annotations

import sys
from contextlib import suppress

# Importing each module triggers Typer command registration via decorators.
from oss_policy_kit.cli import (  # noqa: F401  (import side-effects: command registration)
    batch,
    evaluate,
    evidence,
    profiles,
    recommend,
    reports,
)
from oss_policy_kit.cli.common import app, prepare_cli_args

__all__ = ["app", "main", "prepare_cli_args"]


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            with suppress(Exception):
                stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) > 1:
        sys.argv[1:] = prepare_cli_args(list(sys.argv[1:]))
    app()


if __name__ == "__main__":
    main()
