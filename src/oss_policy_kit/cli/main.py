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
    emit_insights,
    emit_vex,
    evaluate,
    evidence,
    export_evidence,
    init,
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
    "export-evidence",
)


def _order_registered_commands() -> None:
    rank = {name: i for i, name in enumerate(_COMMAND_DISPLAY_ORDER)}
    fallback = len(rank)
    app.registered_commands.sort(key=lambda info: rank.get(info.name or "", fallback))


_order_registered_commands()


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
