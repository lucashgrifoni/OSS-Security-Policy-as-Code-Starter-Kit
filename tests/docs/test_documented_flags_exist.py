"""Every flag `docs/cli-reference.md` documents must exist on the command it documents.

`scan-k8s` was documented with `--helm-pre-pass` / `--no-helm-pre-pass`. The real flags are
`--helm-render` / `--no-helm-render`; the option had been renamed and the reference table had
not. An adopter copying that line gets a usage error from the tool that is supposed to be
teaching them.

Derived from the table itself rather than a list of commands: a row added for a new command is
checked from the moment it is written, and a flag renamed in code fails here rather than in
somebody's pipeline.

`--help` is read from a subprocess, not by importing the Typer app. The rendered help is what
an adopter actually sees, and it is the only place where Rich wrapping, hidden options and
callback-level flags all resolve the way they will for them.
"""

from __future__ import annotations

import functools
import os
import re
import subprocess
import sys

import pytest

from tests.conftest import ROOT

_REFERENCE = ROOT / "docs" / "cli-reference.md"

#: A table row: `| `command` | required | optional | description |`
_ROW = re.compile(r"^\|\s*`(?P<command>[a-z][a-z0-9-]*)`\s*\|(?P<rest>.*)\|\s*$")

#: A long flag as written in the table, e.g. ``--fail-on-severity``.
_FLAG = re.compile(r"--[a-z][a-z0-9-]*")


def _documented() -> list[tuple[str, str]]:
    """(command, flag) for every long flag named in the reference table."""

    pairs: list[tuple[str, str]] = []
    for line in _REFERENCE.read_text(encoding="utf-8").splitlines():
        match = _ROW.match(line)
        if not match:
            continue
        command = match.group("command")
        # Only the two option columns; the description column is prose and mentions other
        # commands' flags, file names and schema ids.
        columns = [c.strip() for c in match.group("rest").split("|")]
        options_text = " ".join(columns[:2])
        for flag in dict.fromkeys(_FLAG.findall(options_text)):
            pairs.append((command, flag))
    return pairs


@functools.cache
def _help_text(command: str) -> str:
    """Cached: the table names ~127 flags across ~23 commands, and a subprocess per flag
    turned a consistency check into two and a half minutes of the suite's wall clock."""

    env = {**os.environ, "COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}
    proc = subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", command, "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(ROOT),
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, f"`{command} --help` exited {proc.returncode}: {proc.stderr[:300]}"
    # Rich wraps long option lines; collapsing whitespace keeps a flag from being split in
    # half by the terminal width and reported as missing.
    return re.sub(r"\s+", " ", proc.stdout)


def test_the_reference_table_was_actually_parsed() -> None:
    """A sweep over an empty table passes for the wrong reason."""

    pairs = _documented()
    commands = {pair[0] for pair in pairs}
    assert len(commands) > 15, f"only {len(commands)} commands parsed out of the reference table"
    assert len(pairs) > 40, f"only {len(pairs)} documented flags found"


@pytest.mark.parametrize(("command", "flag"), _documented(), ids=[f"{c}{f}" for c, f in _documented()])
def test_a_documented_flag_exists_on_the_command(command: str, flag: str) -> None:
    help_text = _help_text(command)

    assert flag in help_text, (
        f"docs/cli-reference.md documents `{flag}` for `{command}`, and `{command} --help` does "
        "not offer it. An adopter copying that line gets a usage error from the tool that is "
        "supposed to be teaching them."
    )
