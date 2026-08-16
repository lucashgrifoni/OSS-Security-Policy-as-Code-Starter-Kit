"""Every flag `docs/cli-reference.md` documents must exist on the command it documents.

`scan-k8s` was documented with `--helm-pre-pass` / `--no-helm-pre-pass`. The real flags are
`--helm-render` / `--no-helm-render`; the option had been renamed and the reference table had
not. An adopter copying that line gets a usage error from the tool that is supposed to be
teaching them.

Derived from the table itself rather than a list of commands: a row added for a new command is
checked from the moment it is written, and a flag renamed in code fails here rather than in
somebody's pipeline.

**The flags come from the command object, not from rendered `--help`.** The first version ran
`--help` in a subprocess, arguing that the rendered text is what an adopter sees. It passed on
the author's machine and failed in CI on `--applicability-engine` and `--use-insights-evidence`,
because Rich hard-wraps a long option name when the terminal is narrow -- at 80 columns those
render as `applicability-en` and `use-insights-evi`, split across lines. Setting `COLUMNS` did
not survive the runner.

So the test was judging **layout** while claiming to judge **existence**, which is the same
defect this release spent its time removing from the product: reading rendered text instead of
structure. Click knows every option the command accepts, at any width, on any platform.
"""

from __future__ import annotations

import re

import pytest
import typer.main

from oss_policy_kit.cli.main import app
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


def _declared_flags() -> dict[str, set[str]]:
    """Every long option each command accepts, straight from the Click command objects."""

    group = typer.main.get_command(app)
    return {
        name: {opt for param in command.params for opt in (*param.opts, *param.secondary_opts) if opt.startswith("--")}
        for name, command in group.commands.items()
    }


def test_the_reference_table_was_actually_parsed() -> None:
    """A sweep over an empty table passes for the wrong reason."""

    pairs = _documented()
    commands = {pair[0] for pair in pairs}
    assert len(commands) > 15, f"only {len(commands)} commands parsed out of the reference table"
    assert len(pairs) > 40, f"only {len(pairs)} documented flags found"


@pytest.mark.parametrize(("command", "flag"), _documented(), ids=[f"{c}{f}" for c, f in _documented()])
def test_a_documented_flag_exists_on_the_command(command: str, flag: str) -> None:
    declared = _declared_flags()

    assert command in declared, (
        f"docs/cli-reference.md documents `{command}`, and the CLI has no such command. Available: {sorted(declared)}"
    )
    assert flag in declared[command], (
        f"docs/cli-reference.md documents `{flag}` for `{command}`, and the command does not "
        "accept it. An adopter copying that line gets a usage error from the tool that is "
        f"supposed to be teaching them. It accepts: {sorted(declared[command])}"
    )
