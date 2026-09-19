"""`reports/README.md` must name the commands that actually carry `--output-dir`.

It named four and got two of them wrong: `scaffold-evidence` has no such flag, and
`collect-evidence` has no default rather than `out/`. It also left out `init`, which has
one. The sentence was written once and never asked the CLI again.

The cost is not only a reader's confusion. A test written from that sentence passed
`--output-dir` to `scaffold-evidence`, Click answered exit 2 for an unknown option, and
the case looked like it was asserting the refusal under test. It passed on both sides of
the fix.

So the expected set is taken from Click rather than restated here. A command that gains or
loses the flag moves this test with it, which a second hand-written list cannot do.
"""

from __future__ import annotations

import re

from typer.main import get_command

from oss_policy_kit.cli.main import app
from tests.conftest import ROOT

_DOC = ROOT / "reports" / "README.md"


def _commands_with_output_dir() -> list[str]:
    group = get_command(app)
    found: list[str] = []
    for name in sorted(getattr(group, "commands", {})):
        command = group.get_command(None, name)  # type: ignore[arg-type]
        if command is None:
            continue
        if any("--output-dir" in getattr(param, "opts", []) for param in command.params):
            found.append(name)
    return found


_WITH = _commands_with_output_dir()
_WITHOUT = sorted(set(getattr(get_command(app), "commands", {})) - set(_WITH))

#: The phrase the claim hangs on. Everything backticked before it is a command the document
#: says accepts the flag; everything after is prose about defaults and exclusions.
_CLAIM = "accept an `--output-dir`"


def _claimed_commands() -> list[str]:
    """The commands the document says take the flag, read from the claim itself.

    Keyed on the grammar rather than on the line layout: an earlier version looked for the
    backticked name anywhere in the line, which then failed on the corrected sentence,
    because that sentence names `scaffold-evidence` in order to say it does NOT take the
    flag. Only the names before the claim are the claim.
    """

    text = _DOC.read_text(encoding="utf-8")
    prefix = text[: text.index(_CLAIM)].rsplit("\n\n", 1)[-1]
    known = set(getattr(get_command(app), "commands", {}))
    return sorted({name for name in re.findall(r"`([a-z-]+)`", prefix) if name in known})


def test_the_cli_still_has_commands_on_both_sides() -> None:
    """Anti-vacuum: an empty list either way would make the cases below say nothing."""

    assert len(_WITH) >= 4, f"only {len(_WITH)} commands carry --output-dir: {_WITH}"
    assert _WITHOUT, "every command carries the flag, so the exclusion case below is empty"
    assert _claimed_commands(), "no command name was read out of the claim, so it matches nothing"


def test_the_document_claims_exactly_the_commands_that_have_the_flag() -> None:
    claimed = _claimed_commands()

    assert claimed == _WITH, (
        f"the document says {claimed} accept --output-dir; Click says {_WITH}. "
        f"Missing from the document: {sorted(set(_WITH) - set(claimed))}. "
        f"Listed and wrong: {sorted(set(claimed) - set(_WITH))}. A test written from a wrong "
        "entry passes an unknown option, gets exit 2, and reads it as the behaviour under test."
    )
