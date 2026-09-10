"""Every ``--format`` value written into a documented command line must be one the CLI takes.

`docs/release-playbook-hardgate.md` told the reader to run
``recommend-profile --target . --format text``. That command exits 2:
``recommend-profile --format must be human or json (aliases: table, compact map to human)``.
The same page opens by promising it "uses only commands and flags that exist in the current
CLI", so the page contradicted itself on its own terms, and the reader who trusted it got a
usage error from the runbook.

`test_documented_flags_exist.py` could not see this: it reads the option column of the
`cli-reference.md` table and checks that each flag *exists*. `--format` exists everywhere. What
was wrong was the **value**, and values live in code blocks scattered across sixty pages, not
in that table.

**No vocabulary is duplicated here.** The accepted set is not restated in this file -- there
are nine of them, they are inline literals in nine modules, and a copy would rot. Each pair is
run through the real command and judged only by whether the failure is a `--format` rejection.

**Every command is canaried.** Running a command that fails for some *other* reason -- a
missing `--profile`, a report file that is not there -- would pass this test no matter what the
format said, so each command is first run with a value that is definitely not a format and
required to reject it. If format validation ever moves behind another check, the canary fails
and this guard says so instead of going quietly green.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app
from tests.conftest import ROOT

#: A value no command could plausibly accept, used to prove the check can see a rejection.
_CANARY = "zzz-not-a-format"

#: What a `--format` rejection looks like from the validators behind these commands. They phrase
#: it four ways, so all four are matched.
#:
#: Matching the bare string ``--format`` instead was tried first and was wrong in both
#: directions of interest: `profiles --format detailed` *succeeds* and prints a profile table
#: whose Description column names `--format`, which read as a rejection. A guard that fires on
#: successful output is not measuring what it claims.
_REJECTION = re.compile(
    r"(--format must be|Unsupported --format|Unknown --format|Invalid value for ['\"]?--format)",
    re.IGNORECASE,
)

#: Minimal argv (minus `--format`) that reaches each command's format validation. Deliberately
#: short: the run is allowed -- expected, even -- to fail afterwards on a missing profile or an
#: absent report. Only the reason matters.
_MINIMAL_ARGV: dict[str, list[str]] = {
    "diff-reports": ["--before", "missing-before.json", "--after", "missing-after.json"],
    "emit-vex": ["--output", "vex.json"],
    "evaluate": ["--target", ".", "--profile", "github-level-1"],
    "export-evidence": ["--target", ".", "--output", "evidence.json"],
    "export-policy": ["--profile", "github-level-1", "--output", "policy.out"],
    "ingest-insights": ["--target", "."],
    "ingest-scorecard": ["--target", "."],
    "init": ["--target", ".", "--dry-run"],
    "profiles": [],
    "recommend-profile": ["--target", "."],
}

_DOC_COMMAND = re.compile(r"^(?:python -m oss_policy_kit|oss-policy-kit)\s+([a-z][a-z0-9-]*)\b(.*)$")
_FORMAT_VALUE = re.compile(r"--format[= ]+([A-Za-z0-9_.-]+)")


def _documented_format_values() -> list[tuple[str, str, str]]:
    """(command, format value, source page) for every documented command line that sets --format."""

    pages = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    found: dict[tuple[str, str], str] = {}
    for page in pages:
        text = page.read_text(encoding="utf-8", errors="replace")
        # Join backslash-continued command lines so a wrapped `--format` is still seen.
        text = re.sub(r"\\r?\n\s*", " ", text)
        for raw in text.splitlines():
            line = raw.strip().removeprefix("$ ").strip()
            command_match = _DOC_COMMAND.match(line)
            if command_match is None:
                continue
            command, rest = command_match.group(1), command_match.group(2)
            for value_match in _FORMAT_VALUE.finditer(rest.split("#")[0]):
                found.setdefault(
                    (command, value_match.group(1)),
                    page.relative_to(ROOT).as_posix(),
                )
    return [(command, value, page) for (command, value), page in sorted(found.items())]


def _run(command: str, value: str) -> str:
    argv = [command, *_MINIMAL_ARGV[command], "--format", value]
    result = CliRunner().invoke(app, argv, catch_exceptions=False)
    return f"{result.stdout}\n{result.output}"


_PAIRS = _documented_format_values()


def test_the_pages_were_actually_read() -> None:
    """An empty sweep passes every case below for the wrong reason."""

    assert len(_PAIRS) >= 10, f"only {len(_PAIRS)} documented --format values found across the docs"
    assert len({command for command, _, _ in _PAIRS}) >= 6, "documented --format values collapsed to a few commands"


@pytest.mark.parametrize(("command", "value", "page"), _PAIRS, ids=[f"{c}-{v}" for c, v, _ in _PAIRS])
def test_a_documented_format_value_is_accepted(
    command: str,
    value: str,
    page: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert command in _MINIMAL_ARGV, (
        f"{page} documents `{command} --format {value}` and this guard has no argv for `{command}`. "
        "Add one to _MINIMAL_ARGV rather than letting the command go unchecked."
    )

    # An empty directory as the working tree: every run here is expected to fail on something
    # after the format check, and none of them may write into the repository.
    monkeypatch.chdir(tmp_path)
    canary = _run(command, _CANARY)
    assert _REJECTION.search(canary), (
        f"`{command}` accepted the impossible format {_CANARY!r}, so this case cannot see a bad "
        f"value and would pass whatever {page} said. Output was: {canary[:400]}"
    )
    actual = _run(command, value)

    assert not _REJECTION.search(actual), (
        f"{page} documents `{command} --format {value}`, and the CLI refuses that value: {actual.strip()[:400]}"
    )
