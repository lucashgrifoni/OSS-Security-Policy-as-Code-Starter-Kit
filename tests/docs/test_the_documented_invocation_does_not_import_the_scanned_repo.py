"""What the docs tell an operator to type must not import the repository being scanned.

`python -m oss_policy_kit` puts the current directory first on `sys.path`. This kit is
pointed at repositories nobody has read, and its own examples use `--target .` 164 times,
so the two meet: run the documented command from inside a repository that happens to
contain `oss_policy_kit.py`, and that file runs as the tool meant to be scanning it.

Measured on 10.0.24 in a directory holding a one-line `oss_policy_kit.py`:

    python -m oss_policy_kit --version      -> the repository's file executed
    python -P -m oss_policy_kit --version   -> 10.0.24
    oss-policy-kit --version                -> 10.0.24
    PYTHONSAFEPATH=1 python -m ... version  -> 10.0.24

`-P` is the form the docs now teach, because the reason they gave for preferring `-m` over
the console script is real: on Windows the per-user `Scripts\\` directory may not be on
`PATH`. `-P` keeps that and closes the hole, so the advice keeps its original intent.

The first test here is the exploit, not a search for a string. The rest keep the advice
from drifting back, and they exclude the four places that describe the bare form rather
than recommend it.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import ROOT

#: Lines that talk about the unsafe form instead of telling anyone to use it.
_EXPLAINS_RATHER_THAN_ADVISES = (
    "run from inside a repository imports an",
    "would otherwise steal ``evaluate`` as a",
    "instead of repeating ``python -m oss_policy_kit`` on every line.",
)

_ADVICE_FILES = [
    *sorted((ROOT / "docs").rglob("*.md")),
    ROOT / "README.md",
    ROOT / "src" / "oss_policy_kit" / "cli" / "help_text.py",
    ROOT / "src" / "oss_policy_kit" / "cli" / "common.py",
    ROOT / "src" / "oss_policy_kit" / "cli" / "evaluate.py",
    ROOT / "src" / "oss_policy_kit" / "application" / "evidence_scaffold.py",
]


def _shadowed_repo(tmp_path: Path) -> Path:
    """A directory shaped like something an operator was asked to scan."""

    repo = tmp_path / "repo-under-review"
    repo.mkdir()
    (repo / "README.md").write_text("# a repository you have not read\n", encoding="utf-8")
    (repo / "oss_policy_kit.py").write_text(
        "import sys\nsys.stderr.write('SHADOW RAN\\n')\nraise SystemExit(99)\n",
        encoding="utf-8",
    )
    return repo


def _run(repo: Path, argv: list[str], env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1", "COLUMNS": "200"}
    env.pop("PYTHONSAFEPATH", None)
    env.update(env_extra or {})
    return subprocess.run(  # noqa: S603 - fixed argv, shell=False
        argv,
        cwd=repo,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=False,
    )


def test_the_bare_dash_m_form_runs_the_scanned_repositorys_file(tmp_path: Path) -> None:
    """The defect itself. If this ever stops holding, the rest of the file is pointless.

    Asserted rather than described so the tests below are anchored to a real behaviour
    and not to a belief about how Python resolves imports.
    """

    result = _run(_shadowed_repo(tmp_path), [sys.executable, "-m", "oss_policy_kit", "--version"])

    assert "SHADOW RAN" in result.stderr, (
        "the shadowing no longer happens, which would be good news and makes the advice "
        f"below unnecessary. stdout={result.stdout[:200]!r} stderr={result.stderr[:200]!r}"
    )


@pytest.mark.parametrize(
    ("argv_tail", "env_extra", "label"),
    [
        pytest.param(["-P", "-m", "oss_policy_kit", "--version"], None, "-P", id="dash-P"),
        pytest.param(
            ["-m", "oss_policy_kit", "--version"], {"PYTHONSAFEPATH": "1"}, "PYTHONSAFEPATH", id="safepath-env"
        ),
    ],
)
def test_the_documented_form_runs_the_installed_kit(
    tmp_path: Path, argv_tail: list[str], env_extra: dict[str, str] | None, label: str
) -> None:
    result = _run(_shadowed_repo(tmp_path), [sys.executable, *argv_tail], env_extra)

    assert "SHADOW RAN" not in result.stderr, f"{label} did not stop the repository's file from running"
    assert result.returncode == 0, f"{label} broke the CLI: {result.stderr[:300]!r}"


def test_nothing_advises_the_bare_form_any_more() -> None:
    """Derived from the files, so a new doc page is covered without a list edit."""

    offenders: list[str] = []
    for path in _ADVICE_FILES:
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if "python -m oss_policy_kit" not in line:
                continue
            if any(marker in line for marker in _EXPLAINS_RATHER_THAN_ADVISES):
                continue
            offenders.append(f"{path.relative_to(ROOT).as_posix()}:{number}")

    assert not offenders, (
        "these lines teach an invocation that imports the scanned repository; write "
        f"`python -P -m oss_policy_kit` or the console script instead: {', '.join(offenders[:20])}"
        + (f" (+{len(offenders) - 20} more)" if len(offenders) > 20 else "")
    )


def test_the_guard_above_can_still_see_the_bare_form() -> None:
    """The mutation: an advice line with no explanatory marker must be caught."""

    line = "Run `python -m oss_policy_kit evaluate --target .` to start."

    assert "python -m oss_policy_kit" in line
    assert not any(marker in line for marker in _EXPLAINS_RATHER_THAN_ADVISES), (
        "the exclusion list has grown wide enough to swallow an ordinary advice line"
    )


def test_the_adoption_guide_says_why_the_flag_is_there() -> None:
    """A flag with no reason beside it is the first thing an editor drops."""

    # Blockquote markers dropped and whitespace collapsed, in that order. The note is
    # hard-wrapped inside a `>` block, so a phrase that reads as one sentence is split
    # across lines and each continuation carries a `>`. Collapsing alone leaves those in
    # the middle of the sentence and the search still misses.
    raw = (ROOT / "docs" / "adoption-guide.md").read_text(encoding="utf-8")
    guide = " ".join(line.lstrip().removeprefix(">").strip() for line in raw.splitlines()).replace("  ", " ")
    guide = " ".join(guide.split())

    assert "Keep the `-P`" in guide
    assert "sys.path" in guide
    assert "console script is equally safe and needs no flag" in guide
    assert "PYTHONSAFEPATH=1" in guide, "the third safe form is worth naming too"


def test_the_cli_note_says_why_too() -> None:
    """The help text is the last thing read before the command is typed."""

    from oss_policy_kit.cli.help_text import ROOT_WINDOWS_NOTE

    assert "-P" in ROOT_WINDOWS_NOTE
    assert "current directory" in ROOT_WINDOWS_NOTE
