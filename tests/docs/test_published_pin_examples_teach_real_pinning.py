"""Every self-referencing pin example must come from a release where pinning works.

`docs/github-action.md` sells SHA pinning as *"maximum supply-chain assurance"*, and the
shipped marketplace template repeats it. Until v10.0.14, a SHA-pinned reference to this action
fell through to an empty version and the composite step ran `pip install oss-policy-kit` with
no pin at all -- so an adopter who followed the advice got a **less** reproducible install than
one who ignored it.

The two SHAs those files showed, `9782606d` (v10.0.4) and `4dc762d8` (v10.0.2), were both from
that period. Reading `action.yml` at each of those revisions confirms it: both end in
``else -> kit_version=`` with nothing on the right-hand side.

Nothing noticed, because an example is only wrong relative to a fix that landed later, and
nothing re-reads examples after a fix.

This checks the trailing tag comment rather than resolving the SHA through git: CI checks out
shallow, so `git show <old-sha>` and `git tag` are not reliably available. The comment is
already the repository's convention for recording which tag a SHA belongs to, which makes it
the contract worth enforcing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import ROOT

#: The release that made a SHA pin resolve to the wheel that revision ships.
MINIMUM = (10, 0, 14)

#: `uses: <owner>/<this action>@<40-hex sha>  # vX.Y.Z`
_SELF_PIN = re.compile(
    r"OSS-Security-Policy-as-Code-Starter-Kit@(?P<sha>[0-9a-f]{40})\s*#\s*v(?P<version>\d+\.\d+\.\d+)"
)

#: Everything an adopter reads and copies from.
_SEARCHED = ("README.md", "action.yml", "docs", "templates", "examples")


def _adopter_facing_files() -> list[Path]:
    files: list[Path] = []
    for entry in _SEARCHED:
        path = ROOT / entry
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(p for p in path.rglob("*") if p.is_file() and p.suffix in {".md", ".yml", ".yaml"})
    return sorted(files)


def _pins() -> list[tuple[Path, str, tuple[int, ...]]]:
    found: list[tuple[Path, str, tuple[int, ...]]] = []
    for path in _adopter_facing_files():
        for match in _SELF_PIN.finditer(path.read_text(encoding="utf-8", errors="replace")):
            version = tuple(int(p) for p in match.group("version").split("."))
            found.append((path.relative_to(ROOT), match.group("sha"), version))
    return found


def test_there_are_pin_examples_to_check() -> None:
    """A sweep over an empty set passes for the wrong reason."""

    assert _pins(), "no SHA-pinned examples of this action were found -- has the pattern changed?"


@pytest.mark.parametrize(
    ("rel", "sha", "version"),
    _pins(),
    ids=[f"{p.as_posix()}@{s[:7]}" for p, s, _v in _pins()],
)
def test_a_pin_example_comes_from_a_release_that_pins(rel: Path, sha: str, version: tuple[int, ...]) -> None:
    assert version >= MINIMUM, (
        f"{rel} pins this action at {sha[:7]} (v{'.'.join(map(str, version))}), from before "
        f"v{'.'.join(map(str, MINIMUM))} -- at that revision a SHA pin installed an UNPINNED "
        "wheel, so the example teaches the opposite of what the surrounding text promises."
    )


def test_no_document_offers_a_major_line_tag_that_is_not_published() -> None:
    """`action.yml` told adopters they could pin `@v10`. No such tag or branch exists.

    A rolling major tag is deliberately not published -- it must be moved on every release,
    and a release that forgets leaves everyone pinned to it silently on an old version. So the
    offer had to go, not the tag be created.
    """

    # Scoped to THIS action. My first version matched any `@vN` and flagged
    # `actions/checkout@v4` inside the deliberately-vulnerable fixture -- which is there on
    # purpose and must stay -- plus an ADR quoting a control and this file's own explanation.
    # A sweep that fires on correct content gets switched off, so it has to name its subject.
    bare_major = re.compile(r"OSS-Security-Policy-as-Code-Starter-Kit@v\d+(?![.\d])")

    offered = []
    for path in _adopter_facing_files():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if bare_major.search(line):
                offered.append(f"{path.relative_to(ROOT).as_posix()}: {line.strip()[:90]}")

    assert not offered, (
        "these offer a major-line pin, but this repository publishes no rolling major tag, so "
        f"an adopter following them gets a ref that does not resolve: {offered}"
    )
