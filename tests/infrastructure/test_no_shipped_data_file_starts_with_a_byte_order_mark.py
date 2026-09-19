"""No file the wheel carries may begin with a UTF-8 byte-order mark.

Four of the 56 shipped `profile.yaml` files did, and they were exactly the strict GitHub
ones: `github-level-2`, `github-level-3`, `github-release-hardening-2` and
`github-release-hardening-3`. A Windows editor writes the mark by default and no editor
shows it, so it spread to four siblings and stopped there for no reason anybody chose.

What it did not do is break anything here, and that is worth saying plainly rather than
overselling the fix. PyYAML strips a leading mark from bytes and from a `str` read with
`encoding="utf-8"` alike: the first key does not come back as `﻿ id`, and
`profile["id"]` answers `github-level-3`. No loading failure was found, and none should be
claimed.

The reason to hold the line anyway is that these are data files the kit publishes for other
tools to read. The kit's own reader tolerates the mark; a stricter YAML parser in another
language is under no obligation to, and an adopter who hits that has to discover the three
invisible bytes on their own.

Scoped to `src/oss_policy_kit/data/`, which is what the wheel installs. A sweep of every
tracked file also finds five in `tests/fixtures/repositories/azure-hardened-target/`.
Those are deliberately left: removing them changes no test result, measured, and fixture
bytes are not a contract with anyone.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.conftest import ROOT

_SHIPPED_DATA = ROOT / "src" / "oss_policy_kit" / "data"
_BOM = b"\xef\xbb\xbf"


def _shipped_files() -> list[Path]:
    return sorted(p for p in _SHIPPED_DATA.rglob("*") if p.is_file())


_FILES = _shipped_files()


def test_the_sweep_actually_reaches_the_shipped_data() -> None:
    """Anti-vacuum: an empty sweep would make the case below pass on any tree."""

    assert len(_FILES) >= 90, (
        f"the sweep found {len(_FILES)} shipped data files; it found 95 when this was written, "
        "so it is looking in the wrong place"
    )


@pytest.mark.parametrize("path", _FILES, ids=lambda p: p.relative_to(_SHIPPED_DATA).as_posix())
def test_no_shipped_data_file_starts_with_a_byte_order_mark(path: Path) -> None:
    head = path.read_bytes()[:3]

    assert head != _BOM, (
        f"{path.relative_to(ROOT).as_posix()} begins with a UTF-8 byte-order mark. The kit's own "
        "reader tolerates it, but this file is published for other tools to parse, and the three "
        "bytes are invisible in every editor that would be used to find them."
    )
