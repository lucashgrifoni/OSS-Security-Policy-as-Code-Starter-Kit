"""A doc that talks about "the vN.x line" is making a claim with an expiry date.

`docs/evidence-export.md` carried three of them pinned to `v6.x` while the kit shipped 10.0.22,
so guidance written for adopters told them to read the CHANGELOG before upgrading inside a
release line that ended four majors earlier. Nothing was wrong with the advice; it just named
a version nobody was on.

Two of those three did not need a version at all and no longer have one. The remaining one is
a genuine statement about how long a label has been carried, and this test is what stops it
from rotting the way the others did: a `vN.x` in this page must name the major the kit is
actually on, so the first release of a new major fails here instead of shipping a stale line.

Point releases are exempt on purpose. "Available since v6.0.0" is a fact about history that
stays true forever, and rewriting it would destroy information rather than refresh it.
"""

from __future__ import annotations

import re

from oss_policy_kit import __version__
from tests.conftest import ROOT

_DOC = ROOT / "docs" / "evidence-export.md"

#: `v6.x` and `v6.0.x` both name a line; `v6.0.0` names a release and is history.
_LINE_REFERENCE = re.compile(r"\bv(\d+)\.(?:\d+\.)?x\b")


def test_every_release_line_this_page_names_is_the_current_one() -> None:
    current = __version__.split(".")[0]

    stale = sorted(
        {m.group(0) for m in _LINE_REFERENCE.finditer(_DOC.read_text(encoding="utf-8")) if m.group(1) != current}
    )

    assert not stale, (
        f"{_DOC.name} tells adopters about release lines the kit is not on (current major is "
        f"v{current}.x): {', '.join(stale)}. Either name the current line or drop the version, "
        "which is what two sentences on this page did when they turned out not to need one."
    )


def test_the_matcher_still_recognises_a_line_reference() -> None:
    """Anti-vacuum: a regex that matches nothing would pass the check above on any page."""

    assert _LINE_REFERENCE.match("v6.x")
    assert _LINE_REFERENCE.match("v6.0.x")
    assert not _LINE_REFERENCE.match("v6.0.0"), "a point release is history, not a line"


def test_the_page_still_names_a_line_at_all() -> None:
    """The other half: if the sentence disappears, the guard has nothing left to hold.

    It is not required to stay forever, but its removal should be a decision rather than a
    side effect, and a silently vacuous guard is how that decision gets skipped.
    """

    assert _LINE_REFERENCE.search(_DOC.read_text(encoding="utf-8")), (
        f"{_DOC.name} no longer names any release line; drop this file if that was deliberate"
    )
