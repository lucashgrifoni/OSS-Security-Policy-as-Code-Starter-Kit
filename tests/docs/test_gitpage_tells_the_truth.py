"""The landing page must state the release it is actually shipped from, and be rebuilt.

Two failures, one page:

* The source announced *"Now -- v8.0.0"* and *"20 profiles across GitHub, Azure, and AWS"*
  while the kit shipped v10.0.15 with 56 profiles across four platforms -- GitLab has been
  first-class since v6.4.0. The roadmap listed as *"Directional"* two things that had already
  shipped: CRA conformance evidence (v9.0.0) and the cross-scanner finding model (v10.0.0).
* GitHub Pages serves the **prebuilt** `bundle.js`; the deploy workflow does not run esbuild.
  So editing a `.jsx` file changes nothing anybody sees until `node build-js.mjs` runs and the
  bundle is committed. Fixing the numbers above without rebuilding would have left the page
  saying v8.0.0 while the repository said v10.0.15 -- and looked, in the diff, like a fix.

The staleness half is derived from the sources rather than from a list of claims: any prose
edit to any part is checked, not just the ones known to have rotted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from oss_policy_kit import __version__
from tests.conftest import ROOT

_GITPAGE = ROOT / "gitpage"
_BUNDLE = _GITPAGE / "bundle.js"
_PARTS = sorted((_GITPAGE / "parts").glob("*.jsx")) + [_GITPAGE / "app.jsx"]

#: A double-quoted JS string with no escapes and no embedded quote of either kind. esbuild
#: keeps such a literal verbatim apart from re-encoding non-ASCII, so it can be searched for
#: in the minified output without reimplementing the minifier.
_PLAIN_LITERAL = re.compile(r'"([^"\'\\\n`${}<>]{30,})"')


def _as_esbuild_writes_it(text: str) -> str:
    """Re-encode a literal the way esbuild's ASCII-only output writes it.

    Two escape forms, and it took a failing run to learn that guessing one was not enough:
    `\\xHH` in UPPERCASE hex below U+0100 (`.` becomes `\\xB7`, `SS` becomes `\\xA7`), and
    `\\uXXXX` in lowercase above it (`--` becomes `\\u2014`). Anything past the BMP is written
    as its two UTF-16 code units, so the encoding walks code units rather than code points.
    """

    out: list[str] = []
    raw = text.encode("utf-16-be")
    for code in (int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw), 2)):
        if code < 128:
            out.append(chr(code))
        elif code < 256:
            out.append(f"\\x{code:02X}")
        else:
            out.append(f"\\u{code:04x}")
    return "".join(out)


def _visible_prose() -> list[tuple[str, str]]:
    """(part name, literal) for every plain prose literal in the page sources."""

    found: list[tuple[str, str]] = []
    for part in _PARTS:
        text = part.read_text(encoding="utf-8")
        for literal in dict.fromkeys(_PLAIN_LITERAL.findall(text)):
            # Class lists and import paths are long and space-separated too, and they are not
            # prose. Requiring a sentence-like shape keeps the check on what a reader sees.
            if " " in literal and not literal.startswith(("http", "./", "M", "0 0 ")):
                found.append((part.name, literal))
    return found


def test_there_is_prose_to_check() -> None:
    """A sweep over an empty set passes for the wrong reason."""

    prose = _visible_prose()
    assert len(prose) > 100, f"only {len(prose)} prose literals extracted from {len(_PARTS)} parts"


def test_the_published_bundle_was_rebuilt_from_the_current_sources() -> None:
    """Every prose string in the parts must be present in the committed bundle."""

    bundle = _BUNDLE.read_text(encoding="utf-8")

    missing = [
        f"{part}: {literal[:70]}" for part, literal in _visible_prose() if _as_esbuild_writes_it(literal) not in bundle
    ]

    assert not missing, (
        "gitpage/bundle.js does not contain these strings from the page sources, so it was not "
        "rebuilt after they changed. GitHub Pages serves the prebuilt bundle -- the deploy "
        "workflow does not run esbuild -- so until `node build-js.mjs` runs and bundle.js is "
        f"committed, visitors keep seeing the old text: {missing}"
    )


def test_the_page_announces_the_release_line_this_repository_ships() -> None:
    """The `Now --` milestone is the page's headline claim about what a visitor would install.

    The page names the release LINE (`v10.0`), not the point release, and this compares
    major.minor. A patch release changes nothing the page describes, and demanding an edit plus
    a node rebuild inside every release PR -- which release-please cannot do -- would have made
    this fence an obstacle at exactly the moment it is most tempting to switch off.
    """

    sections = (_GITPAGE / "parts" / "sections-c.jsx").read_text(encoding="utf-8")

    announced = re.findall(r'title:\s*"Now\s*—\s*v([0-9]+\.[0-9]+)"', sections)
    line = ".".join(__version__.split(".")[:2])

    assert announced, "the roadmap's `Now` milestone no longer names a release line -- has it moved?"
    assert announced == [line], (
        f"the landing page announces v{announced[0]} as the current line and this repository "
        f"ships v{__version__}. A visitor reads the page to decide what they are installing."
    )


def _bundled_profile_count() -> int:
    """What `oss-policy-kit profiles` would list -- the number a visitor can verify.

    Mirrors `cli.profiles._iter_bundled_profiles`: a profile is a directory holding a
    `profile.yaml`, and a legacy alias is not counted when its target is also bundled.
    """

    from oss_policy_kit.application.loader import merge_kit_root  # noqa: PLC0415
    from oss_policy_kit.cli.profiles import _PROFILE_DISPLAY_ALIAS_TARGETS  # noqa: PLC0415

    profiles_dir = merge_kit_root(None) / "profiles"
    ids = {p.parent.name for p in profiles_dir.glob("*/profile.yaml")}
    return sum(1 for i in ids if _PROFILE_DISPLAY_ALIAS_TARGETS.get(i) not in ids)


@pytest.mark.parametrize("part", _PARTS, ids=lambda p: p.name)
def test_no_page_claims_a_profile_count_that_is_not_the_real_one(part: Path) -> None:
    """`20 profiles` survived on the page for four minor releases and thirty-six profiles."""

    real = _bundled_profile_count()

    claimed = {int(n) for n in re.findall(r"\b([0-9]{1,3})\s+profiles\b", part.read_text(encoding="utf-8"))}
    wrong = sorted(n for n in claimed if n != real)

    assert not wrong, (
        f"{part.name} advertises {wrong} profiles and the kit bundles {real}. The count is the "
        "first thing a visitor uses to size the project up."
    )
