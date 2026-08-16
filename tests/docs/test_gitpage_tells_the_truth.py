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

#: A quoted JS string, single or double, with no escapes and no interpolation. Ten characters
#: is enough to be a phrase and short enough to include the page's own `Now -- v10.0` heading,
#: which the first version's 30-character floor exempted -- so the exact claim this file was
#: written to protect was the one thing it did not check.
_PLAIN_LITERAL = re.compile(r'"([^"\\\n`${}<>]{10,})"' r"|'([^'\\\n`${}<>]{10,})'")

#: JSX text between tags: `<p>Some visible sentence</p>`. esbuild turns this into a string
#: argument to React.createElement, so it lands in the bundle like any other literal -- and
#: the first version, which only read quoted literals, could not see it change.
_JSX_TEXT = re.compile(r">([^<>{}\n]{10,})<")

#: `\xHH`, `\uXXXX`, `\u{XXXXX}` as esbuild's ASCII-only output writes them.
_ESCAPE = re.compile(r"\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")


def _decoded(bundle: str) -> str:
    """Turn the bundle's escapes back into the characters they stand for.

    The first version went the other way -- it re-encoded each source literal into the escape
    form it *guessed* esbuild used -- and guessed wrong twice. esbuild writes `\\xHH` in
    UPPERCASE hex but `\\uXXXX` in uppercase too (`\\u251C`), while that code emitted lowercase;
    every character whose hex contains a-f would have been reported as missing from a bundle
    that was perfectly fresh. It survived only because no swept string happened to contain one.
    A curly quote (U+201C) would have been enough.

    Decoding needs no model of the minifier, so it cannot be wrong about one. Surrogate pairs
    fall out of the UTF-16 decode for free, which also settles the `\\u{...}` question.
    """

    units: list[int] = []
    index = 0
    for match in _ESCAPE.finditer(bundle):
        units.extend(ord(c) for c in bundle[index : match.start()])
        astral, bmp, byte = match.groups()
        units.append(int(astral or bmp or byte, 16))
        index = match.end()
    units.extend(ord(c) for c in bundle[index:])
    # Surrogate pairs are two code units and must recombine; a lone surrogate must not raise.
    return b"".join(u.to_bytes(4, "little") for u in units).decode("utf-32-le", errors="replace")


def _visible_prose() -> list[tuple[str, str]]:
    """(part name, text) for everything a reader of the page can see."""

    found: list[tuple[str, str]] = []
    for part in _PARTS:
        text = part.read_text(encoding="utf-8")
        candidates = [g for m in _PLAIN_LITERAL.finditer(text) for g in m.groups() if g]
        candidates += [m.group(1) for m in _JSX_TEXT.finditer(text)]
        for literal in dict.fromkeys(c.strip() for c in candidates):
            if _is_prose(literal):
                found.append((part.name, literal))
    return found


def _is_prose(candidate: str) -> bool:
    """Keep what a reader sees; drop what only a parser sees.

    Both extractors over-match, and the filter is where that is paid for. A quote regex pairs
    the CLOSING quote of one literal with the OPENING quote of the next, so `{ as: Tag = "div",
    className = "" }` yields `, className = `; and `>` ... `<` spans ordinary code, so an arrow
    function through the next JSX tag yields ` aria-hidden=`. Neither is text on the page.

    Real prose starts with a word and contains no assignment. That also drops a sentence
    containing `=`, which this page has none of -- a false negative here costs a missed staleness
    check, while a false positive would make the fence fire on a correctly rebuilt bundle, and
    a fence that cries wolf gets deleted.
    """

    if not candidate or " " not in candidate or "=" in candidate:
        return False
    if not candidate[0].isalnum():
        return False
    # Class lists, import paths and SVG path data are long and space-separated too.
    return not candidate.startswith(("http", "./", "M", "0 0 "))


def test_there_is_prose_to_check() -> None:
    """A sweep over an empty set passes for the wrong reason."""

    prose = _visible_prose()
    assert len(prose) > 100, f"only {len(prose)} prose literals extracted from {len(_PARTS)} parts"


def test_the_published_bundle_was_rebuilt_from_the_current_sources() -> None:
    """Every visible string in the parts must be present in the committed bundle."""

    bundle = _decoded(_BUNDLE.read_text(encoding="utf-8"))

    missing = [f"{part}: {literal[:70]}" for part, literal in _visible_prose() if literal not in bundle]

    assert not missing, (
        "gitpage/bundle.js does not contain these strings from the page sources, so it was not "
        "rebuilt after they changed. GitHub Pages serves the prebuilt bundle -- the deploy "
        "workflow does not run esbuild -- so until `node build-js.mjs` runs and bundle.js is "
        f"committed, visitors keep seeing the old text: {missing}"
    )


def test_the_bundle_publishes_nothing_the_sources_no_longer_say() -> None:
    """The direction the presence check cannot see: a claim DELETED from the sources.

    "every source string is in the bundle" is satisfied by a bundle that also contains a
    paragraph somebody removed, which is exactly the shape of the bug this file exists for --
    the page kept announcing v8.0.0 after the sources moved on. Deletion is the case where a
    stale bundle keeps publishing something the maintainer decided was wrong.

    Scoped to the milestone titles and era labels, which are the page's dated claims and the
    ones that go stale. Sweeping every bundle string would flag minifier artefacts and React's
    own text, and a fence that fires on those gets switched off.
    """

    bundle = _decoded(_BUNDLE.read_text(encoding="utf-8"))
    sources = "\n".join(p.read_text(encoding="utf-8") for p in _PARTS)

    stale = [claim for claim in re.findall(r'(?:title|era):\s*"([^"\n]{4,})"', bundle) if claim not in sources]

    assert not stale, (
        "gitpage/bundle.js still publishes these milestone claims and no page source contains "
        "them any more, so the deploy is serving text that was deliberately removed. Run "
        f"`node build-js.mjs` in gitpage/ and commit the result: {stale}"
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
