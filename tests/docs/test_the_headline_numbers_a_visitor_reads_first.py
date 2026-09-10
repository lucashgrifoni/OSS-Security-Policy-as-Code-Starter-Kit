"""The four surfaces that state a number before the reader runs anything.

`test_documented_counts_match_the_product.py` already holds the stats strip -- but it reads
`gitpage/parts/strip.jsx`, the *source*. GitHub Pages serves the prebuilt `gitpage/bundle.js`
and the deploy workflow does not run esbuild, so the numbers a visitor actually sees come from
the bundle. The freshness fence next door (`test_gitpage_tells_the_truth`) compares *prose*,
and a stat is a bare integer with no space in it: editing `num: 18` to `num: 56` and forgetting
`node build-js.mjs` changes no prose at all. Measured on 2026-09-09 by putting `num:18` back
into the committed bundle: the full suite stayed green at 8186 passed.

The README's At a Glance row -- `| 56 | 222 | 23 |`, the first table in the first screen of the
repository -- had no guard of any kind. Measured the same way, with `| 18 | 207 | 5 |` in place:
green.

The banner is the same claim in the CLI. It read `GitHub | Azure | AWS` from before GitLab
became first-class (v6.4.0, six bundled GitLab profiles) until 2026-09-09, while
`SUPPORTED_PLATFORMS` held four and the landing page advertised four.

docs/at-a-glance.md carries the same three counts, as the page the README delegates its
capability snapshot to. Measured unguarded the same way, same result.

Every expectation here is derived from the shipped code. None of these numbers may be typed
into this file: a guard with its own copy of the answer is a second thing to forget.
"""

from __future__ import annotations

import re

from oss_policy_kit.application.init_planner import SUPPORTED_PLATFORMS
from tests.conftest import ROOT
from tests.docs.test_documented_counts_match_the_product import (
    _STAT,
    _catalog_ids,
    _real_stat_values,
)
from tests.docs.test_gitpage_tells_the_truth import _bundled_profile_count

_BUNDLE = ROOT / "gitpage" / "bundle.js"
_README = ROOT / "README.md"
_TERMINAL_UI = ROOT / "src" / "oss_policy_kit" / "cli" / "terminal_ui.py"
_AT_A_GLANCE = ROOT / "docs" / "at-a-glance.md"

#: The baseline table on the page the README delegates its capability snapshot to. Same
#: three counts, written as prose cells, and measured unguarded on 2026-09-09 by the same
#: method: `18 bundled profiles`, `207 bundled controls`, `5` subcommands, suite green.
_GLANCE_CELLS = {
    "Bundled profiles": re.compile(r"\|\s*Profiles\s*\|\s*(\d+)\s+bundled profiles\s*\|"),
    "Controls": re.compile(r"\|\s*Controls\s*\|\s*(\d+)\s+bundled controls\s*\|"),
    "CLI commands": re.compile(r"\|\s*CLI subcommands\s*\|\s*(\d+)\s*\|"),
}

#: The At a Glance row: `| v10.0.20 <!-- ... --> | 56 | 222 | 23 | 3.12+ |`. The release marker
#: sits in the version cell, so the three counted cells are matched positionally after it.
_GLANCE_ROW = re.compile(
    r"^\|\s*v[0-9][^|]*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|[^|]*\|\s*$",
    re.M,
)

_BANNER_LINE = re.compile(r'^_BANNER_PLATFORMS\s*=\s*"([^"]+)"', re.M)


def _expected_counts() -> dict[str, int]:
    """The three counted claims, each derived from what the kit actually ships."""

    return {
        "Bundled profiles": _bundled_profile_count(),
        "Controls": len(_catalog_ids()),
        "CLI commands": _real_stat_values()["CLI commands"],
    }


def test_the_published_bundle_states_the_products_own_numbers() -> None:
    """The four stats as GitHub Pages serves them, not as the source says them."""

    claimed = {label: int(num) for num, label in _STAT.findall(_BUNDLE.read_text(encoding="utf-8"))}
    assert claimed, (
        "no `num:`/`label:` stat pairs found in gitpage/bundle.js. Either the strip changed "
        "shape or the bundle was built from sources that no longer carry it. Either way this "
        "guard is now blind and must be re-pointed, not deleted."
    )

    real = _real_stat_values()
    unknown = sorted(set(claimed) - set(real))
    assert not unknown, (
        f"the published bundle advertises {unknown}, which `_real_stat_values` cannot derive. "
        "Add a deriver there -- a relabelled stat that nothing checks is how the last four rotted."
    )

    wrong = {label: (claimed[label], real[label]) for label in claimed if claimed[label] != real[label]}
    assert not wrong, (
        f"gitpage/bundle.js publishes stale numbers (claimed, real): {wrong}. This is the file "
        "GitHub Pages serves; the deploy workflow does not run esbuild. Fix "
        "gitpage/parts/strip.jsx, then run `node build-js.mjs` in gitpage/ and commit bundle.js."
    )


def test_the_bundle_and_its_source_agree_on_every_stat() -> None:
    """A rebuild that never happened, stated as the two files disagreeing.

    The check above would also fire, but only once the product moved. This one fires the moment
    the source is edited and the bundle is not, which is the moment the fix is cheap.
    """

    source = _STAT.findall((ROOT / "gitpage" / "parts" / "strip.jsx").read_text(encoding="utf-8"))
    bundled = _STAT.findall(_BUNDLE.read_text(encoding="utf-8"))
    assert source, "no stat pairs in gitpage/parts/strip.jsx -- has the strip changed shape?"

    assert source == bundled, (
        f"gitpage/parts/strip.jsx says {source} and the committed bundle says {bundled}, so "
        "bundle.js was not rebuilt after the strip changed. Run `node build-js.mjs` in gitpage/ "
        "and commit the result -- visitors are served the bundle."
    )


def test_the_readme_at_a_glance_row_states_the_products_own_numbers() -> None:
    """Bundled profiles, controls and CLI commands, in the repository's first table."""

    rows = _GLANCE_ROW.findall(_README.read_text(encoding="utf-8"))
    assert len(rows) == 1, (
        f"expected exactly one At a Glance row in README.md, found {len(rows)}. The row is "
        "`| vX.Y.Z <!-- x-release-please-version --> | profiles | controls | commands | python |`; "
        "if it moved, re-point this guard rather than dropping it."
    )

    profiles, controls, commands = (int(cell) for cell in rows[0])
    claimed = {"Bundled profiles": profiles, "Controls": controls, "CLI commands": commands}
    expected = _expected_counts()

    wrong = {k: (claimed[k], expected[k]) for k in claimed if claimed[k] != expected[k]}
    assert not wrong, (
        f"README.md's At a Glance table is stale (claimed, real): {wrong}. It is the first table "
        "a reader sees and the numbers they quote back."
    )


def test_the_at_a_glance_baseline_table_states_the_products_own_numbers() -> None:
    """docs/at-a-glance.md holds the snapshot the README deliberately does not carry."""

    text = _AT_A_GLANCE.read_text(encoding="utf-8")
    claimed: dict[str, int] = {}
    for label, pattern in _GLANCE_CELLS.items():
        found = pattern.findall(text)
        assert len(found) == 1, (
            f"expected exactly one {label!r} cell in docs/at-a-glance.md, found {len(found)}. "
            "If the table was reshaped, re-point this guard rather than dropping it."
        )
        claimed[label] = int(found[0])

    expected = _expected_counts()
    wrong = {k: (claimed[k], expected[k]) for k in claimed if claimed[k] != expected[k]}
    assert not wrong, (
        f"docs/at-a-glance.md's baseline table is stale (claimed, real): {wrong}. The README "
        "sends readers here for the capability snapshot, so this page carries the claim."
    )


def test_the_cli_banner_names_every_supported_platform() -> None:
    """The banner above `--help` is the product's own answer to which forges it reads."""

    match = _BANNER_LINE.search(_TERMINAL_UI.read_text(encoding="utf-8"))
    assert match, "_BANNER_PLATFORMS is no longer a plain string literal in cli/terminal_ui.py"

    named = {part.strip().casefold() for part in match.group(1).split("|")}
    assert named, "the banner platform line is empty"

    missing = sorted(p for p in SUPPORTED_PLATFORMS if p.casefold() not in named)
    extra = sorted(n for n in named if n not in {p.casefold() for p in SUPPORTED_PLATFORMS})

    assert not missing and not extra, (
        f"the CLI banner advertises {sorted(named)} and the kit supports {sorted(SUPPORTED_PLATFORMS)} "
        f"(missing: {missing}, not supported: {extra}). Every interactive `--help` prints this "
        "line; it under-reported GitLab from v6.4.0 until 2026-09-09."
    )
