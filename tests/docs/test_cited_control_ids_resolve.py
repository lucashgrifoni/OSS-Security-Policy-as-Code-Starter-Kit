"""A control id a reader is shown as current must be one the catalog defines.

The landing page was caught inventing four ids and got a guard for it. The same defect was
sitting in three other places that guard does not look, and had been there for releases:

* ``src/oss_policy_kit/data/profiles/cra-eu-ai-act-art11-1/profile.yaml`` described itself as
  bundling ``REL-CHANGE-001`` while its own ``controls:`` list bound ``REL-CHANGE-012``. That
  is shipped product data, not prose -- the description travels in the wheel;
* ``docs/insights-emission.md`` mapped two ``SECURITY-INSIGHTS.yml`` fields to
  ``GOV-COWN-001`` and ``REL-CHANGE-001``, neither of which the catalog has ever defined;
* ``docs/framework-alignment.md`` wrote two families as ``A .. B`` ranges whose endpoint named
  nothing -- ``SEC-WEBHOOK-008`` and ``LLM-AI-ACT-006``. The page's own closing paragraph said
  a 2026-05-25 pass had left every cited id resolving; that pass read single ids and walked
  past both range endpoints, so the claim was false on the day it was written.

Every expectation is read out of ``catalog.yaml``. Nothing here restates an id, so nothing
here can agree with a wrong one.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from tests.conftest import ROOT

_CATALOG = ROOT / "src" / "oss_policy_kit" / "data" / "controls" / "catalog.yaml"
_PROFILE_ROOT = ROOT / "src" / "oss_policy_kit" / "data" / "profiles"
_DOCS = ROOT / "docs"
_FRAMEWORK_ALIGNMENT = _DOCS / "framework-alignment.md"

#: A catalog id, with the boundaries that keep partial matches out. Without the lookbehind,
#: ``LLM-AI-ACT-CHANGE-007`` also yields the substring ``AI-ACT-CHANGE-007``, which resolves
#: to nothing and would report a real id as invented. Without the lookahead, the waiver id
#: ``WAIVER-IAC-TF-008-LEGACY`` in docs/iac-terraform.md yields a control-shaped prefix.
_CONTROL_ID = re.compile(r"(?<![A-Z0-9-])[A-Z][A-Z0-9]{1,6}(?:-[A-Z0-9]{2,10}){1,3}-\d{3}(?![-\w])")

#: ```CI-PIN-001` -> `CI-PIN-008``` records a rename. Naming the retired id is the
#: point of that sentence, so an id is forgiven exactly when an arrow gives it a successor
#: that resolves.
_RENAME = re.compile(r"`([A-Z][A-Z0-9-]*-\d{3})`\s*(?:->|→)\s*`([A-Z][A-Z0-9-]*-\d{3})`")

#: The ``A .. B`` notation that hid two dead endpoints in framework-alignment.md.
_RANGE = re.compile(r"`([A-Z][A-Z0-9-]*-\d{3})`\s*\.\.\s*`([A-Z][A-Z0-9-]*-\d{3})`")

#: Pages that name a retired or not-yet-existing id on purpose. Each is excluded because
#: describing ids outside the catalog is what the page is FOR, not because it is inconvenient:
#: ``policy-data-lifecycle.md`` is the register of controls the kit retired and what replaced
#: them, and ``deferred-followups.md`` names controls it says in the same sentence do not
#: exist yet ("the kit currently has no direct control for this").
_BY_DESIGN = frozenset({"policy-data-lifecycle.md", "deferred-followups.md"})


def _catalog_ids() -> set[str]:
    catalog = yaml.safe_load(_CATALOG.read_text(encoding="utf-8-sig"))
    return {control["id"] for control in catalog["controls"]}


def _current_pages() -> list[Path]:
    """Docs that describe the kit as it ships today.

    ADRs and migration guides are excluded for the reason the phase before this one excluded
    them from the count check: both are dated records, and an id that was real when the
    decision was taken is the truth of that document, not a defect in it.
    """

    return [
        page
        for page in sorted(_DOCS.rglob("*.md"))
        if "decisions" not in page.parts
        and "sample-reports" not in page.parts
        and "migration-guide" not in page.name
        and page.name not in _BY_DESIGN
    ]


def _unknown_in(text: str, known: set[str]) -> list[str]:
    superseded = {old for old, new in _RENAME.findall(text) if new in known}
    return sorted({c for c in _CONTROL_ID.findall(text) if c not in known and c not in superseded})


def _profile_prose() -> list[tuple[str, str]]:
    prose: list[tuple[str, str]] = []
    for spec in sorted(_PROFILE_ROOT.glob("*/profile.yaml")):
        profile = yaml.safe_load(spec.read_text(encoding="utf-8-sig"))
        blob = " ".join(str(profile.get(field, "")) for field in ("title", "description", "audience"))
        prose.append((spec.parent.name, blob))
    return prose


def test_the_pattern_reads_the_ids_the_catalog_actually_writes() -> None:
    """A sweep whose regex is wrong reports real ids as invented and misses the fake ones."""

    assert _CONTROL_ID.findall("LLM-AI-ACT-CHANGE-007") == ["LLM-AI-ACT-CHANGE-007"]
    assert _CONTROL_ID.findall("WAIVER-IAC-TF-008-LEGACY") == []
    assert _CONTROL_ID.findall("no such thing as ZZZ-NOPE-999 here") == ["ZZZ-NOPE-999"]
    assert "ZZZ-NOPE-999" not in _catalog_ids()


@pytest.mark.parametrize("profile_id, prose", _profile_prose())
def test_a_bundled_profile_describes_itself_with_real_control_ids(profile_id: str, prose: str) -> None:
    """The description ships in the wheel; `profiles --format json` hands it to a consumer."""

    invented = _unknown_in(prose, _catalog_ids())
    assert not invented, (
        f"the bundled profile `{profile_id}` describes itself as covering {invented}, which "
        "src/oss_policy_kit/data/controls/catalog.yaml does not define. Check the profile's own "
        "`controls:` list -- cra-eu-ai-act-art11-1 said REL-CHANGE-001 while binding "
        "REL-CHANGE-012."
    )


def test_there_are_control_ids_in_the_profile_descriptions_to_check() -> None:
    """A sweep that matches nothing passes for the wrong reason."""

    found = [c for _, prose in _profile_prose() for c in _CONTROL_ID.findall(prose)]
    assert len(found) >= 50, f"only {len(found)} control-id-shaped tokens across bundled profiles"


@pytest.mark.parametrize("page", _current_pages(), ids=lambda p: p.name)
def test_a_current_doc_page_cites_no_control_id_the_catalog_lacks(page: Path) -> None:
    invented = _unknown_in(page.read_text(encoding="utf-8"), _catalog_ids())
    assert not invented, (
        f"docs/{page.relative_to(_DOCS).as_posix()} cites {invented}, which "
        "src/oss_policy_kit/data/controls/catalog.yaml does not define. A reader who greps the "
        "catalog for one of these finds nothing."
    )


def test_there_are_control_ids_in_the_current_docs_to_check() -> None:
    """A sweep that matches nothing passes for the wrong reason."""

    pages = _current_pages()
    found = [c for page in pages for c in _CONTROL_ID.findall(page.read_text(encoding="utf-8"))]
    assert len(pages) >= 20, f"only {len(pages)} current doc pages resolved"
    assert len(found) >= 200, f"only {len(found)} control-id-shaped tokens across {len(pages)} pages"


def test_a_control_id_range_names_a_real_control_at_both_ends() -> None:
    """`A .. B` reads as a family; an endpoint resolving to nothing is invisible in prose."""

    known = _catalog_ids()
    text = _FRAMEWORK_ALIGNMENT.read_text(encoding="utf-8")
    pairs = _RANGE.findall(text)
    assert pairs, "no `A .. B` ranges in framework-alignment.md -- this guard checks nothing"

    broken = sorted(f"{start} .. {end}" for start, end in pairs if start not in known or end not in known)
    assert not broken, (
        "docs/framework-alignment.md writes ranges whose endpoints the catalog does not "
        f"define: {broken}. `SEC-WEBHOOK-001 .. SEC-WEBHOOK-008` read as eight sequential ids; "
        "the family is named, not numbered, and -008 was never one of them."
    )
