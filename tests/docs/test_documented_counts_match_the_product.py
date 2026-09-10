"""A number a reader can verify in one command must not be one the product stopped producing.

The landing page's stats strip said `18` bundled profiles, `7` states, `3` platforms and `5`
CLI commands while the kit shipped `56`, `9`, `4` and `23` -- every one of the four roughly a
third of the truth, on the first screen a visitor sees. It survived because the only count the
suite checked was `N profiles`, and the strip writes its numbers as `num: 18` with the noun in
a separate `label:` field, so the profile guard could not see them either.

The same era left four more claims behind, each found by comparing prose against the data it
describes rather than against a list somebody maintained by hand:

* the `github-release-hardening-1..3` card advertised `16-37 controls`; the ladder tops out at
  39, because `github-release-hardening-3` grew after the card was written;
* the hero's terminal mock printed `evaluating 16 controls` for `github-level-1`, which has 14,
  and attributed the rows to `GH-GOV-001`, `GH-GOV-002`, `GH-CI-009` and `GH-REL-004` -- four
  identifiers that have never existed in the catalog. For a tool whose product is audit
  evidence, inventing control ids in the shop window is the worst possible place to do it;
* `framework-alignment.md` described `appsec-sast-sca-1` as `11 controls` and listed eleven,
  six releases after it reached 17;
* the same page called the catalog `70-control` in the present tense at 222.

Every expectation below is derived by reading the shipped data -- the catalog, the bundled
profiles, the Typer app, the status enum, the supported-platform set. A guard that hardcoded
`56` would rot exactly the way the page did, and would agree with whichever number was pasted
into it.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import yaml
from typer.main import get_command

from oss_policy_kit.application.init_planner import SUPPORTED_PLATFORMS
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.models import ControlStatus, EvidenceCollectionMethod
from tests.conftest import ROOT
from tests.docs.test_gitpage_tells_the_truth import _bundled_profile_count

_PARTS = sorted((ROOT / "gitpage" / "parts").glob("*.jsx"))
_PROSE_PARTS = [p for p in _PARTS if p.name != "catalog-data.jsx"]
_CATALOG = ROOT / "src" / "oss_policy_kit" / "data" / "controls" / "catalog.yaml"
_PROFILE_ROOT = ROOT / "src" / "oss_policy_kit" / "data" / "profiles"
_SECTIONS_B = ROOT / "gitpage" / "parts" / "sections-b.jsx"
_STRIP = ROOT / "gitpage" / "parts" / "strip.jsx"
_FRAMEWORK_ALIGNMENT = ROOT / "docs" / "framework-alignment.md"
_PROFILES_OVERVIEW = ROOT / "docs" / "profiles" / "overview.md"
_PROJECTION = ROOT / "src" / "oss_policy_kit" / "application" / "evidence_projection.py"

#: The projection field each private classifier answers. Reading the functions' own
#: `return "literal"` statements is what keeps this from becoming a second hand-kept list
#: that can disagree with the module -- which is exactly what the docs did.
#: Backticked words on those bullets that are prose or field names, not enum values.
_PROSE_CODE_SPANS = frozenset(
    {
        "evidence_collection_method",
        "attested_by",
        "collected_at",
        "evidence",
        "extra",
        "pass",
        "reports",
        "source_type",
        "trust_level",
    }
)

_PROJECTION_FIELDS = {
    "_source_type_from_result": "source_type",
    "_trust_level": "trust_level",
    "_attestation_status_from_result": "attestation_status",
    "_freshness_status": "freshness_status",
}

#: Pages that describe the profiles a reader can run TODAY. Migration guides are excluded
#: on purpose: `v5.9.0-migration-guide.md` records "appsec-sast-sca-1 grew from 11 to 15
#: controls", which was the truth of that release and is the kind of dated delta a guard
#: must not rewrite. Every page listed here states a count in the present tense.
_CURRENT_PROFILE_PAGES = [
    _FRAMEWORK_ALIGNMENT,
    ROOT / "docs" / "cra-readiness.md",
    *sorted((ROOT / "docs" / "profiles").glob("*.md")),
]

#: `{ num: 56, suffix: "", label: "Bundled profiles", ... }` in gitpage/parts/strip.jsx.
_STAT = re.compile(r'\{\s*num:\s*(\d+)\s*,\s*suffix:\s*"[^"]*"\s*,\s*label:\s*"([^"]+)"')

#: A control id as the catalog writes them: `GOV-SEC-001`, `SAST-SEMGREP-064`, `GL-PIPE-012`.
#: The three-digit tail is what keeps `CVE-2026-8643` and `CICD-SEC-4` out.
_CONTROL_ID = re.compile(r"\b[A-Z][A-Z0-9]{1,6}(?:-[A-Z0-9]{2,10}){1,2}-\d{3}\b")

#: One profile-family card: its `code:` and the `chips:` of the SAME object. Pairing the two
#: findall streams positionally would silently mis-align the moment a card gains a field.
_FAMILY_CARD = re.compile(r'code:\s*"([^"]+)"[\s\S]{0,400}?chips:\s*\[([^\]]*)\]')
_LADDER = re.compile(r"([a-z0-9-]+?)-(\d)\.\.(\d)\b")
_RANGE_CHIP = re.compile(r'"(\d{1,3})-(\d{1,3})\s+controls"')

#: `### \`osps-baseline-1\` - OpenSSF OSPS Baseline` opens a per-profile paragraph.
_PROFILE_HEADING = re.compile(r"^#{2,4}\s+`([a-z0-9][a-z0-9-]+)`", re.M)


def _catalog_ids() -> set[str]:
    catalog = yaml.safe_load(_CATALOG.read_text(encoding="utf-8-sig"))
    return {control["id"] for control in catalog["controls"]}


def _profile_control_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in sorted(_PROFILE_ROOT.glob("*/profile.yaml")):
        profile = yaml.safe_load(spec.read_text(encoding="utf-8-sig"))
        counts[profile["id"]] = len(profile.get("controls") or [])
    return counts


def _real_stat_values() -> dict[str, int]:
    """What each strip label is a count OF, answered by the shipped code."""

    return {
        "Bundled profiles": _bundled_profile_count(),
        "Explicit states": len(list(ControlStatus)),
        "Platforms supported": len(SUPPORTED_PLATFORMS),
        "CLI commands": len(get_command(app).commands),
    }


def test_the_stats_strip_states_the_products_own_numbers() -> None:
    """The four numbers on the first screen, each against the thing it counts."""

    claimed = {label: int(num) for num, label in _STAT.findall(_STRIP.read_text(encoding="utf-8"))}
    assert claimed, "no `num:`/`label:` stat pairs found in strip.jsx -- has the shape changed?"

    real = _real_stat_values()
    unknown = sorted(set(claimed) - set(real))
    assert not unknown, (
        f"the stats strip advertises {unknown}, and this guard has no way to derive that number "
        "from the code. Add a deriver in `_real_stat_values` -- a relabelled stat that nothing "
        "checks is how the last four rotted."
    )

    wrong = {label: (claimed[label], real[label]) for label in claimed if claimed[label] != real[label]}
    assert not wrong, (
        f"the landing page's stats strip is stale (claimed, real): {wrong}. These four numbers "
        "are the first thing a visitor uses to size the project up, and GitHub Pages serves the "
        "prebuilt bundle -- fix strip.jsx, then run `node build-js.mjs` in gitpage/ and commit."
    )


def test_the_page_prints_no_control_id_the_catalog_does_not_define() -> None:
    """A fabricated control id on the landing page of an audit-evidence tool."""

    known = _catalog_ids()
    invented = sorted(
        {
            f"{part.name}: {candidate}"
            for part in _PROSE_PARTS
            for candidate in _CONTROL_ID.findall(part.read_text(encoding="utf-8"))
            if candidate not in known
        }
    )

    assert not invented, (
        "the landing page prints control identifiers that are not in "
        f"src/oss_policy_kit/data/controls/catalog.yaml: {invented}. A visitor who runs the "
        "command shown gets different ids, and the page is the shop window for a tool whose "
        "product is audit evidence."
    )


def test_there_are_control_ids_on_the_page_to_check() -> None:
    """A sweep that matches nothing passes for the wrong reason."""

    found = [c for p in _PROSE_PARTS for c in _CONTROL_ID.findall(p.read_text(encoding="utf-8"))]
    assert len(found) >= 4, f"only {len(found)} control-id-shaped tokens found across {len(_PROSE_PARTS)} parts"


def _ladder_members(code: str, known: dict[str, int]) -> list[str]:
    """`gitlab-level-1..3 - gitlab-release-hardening-1..3` -> the six profile ids it names."""

    members: list[str] = []
    for stem, low, high in _LADDER.findall(code):
        members += [f"{stem}-{n}" for n in range(int(low), int(high) + 1) if f"{stem}-{n}" in known]
    return members


def _family_cards() -> list[tuple[str, tuple[int, int]]]:
    sections = _SECTIONS_B.read_text(encoding="utf-8")
    cards: list[tuple[str, tuple[int, int]]] = []
    for code, chips in _FAMILY_CARD.findall(sections):
        stated = _RANGE_CHIP.search(chips)
        if stated:
            cards.append((code, (int(stated.group(1)), int(stated.group(2)))))
    return cards


def test_there_are_profile_family_cards_to_check() -> None:
    cards = _family_cards()
    assert len(cards) >= 4, f"only {len(cards)} profile-family cards with a control range parsed"
    assert all(_ladder_members(code, _profile_control_counts()) for code, _ in cards), (
        f"a card names a ladder this guard cannot resolve to bundled profiles: {cards}"
    )


def test_a_profile_family_card_states_the_real_control_range() -> None:
    """`16-37 controls` on a ladder whose top rung carries 39."""

    known = _profile_control_counts()
    wrong = []
    for code, (low, high) in _family_cards():
        counts = [known[member] for member in _ladder_members(code, known)]
        if counts and (low, high) != (min(counts), max(counts)):
            wrong.append(f"{code}: card says {low}-{high}, profiles hold {min(counts)}-{max(counts)}")

    assert not wrong, (
        "a profile-family card on the landing page advertises a control range the bundled "
        f"profiles do not have: {wrong}"
    )


def _documented_profile_counts(page: Path) -> list[tuple[str, int, int]]:
    """(profile id, count the page states, real count) for each per-profile section."""

    text = page.read_text(encoding="utf-8")
    real = _profile_control_counts()
    headings = [(m.group(1), m.start()) for m in _PROFILE_HEADING.finditer(text) if m.group(1) in real]
    found: list[tuple[str, int, int]] = []
    for index, (profile_id, start) in enumerate(headings):
        end = headings[index + 1][1] if index + 1 < len(headings) else len(text)
        stated = re.search(r"\b(\d{1,3})\s+controls\b", text[start:end])
        if stated:
            found.append((profile_id, int(stated.group(1)), real[profile_id]))
    return found


def test_framework_alignment_has_per_profile_sections_to_check() -> None:
    documented = _documented_profile_counts(_FRAMEWORK_ALIGNMENT)
    assert len(documented) >= 5, f"only {len(documented)} per-profile control counts parsed from the page"


@pytest.mark.parametrize("page", _CURRENT_PROFILE_PAGES, ids=lambda p: p.name)
def test_a_documented_profile_control_count_is_the_real_one(page: Path) -> None:
    """`appsec-sast-sca-1 ... 11 controls` outlived six releases and six controls."""

    wrong = [
        f"{profile_id}: page says {stated}, profile bundles {real}"
        for profile_id, stated, real in _documented_profile_counts(page)
        if stated != real
    ]

    assert not wrong, f"{page.name} states a control count the bundled profile does not have: {wrong}"


def _emitted_vocabularies() -> dict[str, set[str]]:
    """{projection field: every string literal its classifier can return}."""

    tree = ast.parse(_PROJECTION.read_text(encoding="utf-8"))
    found: dict[str, set[str]] = {field: set() for field in _PROJECTION_FIELDS.values()}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in _PROJECTION_FIELDS:
            field = _PROJECTION_FIELDS[node.name]
            for inner in ast.walk(node):
                returns_a_string = isinstance(inner, ast.Return) and isinstance(inner.value, ast.Constant)
                if returns_a_string and isinstance(inner.value.value, str):
                    found[field].add(inner.value.value)
    return found


def test_the_projection_classifiers_are_still_where_this_guard_looks() -> None:
    """If a classifier is renamed, the sweep below silently checks nothing."""

    emitted = _emitted_vocabularies()
    empty = sorted(field for field, values in emitted.items() if not values)
    assert not empty, (
        f"no return literals found for {empty} in {_PROJECTION.name} -- the classifier was renamed "
        f"or restructured. Update `_PROJECTION_FIELDS`."
    )


def test_the_evidence_model_docs_name_only_values_the_projection_emits() -> None:
    """Three of five documented vocabularies were values the kit has never written.

    `profiles/overview.md` told JSON consumers that `source_type` is one of `clone_file`,
    `workflow_yaml`, `pipeline_yaml`, `evidence_json`; that `collection_method` is one of
    `clone_inspection`, `workflow_yaml_parse`, `evidence_attestation`, `keyword_match`; and that
    `trust_level` runs `verified` / `attested` / `observed` / `heuristic`. The projection emits
    `static_clone` / `heuristic_signal` / `user_supplied` / `api_collected` / `manual_review` /
    `not_observable`, `static` / `live` / `manual`, and `verified` / `declared` / `inferred` /
    `unobserved`. A parser written from that page keys on nothing.
    """

    emitted = _emitted_vocabularies()
    emitted["collection_method"] = {m.value for m in EvidenceCollectionMethod}
    page = _PROFILES_OVERVIEW.read_text(encoding="utf-8")

    # Checked against the UNION of the vocabularies, not per field: these bullets legitimately
    # cross-reference each other ("`signed` only when the source is `api_collected`"), and a
    # per-field check reports that as invented. The defect class is a token no field emits at
    # all, which the union still catches -- it caught `clone_file`, `workflow_yaml` and
    # `evidence_json` on the first run.
    every_value = set().union(*emitted.values())

    wrong: list[str] = []
    for field in emitted:
        line = next((raw for raw in page.splitlines() if f"**`{field}`**" in raw), None)
        if line is None:
            continue
        named = {tok for tok in re.findall(r"`([a-z][a-z_]{2,})`", line)} - {field}
        invented = sorted(tok for tok in named if tok not in every_value and tok not in _PROSE_CODE_SPANS)
        if invented:
            wrong.append(f"{field}: page names {invented}, nothing in the projection emits those")

    assert not wrong, (
        "docs/profiles/overview.md documents evidence-model values the kit does not produce: "
        f"{wrong}. A consumer parses `evaluation-report.json` from this page."
    )
