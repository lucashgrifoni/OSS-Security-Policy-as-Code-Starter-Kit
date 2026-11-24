"""A number a reader can verify in one command must not be one the product stopped producing.

The docs once described `appsec-sast-sca-1` as `11 controls` six releases after it reached 17,
and called the catalog `70-control` in the present tense at 222. Each check below compares
prose against the data it describes rather than against a list somebody maintained by hand.

Every expectation is derived by reading the shipped data -- the bundled profiles, the evidence
projection, the catalog. A guard that hardcoded a count would rot exactly the way the prose did,
and would agree with whichever number was pasted into it.

(The landing-page checks that used to live here left with the GitHub Pages site.)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import yaml

from oss_policy_kit.domain.models import EvidenceCollectionMethod
from tests.conftest import ROOT

_CATALOG = ROOT / "src" / "oss_policy_kit" / "data" / "controls" / "catalog.yaml"
_PROFILE_ROOT = ROOT / "src" / "oss_policy_kit" / "data" / "profiles"
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

#: `### \`osps-baseline-1\` - OpenSSF OSPS Baseline` opens a per-profile paragraph.
_PROFILE_HEADING = re.compile(r"^#{2,4}\s+`([a-z0-9][a-z0-9-]+)`", re.M)


def _profile_control_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in sorted(_PROFILE_ROOT.glob("*/profile.yaml")):
        profile = yaml.safe_load(spec.read_text(encoding="utf-8-sig"))
        counts[profile["id"]] = len(profile.get("controls") or [])
    return counts


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


# ---------------------------------------------------------------------------------------
# Ratios, not just counts.
#
# The counts above are derived and guarded; the PERCENTAGES beside them were not, and both
# drifted. `docs/profiles/cra-eu.md` said cra-eu-strict-1 was 37% evidence-backed when it had
# been 42% since v6.0.0, and `docs/profiles/appsec-sast-sca.md` said 27% experimental when the
# measured figure is 35%. The second page also contradicted itself in the same paragraph: it
# named the experimental set as "the four SARIF adapters plus SAST-OSV-068", and SAST-OSV-068
# is one of those four -- so the sentence double-counted one control and omitted the two SCA
# ones that are actually experimental.
#
# A ratio is a claim a reader can check in one command, exactly like a count, so it is derived
# here from the same two files the counts come from.
# ---------------------------------------------------------------------------------------

#: `42% evidence-backed`, `**Experimental controls:** 35%`, in either order.
_RATIO_CLAIM = re.compile(
    r"(\d{1,3})%\s+(evidence-backed|experimental)|(evidence-backed|experimental)[^.\n]{0,30}?(\d{1,3})%", re.I
)

#: Which catalog field each documented word is a ratio OF.
_RATIO_FIELD = {"evidence-backed": ("assurance", "evidence-backed"), "experimental": ("lifecycle", "experimental")}


def _catalog_by_id() -> dict[str, dict]:
    catalog = yaml.safe_load(_CATALOG.read_text(encoding="utf-8-sig"))
    return {control["id"]: control for control in catalog["controls"]}


def _profile_members() -> dict[str, list[str]]:
    members: dict[str, list[str]] = {}
    for spec in sorted(_PROFILE_ROOT.glob("*/profile.yaml")):
        profile = yaml.safe_load(spec.read_text(encoding="utf-8-sig"))
        raw = profile.get("controls") or []
        members[profile["id"]] = [c if isinstance(c, str) else (c.get("id") or c.get("control")) for c in raw]
    return members


def _real_ratio(profile_id: str, word: str) -> int | None:
    """The measured percentage, rounded the way the correct prose on these pages rounds it."""

    members = _profile_members().get(profile_id)
    if not members:
        return None
    field, wanted = _RATIO_FIELD[word.lower()]
    catalog = _catalog_by_id()
    hits = [c for c in members if catalog.get(c, {}).get(field) == wanted]
    return round(100 * len(hits) / len(members))


def _documented_ratios() -> list[tuple[Path, int, str, str]]:
    """`(page, claimed percent, word, profile id)` for every ratio claim we can attribute.

    Attribution walks headings and remembers the last backtick-quoted profile id seen in one.
    `_PROFILE_HEADING` is not reused: it requires two to four hashes with the id immediately
    after them, and `docs/profiles/appsec-sast-sca.md` opens with a single-hash title that
    carries its id in parentheses, so that pattern attributes none of that page's claims.
    """

    known = set(_profile_members())
    found: list[tuple[Path, int, str, str]] = []
    for page in _CURRENT_PROFILE_PAGES:
        current: str | None = None
        for line in page.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#"):
                ids = [i for i in re.findall(r"`([a-z0-9][a-z0-9-]+)`", line) if i in known]
                if ids:
                    current = ids[-1]
                continue
            if current is None:
                continue
            for match in _RATIO_CLAIM.finditer(line):
                pct, word = (match.group(1), match.group(2)) if match.group(1) else (match.group(4), match.group(3))
                if pct is not None and word is not None:
                    found.append((page, int(pct), word.lower(), current))
    return found


def test_a_documented_percentage_matches_the_profile_it_describes() -> None:
    wrong: list[str] = []
    for page, claimed, word, profile_id in _documented_ratios():
        real = _real_ratio(profile_id, word)
        if real is not None and real != claimed:
            wrong.append(f"{page.relative_to(ROOT).as_posix()}: {profile_id} says {claimed}% {word}, measured {real}%")

    assert not wrong, "documented ratios the data does not support: " + "; ".join(wrong)


def test_there_are_documented_percentages_to_check() -> None:
    """Anti-vacuum: the guard above passes on an empty list, which is how a parser rots."""

    found = _documented_ratios()
    attributed = {profile_id for _, _, _, profile_id in found}

    assert len(found) >= 4, f"only {len(found)} ratio claims parsed; the attribution walk is not reading the pages"
    assert len(attributed) >= 2, f"all claims attributed to {attributed}; heading attribution has collapsed"
