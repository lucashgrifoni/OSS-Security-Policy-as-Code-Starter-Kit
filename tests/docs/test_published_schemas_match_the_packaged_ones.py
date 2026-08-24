"""The schema an adopter is told to read must be the schema the kit enforces.

Two copies of each evidence schema ship: one inside the wheel under
``oss_policy_kit/data/schema/``, which controls validate against, and one under
``reports/schema/`` in the repository, which remediation messages point people at
("Regenerate evidence using reports/schema/evidence-....schema.json").

Nothing kept them in step. That was tolerable only while the packaged copies were
decorative; ``GL-PIPE-011`` now validates against one of them, so a drift would mean the kit
rejects a document the published contract says is valid — and the adopter has no way to tell
which copy is lying.

Derived from the directories rather than a hard-coded list, so a schema added to one side
shows up here instead of being silently half-published.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import ROOT

PACKAGED = ROOT / "src" / "oss_policy_kit" / "data" / "schema"
PUBLISHED = ROOT / "reports" / "schema"

#: Present in the wheel but deliberately not published under ``reports/schema/``: internal
#: contracts nobody is told to author by hand.
PACKAGED_ONLY = {
    "evidence-ai-agent-baseline.schema.json",
    "evidence-ai-system-technical-doc.schema.json",
    "evidence-iac-bicep.schema.json",
    "evidence-iac-cfn.schema.json",
    "evidence-iac-pulumi.schema.json",
    "evidence-iac-terraform.schema.json",
    "profile-recommendation-v2.schema.json",
    "profile-spec.schema.json",
}

#: Published output contracts. They are exempt from the FLAT name parity above because their
#: packaged copies live one directory down -- `data/schema/reports/2.0.json` and
#: `data/schema/findings/1.0.json` -- so a name-set comparison never pairs them up.
#:
#: The comment here used to say they "have no packaged twin", which is false: both twins exist,
#: and both are what the code actually validates against. The exemption was therefore leaving the
#: kit's two most important contracts -- the report an adopter parses and the findings artifact --
#: as the only published schemas with no parity lock at all. Measured when this was written: both
#: pairs are byte-identical today. `test_the_nested_contracts_match_their_published_copy` is what
#: keeps them that way.
PUBLISHED_ONLY = {
    "evaluation-report-2.0.schema.json",
    "findings-1.0.schema.json",
}

#: published name -> packaged path, for the contracts the flat comparison cannot pair.
NESTED_CONTRACT_PAIRS = {
    "evaluation-report-2.0.schema.json": ("reports", "2.0.json"),
    "findings-1.0.schema.json": ("findings", "1.0.json"),
}


def _names(directory: Path) -> set[str]:
    return {p.name for p in directory.glob("*.json")}


def _shared_names() -> list[str]:
    return sorted(_names(PACKAGED) & _names(PUBLISHED))


def test_the_two_schema_directories_are_not_empty() -> None:
    """A parity test over an empty set passes for the wrong reason."""

    assert len(_names(PACKAGED)) > 20
    assert len(_names(PUBLISHED)) > 20
    assert len(_shared_names()) > 20


@pytest.mark.parametrize("name", _shared_names())
def test_a_published_schema_is_byte_identical_to_the_packaged_one(name: str) -> None:
    packaged = (PACKAGED / name).read_text(encoding="utf-8").replace("\r\n", "\n")
    published = (PUBLISHED / name).read_text(encoding="utf-8").replace("\r\n", "\n")

    assert packaged == published, (
        f"{name} differs between the wheel and reports/schema/. Controls validate against the "
        "packaged copy while remediation messages send adopters to the published one, so a "
        "drift makes one of the two a lie."
    )


@pytest.mark.parametrize("published_name", sorted(NESTED_CONTRACT_PAIRS))
def test_the_nested_contracts_match_their_published_copy(published_name: str) -> None:
    """The report and findings contracts must say the same thing in both places.

    Everything the flat comparison pairs by filename is already locked. These two were exempt, so
    the packaged schema the code validates against and the published schema an adopter reads could
    drift apart with nothing failing -- on precisely the two contracts the product is built around.

    Compared as parsed JSON rather than as bytes: a reformat is not drift, and asserting on bytes
    would make this fail for a reason nobody cares about.
    """

    import json

    subdirectory, packaged_name = NESTED_CONTRACT_PAIRS[published_name]
    published = PUBLISHED / published_name
    packaged = PACKAGED / subdirectory / packaged_name

    assert published.is_file(), f"{published_name} is no longer published under reports/schema/"
    assert packaged.is_file(), f"{subdirectory}/{packaged_name} is no longer packaged in the wheel"
    assert json.loads(published.read_text(encoding="utf-8")) == json.loads(packaged.read_text(encoding="utf-8")), (
        f"{published_name} and {subdirectory}/{packaged_name} have drifted. One of them is what "
        "the code validates against and the other is what an adopter reads; drift makes one a lie."
    )


def test_every_schema_is_accounted_for_on_both_sides() -> None:
    """A new schema must be published, or explicitly declared internal."""

    packaged_unpublished = _names(PACKAGED) - _names(PUBLISHED) - PACKAGED_ONLY
    published_unpackaged = _names(PUBLISHED) - _names(PACKAGED) - PUBLISHED_ONLY

    assert not packaged_unpublished, (
        "these ship in the wheel but are not published under reports/schema/, and are not "
        f"listed as internal: {sorted(packaged_unpublished)}"
    )
    assert not published_unpackaged, (
        "these are published but do not exist in the wheel, so nothing can validate against "
        f"them: {sorted(published_unpackaged)}"
    )
