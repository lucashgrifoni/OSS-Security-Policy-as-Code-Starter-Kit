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

#: Published output contracts, not evidence inputs, so they have no packaged twin.
PUBLISHED_ONLY = {
    "evaluation-report-2.0.schema.json",
    "findings-1.0.schema.json",
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
