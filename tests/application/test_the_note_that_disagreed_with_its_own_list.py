"""`recommend-profile` told the reader how the list was ordered, and the list was not.

On a clone carrying both GitHub workflows and an Azure Pipelines file, the note read
`primary ranked: Azure Pipelines` and `Profile suggestions prioritize the strongest platform
signals first`, above a list whose first entry was `github-level-1`.

Two things were wrong at once. The list is sorted by how well each profile fits, with the
platform ranking used only to break ties, so the claim about ordering was false. And that
ranking counts a platform's CI files as a boolean, so nine workflows and one pipeline weigh the
same and the winner is decided alphabetically, which `azure` wins over `github`. Neither is
worth changing behaviour over. Saying it correctly is.
"""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.profile_hints import build_profile_recommendation


def _clone_with_two_platforms(tmp_path: Path) -> Path:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    for name in ("ci.yml", "release.yml", "scan.yml"):
        (workflows / name).write_text("on: push\njobs: {}\n", encoding="utf-8")
    (tmp_path / "azure-pipelines.yml").write_text("trigger:\n  - main\n", encoding="utf-8")
    return tmp_path


def test_the_note_does_not_claim_an_order_the_list_does_not_have(tmp_path: Path) -> None:
    result = build_profile_recommendation(_clone_with_two_platforms(tmp_path))
    notes = " ".join(result.notes)

    assert "prioritize the strongest platform signals first" not in notes, notes


def test_the_note_does_not_crown_a_platform_that_only_won_the_alphabet(tmp_path: Path) -> None:
    """`primary ranked` read as a measurement. With equal weights it is `sorted()` on the name."""

    result = build_profile_recommendation(_clone_with_two_platforms(tmp_path))
    notes = " ".join(result.notes)

    assert "primary ranked" not in notes, notes


def test_the_note_still_names_every_platform_it_found(tmp_path: Path) -> None:
    """Removing a false claim must not remove the true information underneath it."""

    result = build_profile_recommendation(_clone_with_two_platforms(tmp_path))
    notes = " ".join(result.notes)

    assert "GitHub" in notes, notes
    assert "Azure" in notes, notes


def test_the_note_explains_what_actually_decides_the_order(tmp_path: Path) -> None:
    result = build_profile_recommendation(_clone_with_two_platforms(tmp_path))
    notes = " ".join(result.notes)

    assert "fit" in notes.lower(), notes


def test_a_single_platform_clone_gets_no_multi_platform_note(tmp_path: Path) -> None:
    """The note only exists to explain an ordering, so one platform needs none of it."""

    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("on: push\njobs: {}\n", encoding="utf-8")

    notes = " ".join(build_profile_recommendation(tmp_path).notes)

    assert "Multiple CI platforms" not in notes, notes
