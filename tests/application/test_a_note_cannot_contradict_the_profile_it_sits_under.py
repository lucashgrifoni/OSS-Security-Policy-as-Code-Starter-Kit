"""`init` may not print a note that the profile it just chose makes false.

`init --target . --platform gitlab` printed, four lines apart:

    Profile:       gitlab-level-1 (source: platform_default)
    ...
    Notes:
      - Few strong platform signals were detected; defaulting to a conservative GitHub
        baseline profile.

No GitHub baseline was used. `build_profile_recommendation` runs for its signals even when
`--platform` settles the profile, and `init` forwarded its notes list unfiltered, so the
recommender's fallback sentence was printed underneath a profile that had not come from the
recommender. Same for `azure` and `aws` -- three of the four supported platforms, on the first
command a new adopter runs, and the config on disk disagrees with the note.

The note is kept where it is still true: `recommended` and `fallback` are exactly the two
sources that do come from the recommendation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.init_planner import build_init_plan
from oss_policy_kit.application.profile_hints import FEW_SIGNALS_FALLBACK_NOTE


def _bare_repo(tmp_path: Path) -> Path:
    """A clone with nothing that identifies a CI platform -- the condition for the note."""

    repo = tmp_path / "bare"
    repo.mkdir()
    (repo / "README.md").write_text("# bare\n", encoding="utf-8")
    return repo


def _plan(repo: Path, **over: object):
    """Every `build_init_plan` argument is keyword-only and required; this fills the rest in."""

    kwargs: dict[str, object] = {
        "target": repo,
        "forced_profile": None,
        "forced_platform": None,
        "fail_on": "fail",
        "output_dir": "./oss-policy-reports",
        "with_waivers": False,
        "with_evidence": False,
        "with_workflow": False,
        "force": False,
        "dry_run": True,
    }
    kwargs.update(over)
    return build_init_plan(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("platform", "expected_profile"),
    [("gitlab", "gitlab-level-1"), ("azure", "azure-level-1"), ("aws", "aws-level-1")],
)
def test_a_forced_platform_is_not_described_as_a_github_default(
    platform: str,
    expected_profile: str,
    tmp_path: Path,
) -> None:
    plan = _plan(_bare_repo(tmp_path), forced_platform=platform)

    assert plan.profile == expected_profile
    assert FEW_SIGNALS_FALLBACK_NOTE not in plan.notes, (
        f"init --platform {platform} chose {plan.profile} and still told the reader it was "
        f"defaulting to a GitHub baseline. Notes: {plan.notes}"
    )
    assert any(expected_profile in note for note in plan.notes), (
        f"the replacement note does not name the profile actually chosen. Notes: {plan.notes}"
    )


def test_a_forced_profile_is_not_described_as_a_github_default(tmp_path: Path) -> None:
    plan = _plan(_bare_repo(tmp_path), forced_profile="oss-publish-readiness-1")

    assert plan.profile == "oss-publish-readiness-1"
    assert FEW_SIGNALS_FALLBACK_NOTE not in plan.notes, plan.notes
    assert any("oss-publish-readiness-1" in note for note in plan.notes), plan.notes


def test_the_note_survives_when_it_is_the_truth(tmp_path: Path) -> None:
    """Without `--platform` or `--profile` the GitHub baseline really is the fallback.

    Deleting the filter must not be the way to make the tests above pass.
    """

    plan = _plan(_bare_repo(tmp_path))

    assert plan.profile == "github-level-1"
    assert FEW_SIGNALS_FALLBACK_NOTE in plan.notes, (
        f"the fallback note was dropped from the run it describes. Notes: {plan.notes}"
    )
