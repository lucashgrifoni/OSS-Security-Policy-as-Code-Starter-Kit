"""The Rego fidelity check runs in CI, and stays that way.

``export-policy --format rego`` promises that the policy it writes is accepted by the
real interpreter. ``tests/cli/test_export_policy_command.py`` proves it, but only where
an ``opa`` binary is on PATH -- everywhere else the test calls ``pytest.skip`` and the
run stays green having verified nothing. The quality job answers that by installing opa
from a pinned release asset whose SHA-256 it checks before use.

That arrangement is one workflow edit away from disappearing, and its disappearance is
invisible: a removed install step turns the Rego test into a skip, and a skip does not
fail a build. The repository has paid for this shape twice already -- a hygiene gate the
CHANGELOG called a release gate that ran nowhere, and a drift check that sat green
through three major versions -- so the install step gets a test rather than a comment.

The workflow is read with ``yaml.safe_load`` rather than grepped. A commented-out step
is not in the parsed document at all, so it cannot earn a pass here; a raw-text search
would have accepted one. Three sanity assertions come with the check, because a sweep
that finds nothing passes for the wrong reason just as easily as one that finds
everything: the job must parse into a non-empty step list, a step this file does not
otherwise care about must be visible in it, and the digest pattern must reject a string
that is not a digest.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "github-ci-cd.yml"

#: A hex SHA-256 as `sha256sum -c -` consumes it, with boundaries so that a longer hex
#: run (a git object id pasted by mistake, say) is not read as a digest.
_SHA256 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")

#: The opa release the job pins to. Named here so that a version bump is a visible diff
#: in this file too, rather than a silent change under a test that only asks "some opa".
_PINNED_OPA_URL_FRAGMENT = "open-policy-agent/opa/releases/download/v"

#: A floor under the number of steps found in the quality job. Without it, a change to
#: how the job is located could reduce this test to asserting things about an empty list.
#: The job held 18 steps on 2026-09-10; the floor is lower so that removing one unrelated
#: step does not fail the build for the wrong reason.
_MINIMUM_QUALITY_STEPS = 12


def _quality_steps() -> list[dict[str, Any]]:
    document = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    jobs = document["jobs"]
    assert "quality" in jobs, f"no quality job in {_WORKFLOW.name}; jobs are {sorted(jobs)}"
    steps = jobs["quality"]["steps"]
    assert isinstance(steps, list), f"quality steps parsed as {type(steps).__name__}, not a list"
    return [step for step in steps if isinstance(step, dict)]


def test_the_workflow_parses_into_steps_this_test_can_see() -> None:
    """Sanity: the sweep below reads a real step list, not an empty one."""

    steps = _quality_steps()
    assert len(steps) >= _MINIMUM_QUALITY_STEPS, f"only {len(steps)} steps parsed out of the quality job"

    names = [str(step.get("name", "")) for step in steps]
    assert any(name.startswith("Ruff check") for name in names), (
        f"a step this test does not otherwise care about went missing from the parse: {names}"
    )


def test_the_digest_pattern_rejects_a_string_that_is_not_a_digest() -> None:
    """Sanity: the assertion below can fail, so its passing means something."""

    assert _SHA256.search("0b3f152e61be276b70396cfbca49e39fc9d0c5089e0a8574e8f6a30f41a9187f")
    assert not _SHA256.search("not-a-digest")
    assert not _SHA256.search("deadbeef")


def test_the_quality_job_installs_opa_from_a_pinned_asset() -> None:
    """Without this step the Rego engine test is a skip on every CI leg."""

    installs = [step for step in _quality_steps() if _PINNED_OPA_URL_FRAGMENT in str(step.get("run", ""))]
    assert installs, (
        "the quality job no longer downloads opa from a pinned release. "
        "tests/cli/test_export_policy_command.py::test_generated_rego_checks_and_gates "
        "skips without it, so `export-policy --format rego` would ship unverified."
    )

    for step in installs:
        run = str(step["run"])
        assert _SHA256.search(run), f"the opa download in {step.get('name')!r} is not checked against a digest"
        assert "sha256sum -c" in run, f"the digest in {step.get('name')!r} is written down but never verified"
        assert "/latest/" not in run, f"the opa download in {step.get('name')!r} follows a moving tag"


def test_the_opa_install_states_which_legs_it_covers() -> None:
    """The step is Linux-only, and the honest reading of the guard depends on knowing it.

    The agent that installs opa has no Windows build. Asserting the condition keeps this
    test from being read as "opa runs on all three legs", which it does not.
    """

    installs = [step for step in _quality_steps() if _PINNED_OPA_URL_FRAGMENT in str(step.get("run", ""))]
    for step in installs:
        condition = str(step.get("if", ""))
        assert "runner.os" in condition and "Linux" in condition, (
            f"the opa install in {step.get('name')!r} no longer says which legs it covers: {condition!r}"
        )
