"""The 100% coverage floor lives in one workflow step, and stays that way.

This repository reached 100% line coverage and gates on it, but not the way a reader would
guess. The quality job runs pytest twice:

    pytest tests --ignore=tests/property  --cov=... --cov-report=  --cov-fail-under=0
    pytest tests/property/               --cov=... --cov-append    --cov-fail-under=100

Coverage accumulates across the two with ``--cov-append``, and the floor is on the *second*
step alone. So the whole gate rests on one flag in one step of one workflow, and deleting it
is invisible: the suite stays green, the number stops being checked, and nothing says so.
Running `python -m pytest` by itself measures no coverage at all and therefore cannot fail
that floor either, which is what made the omission easy to miss in CONTRIBUTING.md.

The same shape has cost this repository twice before -- a hygiene gate the CHANGELOG called a
release gate and which ran nowhere, and a drift check that sat green through three majors --
so the arrangement gets a test rather than a comment. Written in the shape of
``test_the_rego_fidelity_check_still_runs_in_ci.py``, which guards the neighbouring step.

The workflow is parsed with ``yaml.safe_load`` rather than grepped: a commented-out step is
not in the parsed document at all, so it cannot earn a pass here, while a raw-text search
would have accepted one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "github-ci-cd.yml"

#: The floor this project gates on. Named here so a change to it is a visible diff in this
#: file too, rather than a silent edit under a test that only asks "some floor".
_REQUIRED_FLOOR = "--cov-fail-under=100"


def _quality_steps() -> list[dict[str, Any]]:
    doc = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    job = doc["jobs"]["quality"]
    return [s for s in job["steps"] if isinstance(s, dict)]


def _run_lines(step: dict[str, Any]) -> str:
    return str(step.get("run") or "")


def test_the_workflow_parses_into_steps_this_test_can_read() -> None:
    """Anti-vacuum: a sweep over an empty step list passes and proves nothing."""

    steps = _quality_steps()

    assert len(steps) > 5
    assert any("ruff" in _run_lines(s) for s in steps), "a step this test does not care about is missing"


def test_exactly_one_step_carries_the_coverage_floor() -> None:
    carrying = [s for s in _quality_steps() if _REQUIRED_FLOOR in _run_lines(s)]

    assert carrying, (
        f"no step in the quality job passes {_REQUIRED_FLOOR}. The coverage gate is gone: the "
        "suite will stay green while coverage falls, because the other pytest step passes "
        "--cov-fail-under=0 and a bare `pytest` measures no coverage at all."
    )
    assert len(carrying) == 1, (
        "more than one step carries the floor; the append-then-check arrangement expects "
        "exactly one, and two would check a partial total"
    )


def test_the_floor_step_appends_to_the_first_run() -> None:
    """The floor is only meaningful over the accumulated total, not over the property tests."""

    floor_step = next(s for s in _quality_steps() if _REQUIRED_FLOOR in _run_lines(s))

    assert "--cov-append" in _run_lines(floor_step), (
        "the step carrying the floor does not append, so it would measure only the property "
        "tests and a 100% floor over a fraction of the suite is not the gate anyone intends"
    )


def test_a_first_step_produces_the_coverage_the_floor_then_checks() -> None:
    steps = _quality_steps()
    producing = [s for s in steps if "--cov=oss_policy_kit" in _run_lines(s) and "--cov-append" not in _run_lines(s)]

    assert producing, "no step starts the coverage run, so the appending step would have nothing to append to"


@pytest.mark.parametrize("not_a_floor", ["--cov-fail-under=0", "--cov-fail-under=99", ""])
def test_the_check_rejects_something_that_is_not_the_floor(not_a_floor: str) -> None:
    """The guard has to be able to fail. A substring test that matches anything is decorative."""

    assert _REQUIRED_FLOOR not in not_a_floor
