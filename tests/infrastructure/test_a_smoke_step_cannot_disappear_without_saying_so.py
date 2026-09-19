"""A step the consumer smoke did not run has to appear in the summary as not run.

One `add()` call in `scripts/consumer_smoke.py` sat under `if (repo_root /
invalid_wf).is_dir():`. With the fixture absent the step did not run, nothing recorded
that, and the summary still reported `all_expected_matched: true` over a step list that
was one shorter. Same shape as a gate whose ruleset is empty: green because it checked
nothing, and the flag that says so is worded as though it had.

The fixture is present in a checkout, so this is not an adopter-facing defect. The sdist
ships neither `scripts/` nor `tests/`, which was checked rather than assumed, so nobody
runs the script without the fixture by accident. What it protects against is a rename:
move or delete that directory and the gate quietly loses a step while every signal it
emits stays green.

The last test is the one meant to outlive this change. It reads the script's own syntax
tree for `add()` calls under a condition and requires each such branch to record a skip,
so the next conditional step is caught without anyone remembering this one.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from types import ModuleType

import pytest
from tests.conftest import ROOT

_SCRIPT_PATH = ROOT / "scripts" / "consumer_smoke.py"


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("consumer_smoke", _SCRIPT_PATH)
    assert spec and spec.loader, "could not locate scripts/consumer_smoke.py"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def _tree() -> ast.Module:
    return ast.parse(_SCRIPT_PATH.read_text(encoding="utf-8"))


def test_the_fixture_the_conditional_step_needs_is_in_the_repository() -> None:
    """Otherwise this whole family is about a step that never runs at all."""

    assert (ROOT / "tests" / "fixtures" / "repositories" / "invalid-workflow-target").is_dir()


def test_a_skipped_step_carries_no_expectation() -> None:
    """`expected_exit_code=None` is how this file already says "not checked"."""

    step = _script().SmokeStep(
        name="invalid_fail_on_degraded",
        argv=[],
        exit_code=0,
        expected_exit_code=None,
        stderr_excerpt="skipped: no fixture at tests/fixtures/repositories/invalid-workflow-target",
    )

    assert step.expected_exit_code is None, "a skip that carries an expectation can read as a pass"
    assert step.stderr_excerpt.startswith("skipped: "), "the row has to say why it did not run"


@pytest.mark.parametrize(
    "needle",
    [
        pytest.param('"skipped_steps": skipped_steps', id="named-in-the-json"),
        pytest.param("Steps skipped:", id="named-in-the-markdown"),
        pytest.param("Smoke steps skipped:", id="printed-on-stderr"),
    ],
)
def test_the_summary_says_how_many_steps_did_not_run(needle: str) -> None:
    """Three surfaces, because a reader uses whichever one is in front of them.

    `all_expected_matched` is true over the steps that ran. On its own that sentence is
    the defect, so each place it appears now has the count beside it.
    """

    assert needle in _SCRIPT_PATH.read_text(encoding="utf-8")


def test_the_skip_count_is_derived_from_the_steps_not_maintained_by_hand() -> None:
    """A separately-maintained counter is the next silent divergence."""

    source = _SCRIPT_PATH.read_text(encoding="utf-8")

    assert "skipped_steps = [step.name for step in steps if step.expected_exit_code is None]" in source


def test_every_conditional_step_records_a_skip_on_the_other_branch() -> None:
    """Derived from the script, so the next conditional step is caught by itself.

    Walks for `add(...)` or `add_console(...)` reached only under an `if`, and requires
    that same `if` to call `skipped(...)` on its other branch. A list of known
    conditional steps is what let this one sit unnoticed.
    """

    adders = {"add", "add_console"}

    def calls_in(nodes: list[ast.stmt], names: set[str]) -> bool:
        return any(
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in names
            for body in nodes
            for node in ast.walk(body)
        )

    offenders: list[str] = []
    for node in ast.walk(_tree()):
        if not isinstance(node, ast.If):
            continue
        for branch, other in ((node.body, node.orelse), (node.orelse, node.body)):
            if not calls_in(branch, adders):
                continue
            if not calls_in(other, {"skipped"}):
                offenders.append(f"line {node.lineno}")

    assert not offenders, (
        "a smoke step runs only under a condition and the other branch records nothing, so "
        f"the summary can shrink without saying so ({', '.join(sorted(set(offenders)))}). "
        "Call skipped(<name>, <why>) on the branch that does not run it."
    )


def test_the_guard_above_would_notice_a_new_silent_step() -> None:
    """The mutation, in-process: a conditional adder with no else must be flagged."""

    tree = ast.parse("if fixture.is_dir():\n    add('x', ['-m', 'oss_policy_kit'], 0)\n")
    adders = {"add", "add_console"}

    def calls_in(nodes: list[ast.stmt], names: set[str]) -> bool:
        return any(
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in names
            for body in nodes
            for node in ast.walk(body)
        )

    node = tree.body[0]
    assert isinstance(node, ast.If)
    assert calls_in(node.body, adders), "the detection the test above relies on does not fire"
    assert not calls_in(node.orelse, {"skipped"}), "an empty else must not count as recording a skip"


def test_the_json_summary_round_trips_a_skipped_step() -> None:
    """`asdict` has to carry the field, or the JSON says nothing whatever the code does."""

    from dataclasses import asdict

    step = _script().SmokeStep(
        name="invalid_fail_on_degraded", argv=[], exit_code=0, expected_exit_code=None, stderr_excerpt="skipped: x"
    )

    row = json.loads(json.dumps(asdict(step)))

    assert row["expected_exit_code"] is None
    assert row["stderr_excerpt"] == "skipped: x"
