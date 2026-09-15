"""A waiver naming a control that does not exist was a silent no-op.

Measured against the built wheel in a clean room:

    waivers.yaml:  control_id: NAO-EXISTE-999
    evaluate --profile github-level-1 --waivers ghost.yaml

      operational_warnings   []
      "NAO-EXISTE-999" in stdout, Markdown, JSON, or --verbose:  nowhere

The loader in `waivers.py` warns on every other way an entry can fail to apply, and the
operator is told each time:

    not a mapping              "Waiver entry 0 ignored: not a mapping"
    missing control_id         "Waiver entry 0 ignored: missing control_id"
    empty justification        "Waiver for X ignored: empty justification"
    empty owner                "Waiver for X ignored: empty owner"
    malformed expires_at       "Waiver for X ignored: expires_at=... is not a date"
    expired                    "Waiver for X ignored: expired at 2020-01-01"
    a typo in the control id   nothing at all

The last one is the likeliest of them, and it was the only one that said nothing.

Nothing unsafe happened, which is why this warns rather than fails: the control kept its FAIL,
the pipeline stayed red, and nobody was told a control passed that did not. What it cost is an
operator who believes a control is waived when it is not.

TWO CASES, ONE WARNED. A waiver file is shared across profiles, so an id that exists in the
catalog but not in the profile being evaluated is ordinary -- warning on it would fire on every
run of every other profile, and a warning that fires on correct input is one people learn to
ignore. An id in no catalog entry can never apply to anything, anywhere.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.engine import _unknown_waiver_warnings
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus, WaiverRecord

#: A control id that is in the catalog, and one that is not.
REAL_OFF_PROFILE = "K8S-PSS-001"
GHOST = "NAO-EXISTE-999"


@pytest.fixture(scope="module")
def catalog() -> dict:
    return load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")


def _waiver(control_id: str) -> WaiverRecord:
    return WaiverRecord(
        control_id=control_id,
        justification="accepted by the owning team",
        owner="sec-team",
        status="accepted",
        expires_at=None,
        applies_to=None,
    )


def test_a_waiver_for_a_control_that_does_not_exist_is_named(catalog: dict) -> None:
    """The defect. This produced no warning on any surface."""

    warnings = _unknown_waiver_warnings({GHOST: _waiver(GHOST)}, catalog)

    assert len(warnings) == 1
    assert GHOST in warnings[0]
    assert "no such control id" in warnings[0]


def test_a_real_control_outside_this_profile_stays_silent(catalog: dict) -> None:
    """The half that decides whether anyone keeps the guard switched on.

    `K8S-PSS-001` is a real control. A waiver file carrying it is correct input when the run
    happens to evaluate a GitHub profile, and warning there would fire on every run of every
    other profile.
    """

    assert REAL_OFF_PROFILE in catalog, "the fixture is wrong: this control has to be real"

    assert _unknown_waiver_warnings({REAL_OFF_PROFILE: _waiver(REAL_OFF_PROFILE)}, catalog) == []


def test_no_waivers_produces_no_warnings(catalog: dict) -> None:
    assert _unknown_waiver_warnings({}, catalog) == []


def test_several_unknown_ids_are_all_named_and_ordered(catalog: dict) -> None:
    """Sorted, because a dict's order is the file's order and a report should not wobble."""

    ids = ["ZZZ-1", "AAA-2", "MMM-3"]
    warnings = _unknown_waiver_warnings({i: _waiver(i) for i in ids}, catalog)

    assert [w.split()[2] for w in warnings] == ["AAA-2", "MMM-3", "ZZZ-1"]


def test_the_warning_tells_the_operator_where_to_look(catalog: dict) -> None:
    warning = _unknown_waiver_warnings({GHOST: _waiver(GHOST)}, catalog)[0]

    assert "profiles" in warning, "an operator who typo'd an id needs the command that lists them"


# --- end to end, through the engine ---------------------------------------------------------------


def _repo(tmp_path: Path, waiver_body: str) -> Path:
    (tmp_path / "README.md").write_text("# app\n", encoding="utf-8")
    (tmp_path / "waivers.yaml").write_text(waiver_body, encoding="utf-8")
    return tmp_path


GHOST_FILE = f"""version: 1
waivers:
  - control_id: {GHOST}
    reason: "a typo nobody caught"
    owner: sec-team
    expires_at: "2099-01-01"
"""


def _evaluate(root: Path, *, with_waivers: bool):
    from oss_policy_kit.application.engine import evaluate_repository
    from oss_policy_kit.application.waivers import parse_waivers_file

    kit = bundled_kit_root()
    return evaluate_repository(
        repo_root=root,
        profile=load_profile_by_id(kit, "github-level-1"),
        catalog=load_catalog(kit / "controls" / "catalog.yaml"),
        waiver_outcome=parse_waivers_file(root / "waivers.yaml") if with_waivers else None,
        scorecard=None,
    )


def test_the_warning_reaches_the_report(tmp_path: Path) -> None:
    """The surface that matters: a CI consumer reads `operational_warnings`, not a docstring."""

    report = _evaluate(_repo(tmp_path, GHOST_FILE), with_waivers=True)

    assert any(GHOST in w for w in report.operational_warnings), report.operational_warnings


def test_the_control_keeps_its_verdict(tmp_path: Path) -> None:
    """A warning, never a verdict change.

    The waiver matched nothing, so nothing was waived and every control answers exactly what it
    answered before. Turning this into a failure would punish a typo with a red pipeline on a
    repository whose posture did not change.
    """

    root = _repo(tmp_path, GHOST_FILE)
    with_ghost = _evaluate(root, with_waivers=True)
    without = _evaluate(root, with_waivers=False)

    assert {r.control_id: r.status for r in with_ghost.results} == {r.control_id: r.status for r in without.results}
    assert any(r.status == ControlStatus.FAIL for r in with_ghost.results), (
        "the fixture has to actually fail something, or this proves nothing"
    )
