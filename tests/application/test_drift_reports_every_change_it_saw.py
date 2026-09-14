"""A control that started failing was reported as "no status changes on shared controls".

Measured against the built wheel, one repository evaluated twice with `SECURITY.md` deleted
in between:

    before  GOV-DISC-013 = UNKNOWN
    after   GOV-DISC-013 = FAIL

    diff-reports --format json
      regressions:  []
      improvements: []
      "GOV-DISC-013" anywhere in the payload: False

`diff-reports` is the command an adopter wires into CI to ask whether posture got worse, and
`--fail-on-regression` is on by default.

Two defects, stacked.

`UNKNOWN -> FAIL` was not a regression. `_is_positive` excludes UNKNOWN for a sound reason:
`PASS -> UNKNOWN` is evidence that went unreadable, not a failure, and gating on it would
break builds on flaky evidence. That argument is about one direction and was applied to both.
A control that has moved from "could not determine" to "definitely fails" is a definite new
failure. The rule is now: any move INTO a failing state.

Worse, a change that was neither regression nor improvement fell out of the report entirely.
There was no third bucket, so it vanished from the JSON, the Markdown and the table -- which
then printed "(no status changes on shared controls)" over a report where controls had moved.
A machine consumer could not recover it either, so the wrong answer was the complete answer.

Keeping a change out of the GATE is a design choice worth defending. Keeping it out of the
REPORT is not, and one code path did both.
"""

from __future__ import annotations

from typing import Any

import pytest

from oss_policy_kit.application.drift import _classify_status_changes

#: (before, after, expected bucket). The whole contract in one table.
TRANSITIONS = [
    ("PASS", "FAIL", "regression"),
    ("ATTESTED", "FAIL", "regression"),
    ("SELF_ATTESTED", "FAIL", "regression"),
    # The defect: a control that has started definitely failing, from any non-failing state.
    ("UNKNOWN", "FAIL", "regression"),
    ("NOT_APPLICABLE", "FAIL", "regression"),
    ("WAIVED", "FAIL", "regression"),
    ("FAIL", "PASS", "improvement"),
    ("FAIL", "ATTESTED", "improvement"),
    # Not a regression, deliberately: evidence that went unreadable is not a failure, and
    # gating on it would break builds on flaky evidence. It must still be reported.
    ("PASS", "UNKNOWN", "other"),
    ("PASS", "WAIVED", "other"),
    ("PASS", "NOT_APPLICABLE", "other"),
    ("FAIL", "UNKNOWN", "other"),
    ("UNKNOWN", "NOT_APPLICABLE", "other"),
]


def _row(state: str) -> dict[str, Any]:
    return {"state": state, "title": "a control"}


def _bucket(before: str, after: str) -> str:
    regressions, improvements, other = _classify_status_changes({"C": _row(before)}, {"C": _row(after)}, {"C"})
    if regressions:
        return "regression"
    if improvements:
        return "improvement"
    return "other" if other else "dropped"


@pytest.mark.parametrize(("before", "after", "expected"), TRANSITIONS, ids=[f"{b}->{a}" for b, a, _ in TRANSITIONS])
def test_every_transition_lands_in_a_bucket(before: str, after: str, expected: str) -> None:
    assert _bucket(before, after) == expected


def test_no_transition_at_all_is_ever_dropped() -> None:
    """The property under everything else: a change that happened must be a change that shows.

    Enumerated rather than sampled, because the defect was precisely a pair nobody listed.
    """

    states = ["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "WAIVED", "ATTESTED", "SELF_ATTESTED"]
    dropped = [
        (before, after)
        for before in states
        for after in states
        if before != after and _bucket(before, after) == "dropped"
    ]

    assert dropped == [], f"these state changes are invisible in every surface: {dropped}"


def test_an_unchanged_control_stays_out_of_all_three_buckets() -> None:
    """The other direction: reporting a change that did not happen is its own defect."""

    for state in ("PASS", "FAIL", "UNKNOWN", "WAIVED"):
        regressions, improvements, other = _classify_status_changes({"C": _row(state)}, {"C": _row(state)}, {"C"})
        assert (regressions, improvements, other) == ([], [], [])


# --- the surfaces --------------------------------------------------------------------------------


def _report_with(before: str, after: str):
    from oss_policy_kit.application.drift import DriftReport

    regressions, improvements, other = _classify_status_changes({"C": _row(before)}, {"C": _row(after)}, {"C"})
    return DriftReport(
        before_path="b.json",
        after_path="a.json",
        before_kit_version="1",
        after_kit_version="1",
        regressions=regressions,
        improvements=improvements,
        other_changes=other,
        has_regressions=bool(regressions),
    )


def test_the_json_payload_carries_the_third_bucket() -> None:
    """The surface that matters most: a CI consumer had no field to read this from."""

    from oss_policy_kit.application.reporting import _drift_report_dict

    payload = _drift_report_dict(_report_with("PASS", "WAIVED"))

    assert [d["control_id"] for d in payload["other_changes"]] == ["C"]
    assert payload["has_regressions"] is False, "it moved, and it did not cross the gate line"


def test_the_markdown_names_the_other_changes() -> None:
    from oss_policy_kit.application.reporting import _drift_markdown

    text = _drift_markdown(_report_with("PASS", "UNKNOWN"))

    assert "Other status changes" in text
    assert "`C`" in text


def test_no_status_changes_is_only_printed_when_there_are_none() -> None:
    """The sentence that was false. It may only appear over a genuinely unchanged pair."""

    from oss_policy_kit.application.reporting import _drift_markdown

    moved = _drift_markdown(_report_with("PASS", "WAIVED"))
    still = _drift_markdown(_report_with("PASS", "PASS"))

    assert "**Other status changes**: 1" in moved
    assert "**Other status changes**: 0" in still


def test_the_table_shows_the_third_bucket_and_drops_the_false_sentence() -> None:
    """The table is the default surface, and it was the one printing the false sentence."""

    from oss_policy_kit.application.reporting import render_drift_report

    moved = render_drift_report(_report_with("PASS", "WAIVED"), "table", color=False)
    still = render_drift_report(_report_with("PASS", "PASS"), "table", color=False)

    assert "changed" in moved
    assert "no status changes on shared controls" not in moved
    assert "no status changes on shared controls" in still


# --- and end to end, from two report payloads ----------------------------------------------------


def _report_json(state: str) -> dict[str, Any]:
    return {
        "report_contract": "reports/2.0",
        "kit_version": "10.0.21",
        "controls": [{"id": "GOV-DISC-013", "title": "Disclosure policy", "state": state}],
    }


def test_a_control_that_started_failing_trips_the_gate() -> None:
    """The reproduction, at the level the CLI works at: `--fail-on-regression` must fire."""

    from oss_policy_kit.application.drift import compute_drift

    report = compute_drift(_report_json("UNKNOWN"), _report_json("FAIL"))

    assert report.has_regressions is True
    assert [d.control_id for d in report.regressions] == ["GOV-DISC-013"]


def test_evidence_that_went_unreadable_still_does_not_trip_the_gate() -> None:
    """The direction the original rule was written for, and it has to keep holding.

    `PASS -> UNKNOWN` is evidence the run could not read (ADR-045), not a failure. If this
    started failing builds, every flaky filesystem would look like a posture regression.
    """

    from oss_policy_kit.application.drift import compute_drift

    report = compute_drift(_report_json("PASS"), _report_json("UNKNOWN"))

    assert report.has_regressions is False
    assert [d.control_id for d in report.other_changes] == ["GOV-DISC-013"], "and it is still reported"
