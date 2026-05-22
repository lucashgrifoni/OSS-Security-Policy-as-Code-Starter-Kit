"""Coverage for drift-report rendering in ``application.reporting``.

Exercises ``render_drift_report`` across all three formats (json / markdown /
table) with both a fully-populated report (regressions, improvements, new /
removed controls, expired waivers, profile mismatch) and an empty one.
"""

from __future__ import annotations

import json

from oss_policy_kit.application.drift import ControlDelta, DriftReport
from oss_policy_kit.application.reporting import (
    _control_delta_dict,
    _drift_report_dict,
    render_drift_report,
)


def _full_report() -> DriftReport:
    return DriftReport(
        before_path="before.json",
        after_path="after.json",
        before_kit_version="6.0.0",
        after_kit_version="6.1.0",
        regressions=[ControlDelta("C-1", "Ctrl 1", "PASS", "FAIL", True)],
        improvements=[ControlDelta("C-2", "Ctrl 2", "FAIL", "PASS", False)],
        new_controls=["C-NEW"],
        removed_controls=["C-OLD"],
        expired_waivers=["C-WAIVED"],
        has_regressions=True,
        profile_mismatch=True,
        before_profile_id="github-level-2",
        after_profile_id="github-level-3",
    )


def test_control_delta_dict() -> None:
    d = _control_delta_dict(ControlDelta("C-1", "T", "PASS", "FAIL", True))
    assert d == {
        "control_id": "C-1",
        "title": "T",
        "before_status": "PASS",
        "after_status": "FAIL",
        "is_regression": True,
    }


def test_drift_report_dict_roundtrips() -> None:
    payload = _drift_report_dict(_full_report())
    assert payload["has_regressions"] is True
    assert payload["new_controls"] == ["C-NEW"]
    assert len(payload["regressions"]) == 1


def test_render_drift_json() -> None:
    out = render_drift_report(_full_report(), "json")
    parsed = json.loads(out)
    assert parsed["after_kit_version"] == "6.1.0"
    assert parsed["profile_mismatch"] is True


def test_render_drift_markdown_full() -> None:
    out = render_drift_report(_full_report(), "markdown")
    assert "# Drift report" in out
    assert "differs from after profile" in out  # profile_mismatch note
    assert "## New controls in after" in out
    assert "## Removed controls" in out
    assert "## Expired waivers" in out
    assert "`C-1`" in out and "`C-2`" in out


def test_render_drift_markdown_alias_md_and_empty() -> None:
    empty = DriftReport(
        before_path="b", after_path="a", before_kit_version="1", after_kit_version="1"
    )
    out = render_drift_report(empty, "md")
    assert "# Drift report" in out
    assert "## New controls in after" not in out  # no optional sections


def test_render_drift_table_full_color() -> None:
    out = render_drift_report(_full_report(), "table", color=True)
    assert "regression" in out
    assert "New in after" in out
    assert "Removed" in out
    assert "Expired waivers" in out


def test_render_drift_table_empty_no_color() -> None:
    empty = DriftReport(
        before_path="b", after_path="a", before_kit_version="1", after_kit_version="1"
    )
    out = render_drift_report(empty, "table", color=False)
    assert "no status changes on shared controls" in out
