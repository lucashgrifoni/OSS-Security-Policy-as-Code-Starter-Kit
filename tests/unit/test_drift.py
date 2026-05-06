"""Tests for :mod:`oss_policy_kit.application.drift`."""

from __future__ import annotations

from oss_policy_kit.application.drift import compute_drift
from oss_policy_kit.application.reporting import render_drift_report


def _row(cid: str, title: str, status: str) -> dict:
    return {
        "control_id": cid,
        "title": title,
        "category": "x",
        "status": status,
        "lifecycle": "stable",
        "profile": "p",
        "evidence_sources": [],
        "confidence": "high",
        "reason": "r",
        "remediation": "m",
        "owner": None,
        "expires_at": None,
        "extra": {},
        "waiver": None,
        "evidence_collection_method": "static",
    }


def test_no_changes_empty_drift() -> None:
    rows = [_row("A", "t", "pass"), _row("B", "u", "fail")]
    before = {"results": rows, "kit_version": "1"}
    after = {"results": list(rows), "kit_version": "2"}
    d = compute_drift(before, after)
    assert not d.regressions and not d.improvements
    assert not d.has_regressions


def test_regression_pass_to_fail() -> None:
    before = {"results": [_row("X", "xt", "pass")], "kit_version": "1"}
    after = {"results": [_row("X", "xt", "fail")], "kit_version": "2"}
    d = compute_drift(before, after)
    assert len(d.regressions) == 1
    assert d.regressions[0].control_id == "X"
    assert d.has_regressions


def test_improvement_fail_to_pass() -> None:
    before = {"results": [_row("Y", "yt", "fail")], "kit_version": "1"}
    after = {"results": [_row("Y", "yt", "pass")], "kit_version": "2"}
    d = compute_drift(before, after)
    assert len(d.improvements) == 1
    assert not d.has_regressions


def test_improvement_fail_to_self_attested() -> None:
    before = {"results": [_row("Y2", "y2", "fail")], "kit_version": "1"}
    after = {"results": [_row("Y2", "y2", "self-attested")], "kit_version": "2"}
    d = compute_drift(before, after)
    assert len(d.improvements) == 1
    assert not d.has_regressions


def test_self_attested_to_fail_is_regression() -> None:
    before = {"results": [_row("Z", "zt", "self-attested")], "kit_version": "1"}
    after = {"results": [_row("Z", "zt", "fail")], "kit_version": "2"}
    d = compute_drift(before, after)
    assert d.has_regressions


def test_new_control_in_after() -> None:
    before = {"results": [_row("A", "a", "pass")], "kit_version": "1"}
    after = {"results": [_row("A", "a", "pass"), _row("B", "b", "pass")], "kit_version": "2"}
    d = compute_drift(before, after)
    assert d.new_controls == ["B"]


def test_removed_control() -> None:
    before = {"results": [_row("A", "a", "pass"), _row("B", "b", "pass")], "kit_version": "1"}
    after = {"results": [_row("A", "a", "pass")], "kit_version": "2"}
    d = compute_drift(before, after)
    assert d.removed_controls == ["B"]


def test_expired_waiver() -> None:
    w_before = _row("W", "w", "pass")
    w_before["waiver"] = {"control_id": "W", "justification": "x", "owner": "o", "status": "active"}
    before = {"results": [w_before], "kit_version": "1"}
    after = {"results": [_row("W", "w", "pass")], "kit_version": "2"}
    d = compute_drift(before, after)
    assert "W" in d.expired_waivers


def test_render_drift_json_roundtrip_keys() -> None:
    before = {"results": [_row("X", "xt", "pass")], "kit_version": "1", "profile_id": "p1"}
    after = {"results": [_row("X", "xt", "fail")], "kit_version": "2", "profile_id": "p1"}
    d = compute_drift(before, after)
    out = render_drift_report(d, "json")
    assert "has_regressions" in out
    assert "regressions" in out
    assert "profile_mismatch" in out
    assert "before_profile_id" in out
    assert "after_profile_id" in out


def test_render_drift_table_without_color_has_no_ansi_sequences() -> None:
    before = {"results": [_row("X", "xt", "pass")], "kit_version": "1", "profile_id": "p1"}
    after = {"results": [_row("X", "xt", "fail")], "kit_version": "2", "profile_id": "p1"}
    d = compute_drift(before, after)
    out = render_drift_report(d, "table", color=False)
    assert "\x1b[" not in out


def test_compute_drift_extracts_profile_id_from_v1_nested_object() -> None:
    """``reports/1.0`` nests profile data under ``profile.id`` — drift must read it."""

    before = {
        "results": [_row("X", "xt", "pass")],
        "kit_version": "5",
        "profile": {"id": "github-level-1", "title": "GitHub OSS starter baseline (level 1)"},
    }
    after = {
        "results": [_row("X", "xt", "pass")],
        "kit_version": "5",
        "profile": {"id": "github-level-1", "title": "GitHub OSS starter baseline (level 1)"},
    }
    d = compute_drift(before, after)
    assert d.before_profile_id == "github-level-1"
    assert d.after_profile_id == "github-level-1"
    assert d.profile_mismatch is False


def test_compute_drift_extracts_profile_id_from_v03_flat_field() -> None:
    """``reports/0.3`` keeps the flat ``profile_id`` at the root — drift must still read it."""

    before = {
        "results": [_row("X", "xt", "pass")],
        "kit_version": "5",
        "profile_id": "github-level-1",
    }
    after = {
        "results": [_row("X", "xt", "pass")],
        "kit_version": "5",
        "profile_id": "github-level-1",
    }
    d = compute_drift(before, after)
    assert d.before_profile_id == "github-level-1"
    assert d.after_profile_id == "github-level-1"
    assert d.profile_mismatch is False


def test_compute_drift_flags_profile_mismatch_across_versions_v1() -> None:
    """Different ``profile.id`` in two ``reports/1.0`` payloads sets ``profile_mismatch=True``."""

    before = {
        "results": [_row("X", "xt", "pass")],
        "profile": {"id": "github-level-1"},
    }
    after = {
        "results": [_row("X", "xt", "pass")],
        "profile": {"id": "github-level-2"},
    }
    d = compute_drift(before, after)
    assert d.before_profile_id == "github-level-1"
    assert d.after_profile_id == "github-level-2"
    assert d.profile_mismatch is True


def test_compute_drift_flags_profile_mismatch_across_versions_v03() -> None:
    """Different ``profile_id`` in two ``reports/0.3`` payloads sets ``profile_mismatch=True``."""

    before = {"results": [_row("X", "xt", "pass")], "profile_id": "azure-level-1"}
    after = {"results": [_row("X", "xt", "pass")], "profile_id": "aws-level-1"}
    d = compute_drift(before, after)
    assert d.before_profile_id == "azure-level-1"
    assert d.after_profile_id == "aws-level-1"
    assert d.profile_mismatch is True


def test_compute_drift_handles_legacy_report_without_profile() -> None:
    """A report missing both shapes must produce ``None`` profile ids and no false mismatch."""

    before = {"results": [_row("X", "xt", "pass")], "kit_version": "1"}
    after = {"results": [_row("X", "xt", "pass")], "kit_version": "2"}
    d = compute_drift(before, after)
    assert d.before_profile_id is None
    assert d.after_profile_id is None
    assert d.profile_mismatch is False


def test_compute_drift_v1_takes_precedence_over_legacy_flat_when_both_present() -> None:
    """If a payload carries both shapes (mixed/legacy migration), prefer ``profile.id``.

    This guards against drift accidentally reading the wrong field on a hybrid payload
    produced by a tool that emits both keys for safety.
    """

    before = {
        "results": [_row("X", "xt", "pass")],
        "profile": {"id": "github-level-3"},
        "profile_id": "github-level-1",
    }
    after = {
        "results": [_row("X", "xt", "pass")],
        "profile": {"id": "github-level-3"},
        "profile_id": "github-level-1",
    }
    d = compute_drift(before, after)
    assert d.before_profile_id == "github-level-3"
    assert d.after_profile_id == "github-level-3"
    assert d.profile_mismatch is False


def test_profile_mismatch_detected() -> None:
    before = {"profile_id": "github-level-1", "results": [], "kit_version": "1"}
    after = {"profile_id": "github-level-2", "results": [], "kit_version": "2"}
    report = compute_drift(before, after)
    assert report.profile_mismatch is True
    assert report.before_profile_id == "github-level-1"
    assert report.after_profile_id == "github-level-2"


def test_same_profile_no_mismatch() -> None:
    before = {"profile_id": "github-level-1", "results": [], "kit_version": "1"}
    after = {"profile_id": "github-level-1", "results": [], "kit_version": "2"}
    report = compute_drift(before, after)
    assert report.profile_mismatch is False
