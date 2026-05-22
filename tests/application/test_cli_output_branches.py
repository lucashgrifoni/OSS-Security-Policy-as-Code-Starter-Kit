"""Branch coverage for ``application.cli_output`` — plain summary path, waiver note, fail-on policy."""

from __future__ import annotations

import json

import pytest

from oss_policy_kit.application import cli_output as co
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport, WeightedScore


def _result(cid: str, status: ControlStatus, reason: str = "") -> ControlResult:
    return ControlResult(
        control_id=cid, title=f"{cid} title", category="governance", status=status,
        profile="github-level-1", evidence_sources=[], confidence="high",
        reason=reason, remediation="do it",
    )


def _report(**over: object) -> ExecutionReport:
    base: dict[str, object] = {
        "schema_version": "https://example/reports/0.2",
        "generated_at": "2026-04-18T00:00:00Z",
        "kit_version": "6.1.0",
        "target_path": "C:/tmp/repo",
        "profile_id": "github-level-1",
        "profile_title": "GitHub Level 1",
        "summary_by_status": {"pass": 1, "fail": 1, "manual-review-required": 1},
        "results": [
            _result("GOV-SEC-001", ControlStatus.PASS),
            _result("CI-PIN-008", ControlStatus.FAIL, "Mutable refs detected in workflows."),
            _result("GOV-MR-002", ControlStatus.MANUAL_REVIEW_REQUIRED, "Needs manual check."),
        ],
        "operational_warnings": ["w1"],
        "weighted_score": WeightedScore(earned=7, possible=10, percent=70.0),
    }
    base.update(over)
    return ExecutionReport(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# fail_on_violated
# --------------------------------------------------------------------------- #


def test_fail_on_violated_policies() -> None:
    assert co.fail_on_violated("none", {"fail": 5}) is False
    assert co.fail_on_violated("fail", {"fail": 1}) is True
    assert co.fail_on_violated("fail", {"fail": 0}) is False
    assert co.fail_on_violated("degraded", {"manual-review-required": 1}) is True
    assert co.fail_on_violated("degraded", {"fail": 0, "manual-review-required": 0}) is False
    with pytest.raises(ValueError, match="Unknown fail-on policy"):
        co.fail_on_violated("bogus", {})  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# plain summary path (non-TTY stdout)
# --------------------------------------------------------------------------- #


def test_print_stdout_summary_plain(capsys: pytest.CaptureFixture[str]) -> None:
    co.print_stdout_summary(_report(), output_format="human")
    out = capsys.readouterr().out
    assert "Profile: github-level-1" in out
    assert "Weighted score: 7/10 (70.0%)" in out
    assert "Top gaps:" in out
    assert "Suggested next step:" in out


def test_print_stdout_summary_plain_with_waiver(capsys: pytest.CaptureFixture[str]) -> None:
    co.print_stdout_summary(_report(external_waiver_path="C:/some/waivers.yaml"), output_format="human")
    out = capsys.readouterr().out
    assert "Waiver note:" in out
    assert "waivers.yaml" in out


def test_print_stdout_summary_plain_long_waiver_path(capsys: pytest.CaptureFixture[str]) -> None:
    co.print_stdout_summary(_report(external_waiver_path="C:/" + "x" * 300 + "/waivers.yaml"), output_format="human")
    assert "Waiver note:" in capsys.readouterr().out


def test_print_stdout_summary_gap_fallback_all_pass(capsys: pytest.CaptureFixture[str]) -> None:
    rpt = _report(
        summary_by_status={"pass": 2},
        results=[_result("GOV-SEC-001", ControlStatus.PASS), _result("GOV-SEC-002", ControlStatus.PASS)],
    )
    co.print_stdout_summary(rpt, output_format="human")
    assert "Top gaps:" in capsys.readouterr().out  # fallback path produces section regardless


# --------------------------------------------------------------------------- #
# json summary path
# --------------------------------------------------------------------------- #


def test_print_stdout_summary_json(capsys: pytest.CaptureFixture[str]) -> None:
    co.print_stdout_summary(_report(scorecard_supplemental={"score": 8.0}), output_format="json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["profile_id"] == "github-level-1"
    assert payload["controls_total"] == 3
    assert payload["weighted_score"]["percent"] == 70.0
    assert payload["scorecard_supplemental"] == {"score": 8.0}


def test_human_primary_gap_line_truncation() -> None:
    r = _result("X", ControlStatus.FAIL, "y" * 300)
    assert co._human_primary_gap_line(r, max_len=40).endswith("...")
    r2 = _result("X", ControlStatus.FAIL, "")
    assert "action required" in co._human_primary_gap_line(r2, max_len=40)
