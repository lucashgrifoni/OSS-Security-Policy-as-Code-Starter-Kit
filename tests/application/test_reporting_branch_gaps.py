"""Branch-coverage gaps for application.reporting serialization + markdown helpers."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from oss_policy_kit.application import reporting as rp
from oss_policy_kit.domain.models import (
    ControlResult,
    ControlStatus,
    ExecutionReport,
    WaiverRecord,
    WeightedScore,
)


def _waived_result() -> ControlResult:
    return ControlResult(
        control_id="CI-PIN-008",
        title="pin actions",
        category="supply_chain",
        status=ControlStatus.WAIVED,
        profile="github-level-3",
        evidence_sources=["/abs/evidence.json"],
        confidence="medium",
        reason="waived | with pipe",
        remediation="pin | by sha",
        deprecation_note="superseded by CI-PIN-009",
        waiver=WaiverRecord(
            control_id="CI-PIN-008",
            justification="accepted risk",
            owner="appsec",
            status="active",
            expires_at=date(2027, 1, 1),
            applies_to=["CI-PIN-008"],
        ),
    )


def _rich_report(schema: str = "https://x/reports/0.3") -> ExecutionReport:
    return ExecutionReport(
        schema_version=schema,
        generated_at="2026-04-18T00:00:00Z",
        kit_version="6.1.0",
        target_path="C:/tmp/repo",
        profile_id="github-level-3",
        profile_title="Title",
        summary_by_status={"pass": 1, "waived": 1},
        results=[
            ControlResult(
                control_id="GOV-SEC-001",
                title="t",
                category="governance",
                status=ControlStatus.PASS,
                profile="github-level-3",
                evidence_sources=[],
                confidence="high",
                reason="ok",
                remediation="keep",
            ),
            _waived_result(),
        ],
        operational_warnings=[],
        scorecard_path="scorecard.json",
        scorecard_supplemental={
            "loaded": True,
            "check_count": 12,
            "influenced_control_ids": ["OSS-SCORECARD-001"],
            "workflows_satisfied_codeql_signal": True,
            "explanation": "scorecard influenced results",
        },
        external_waiver_path="waivers/external.yaml",
        weighted_score=WeightedScore(earned=7, possible=10, percent=70.0),
    )


# --------------------------------------------------------------------------- #
# _sanitize_target_path_for_payload — exception fallback (lines 65-67)
# --------------------------------------------------------------------------- #


def test_sanitize_target_path_fallback_on_invalid() -> None:
    out = rp._sanitize_target_path_for_payload("bad\x00path", include_absolute=False)
    assert isinstance(out, str)


# --------------------------------------------------------------------------- #
# _effective_schema_version overrides (lines 77, 79)
# --------------------------------------------------------------------------- #


def test_effective_schema_version_v02_and_v03() -> None:
    rep = _rich_report()
    assert rp._effective_schema_version(rep, "https://x/reports/0.2") == rp.REPORT_JSON_SCHEMA_URL_V0_2
    assert rp._effective_schema_version(rep, "https://x/reports/0.3") == rp.REPORT_JSON_SCHEMA_URL_V0_3


# --------------------------------------------------------------------------- #
# _profile_posture + _structural_bucket (lines 206, 284, 286)
# --------------------------------------------------------------------------- #


def test_profile_posture_release_track() -> None:
    assert rp._profile_posture("github-release-hardening-2") == "release_track"


def test_structural_bucket_azure_and_aws() -> None:
    assert "Azure" in rp._structural_bucket("AZ-PIPE-001")
    assert "AWS" in rp._structural_bucket("AWS-CB-001")


# --------------------------------------------------------------------------- #
# Serialization with waiver + deprecation_note (lines 351, 366, 375, 404)
# --------------------------------------------------------------------------- #


def test_report_to_dict_v03_includes_waiver_and_deprecation() -> None:
    payload = rp.report_to_dict(_rich_report())
    waived = next(r for r in payload["results"] if r["control_id"] == "CI-PIN-008")
    assert waived["waiver"]["owner"] == "appsec"
    assert waived["deprecation_note"] == "superseded by CI-PIN-009"


def test_report_to_dict_v1_includes_waiver_and_deprecation() -> None:
    payload = rp.report_to_dict_v1(_rich_report())
    waived = next(r for r in payload["results"] if r["control_id"] == "CI-PIN-008")
    assert waived["waiver"]["owner"] == "appsec"
    assert waived["deprecation_note"] == "superseded by CI-PIN-009"


def test_report_to_dict_v2_includes_waiver_and_deprecation() -> None:
    payload = rp.report_to_dict(_rich_report(), schema_version_override="https://x/reports/2.0")
    waived = next(r for r in payload["results"] if r["control_id"] == "CI-PIN-008")
    assert waived["waiver"] is not None
    assert waived.get("deprecation_note") == "superseded by CI-PIN-009"


# --------------------------------------------------------------------------- #
# Markdown report — scorecard, external waiver, waiver detail (666, 706-711,
# 761-768, 815-823)
# --------------------------------------------------------------------------- #


def test_write_markdown_report_rich(tmp_path: Path) -> None:
    out = tmp_path / "evaluation-report.md"
    rp.write_markdown_report(_rich_report(), out)
    text = out.read_text(encoding="utf-8")
    assert "Scorecard file" in text
    assert "External waiver file loaded" in text
    assert "Scorecard supplemental" in text
    assert "OSS-SCORECARD-001" in text
    assert "Expires" in text  # waiver expires_at detail line
    assert "/abs/evidence.json" in text  # evidence sources detail
