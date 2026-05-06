"""SARIF 2.1.0 output tests for evaluation reports."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from oss_policy_kit.application.sarif_writer import (
    SARIF_VERSION,
    build_sarif,
    write_sarif_report,
)
from oss_policy_kit.domain.models import (
    ControlResult,
    ControlStatus,
    ExecutionReport,
    LiveCollectionMetadata,
)


def _result(
    *,
    cid: str,
    status: ControlStatus,
    sources: list[str] | None = None,
    profile: str = "github-level-1",
    weight: int = 1,
) -> ControlResult:
    return ControlResult(
        control_id=cid,
        title=f"Title {cid}",
        category="governance",
        status=status,
        profile=profile,
        evidence_sources=sources or [],
        confidence="high",
        reason="reason text",
        remediation="do thing",
        lifecycle="stable",
        assurance="signal",
        evidence_collection_method="static",
        weight=weight,
    )


def _report(results: list[ControlResult]) -> ExecutionReport:
    summary: dict[str, int] = {}
    for r in results:
        summary[r.status.value] = summary.get(r.status.value, 0) + 1
    return ExecutionReport(
        schema_version="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/1.0",
        generated_at=datetime.now(UTC).isoformat(),
        kit_version="5.0.0-test",
        target_path=str(Path.cwd()),
        profile_id="github-level-1",
        profile_title="GitHub OSS starter baseline (level 1)",
        summary_by_status=summary,
        results=results,
        operational_warnings=[],
        live_collection=LiveCollectionMetadata(performed=False),
    )


def test_sarif_version_and_schema() -> None:
    sarif = build_sarif(_report([_result(cid="GOV-SEC-001", status=ControlStatus.FAIL)]))
    assert sarif["version"] == SARIF_VERSION == "2.1.0"
    assert sarif["$schema"].startswith("https://")
    assert "runs" in sarif and isinstance(sarif["runs"], list)
    assert len(sarif["runs"]) == 1


def test_only_fail_and_manual_review_become_results() -> None:
    results = [
        _result(cid="GOV-SEC-001", status=ControlStatus.PASS),
        _result(cid="GOV-LIC-004", status=ControlStatus.FAIL),
        _result(cid="PLAT-BRPROT-015", status=ControlStatus.MANUAL_REVIEW_REQUIRED),
        _result(cid="GOV-WAIV-014", status=ControlStatus.WAIVED),
        _result(cid="REL-CHANGE-012", status=ControlStatus.NOT_APPLICABLE),
    ]
    sarif = build_sarif(_report(results))
    sarif_results = sarif["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in sarif_results}
    assert rule_ids == {"GOV-LIC-004", "PLAT-BRPROT-015"}


def test_fail_maps_to_error_manual_review_to_warning() -> None:
    results = [
        _result(cid="GOV-LIC-004", status=ControlStatus.FAIL),
        _result(cid="PLAT-BRPROT-015", status=ControlStatus.MANUAL_REVIEW_REQUIRED),
    ]
    sarif = build_sarif(_report(results))
    by_id = {r["ruleId"]: r for r in sarif["runs"][0]["results"]}
    assert by_id["GOV-LIC-004"]["level"] == "error"
    assert by_id["PLAT-BRPROT-015"]["level"] == "warning"


def test_repo_level_finding_uses_dot_uri_no_region() -> None:
    """Repo-level findings (no file evidence) must NOT carry a region."""

    sarif = build_sarif(_report([_result(cid="GOV-SEC-001", status=ControlStatus.FAIL)]))
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "."
    assert "region" not in loc


def test_file_backed_finding_uses_relative_path() -> None:
    sarif = build_sarif(
        _report(
            [
                _result(
                    cid="CI-PIN-008",
                    status=ControlStatus.FAIL,
                    sources=[".github/workflows/ci.yml"],
                ),
            ]
        )
    )
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == ".github/workflows/ci.yml"
    assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    assert "region" not in loc


def test_absolute_paths_are_rejected_from_sarif_locations() -> None:
    """No host paths must leak through. Absolute paths fall back to repo-level."""

    windows_path = (
        "C:"
        + "\\"
        + "Users"
        + "\\"
        + "Lucas Grifoni"
        + "\\"
        + "repo"
        + "\\"
        + ".github"
        + "\\"
        + "workflows"
        + "\\"
        + "ci.yml"
    )
    sarif = build_sarif(
        _report(
            [
                _result(
                    cid="CI-PIN-008",
                    status=ControlStatus.FAIL,
                    sources=[windows_path],
                ),
            ]
        )
    )
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "."


def test_healthy_run_emits_zero_results_but_keeps_tool_block() -> None:
    sarif = build_sarif(_report([_result(cid="GOV-SEC-001", status=ControlStatus.PASS)]))
    run = sarif["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["name"] == "oss-policy-kit"
    # zero rules when there are no reportable findings
    assert run["tool"]["driver"]["rules"] == []


def test_severity_scales_with_weight_and_status() -> None:
    weighted = [
        _result(cid="X-1", status=ControlStatus.FAIL, weight=1),
        _result(cid="X-3", status=ControlStatus.FAIL, weight=3),
        _result(cid="X-MR", status=ControlStatus.MANUAL_REVIEW_REQUIRED, weight=3),
    ]
    sarif = build_sarif(_report(weighted))
    by_id = {r["ruleId"]: r for r in sarif["runs"][0]["results"]}

    def sev(rule_id: str) -> float:
        return float(by_id[rule_id]["properties"]["security-severity"])

    assert sev("X-3") > sev("X-1")
    assert sev("X-MR") < sev("X-3")  # manual-review penalty


def test_partial_fingerprint_is_stable(tmp_path: Path) -> None:
    sarif1 = build_sarif(_report([_result(cid="GOV-LIC-004", status=ControlStatus.FAIL)]))
    sarif2 = build_sarif(_report([_result(cid="GOV-LIC-004", status=ControlStatus.FAIL)]))
    fp1 = sarif1["runs"][0]["results"][0]["partialFingerprints"]
    fp2 = sarif2["runs"][0]["results"][0]["partialFingerprints"]
    assert fp1 == fp2 == {"controlAndProfile/v1": "GOV-LIC-004@github-level-1"}


def test_write_sarif_report_creates_valid_json(tmp_path: Path) -> None:
    out = tmp_path / "evaluation-report.sarif"
    write_sarif_report(_report([_result(cid="GOV-SEC-001", status=ControlStatus.FAIL)]), out)
    assert out.is_file()
    import json

    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["version"] == "2.1.0"


def test_no_personal_email_or_host_paths_in_sarif() -> None:
    posix_path = (
        "/" + "Users" + "/" + "someone" + "/" + "private" + "/" + ".github" + "/" + "workflows" + "/" + "ci.yml"
    )
    windows_path = "C:" + "\\" + "Users" + "\\" + "private"
    sarif = build_sarif(
        _report(
            [
                _result(
                    cid="CI-PIN-008",
                    status=ControlStatus.FAIL,
                    sources=[posix_path, windows_path],
                ),
            ]
        )
    )
    import json

    serialized = json.dumps(sarif)
    assert "Users\\Lucas" not in serialized
    forbidden_consumer_domain = "@" + "gm" + "ail" + ".com"
    assert forbidden_consumer_domain not in serialized
    forbidden_posix_home = "/" + "Users" + "/"
    assert forbidden_posix_home not in serialized  # absolute POSIX paths must not leak through
