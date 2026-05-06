"""Backward-compatibility tests: --report-json-contract 0.3 must remain stable in v5."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from oss_policy_kit.application.engine import (
    REPORT_JSON_SCHEMA_URL_V0_2,
    REPORT_JSON_SCHEMA_URL_V0_3,
    REPORT_JSON_SCHEMA_URL_V1_0,
    report_json_schema_url,
)
from oss_policy_kit.application.reporting import report_to_dict
from oss_policy_kit.domain.models import (
    ControlResult,
    ControlStatus,
    ExecutionReport,
    LiveCollectionMetadata,
    WeightedScore,
)


def _result(cid: str = "GOV-SEC-001") -> ControlResult:
    return ControlResult(
        control_id=cid,
        title=f"Title {cid}",
        category="governance",
        status=ControlStatus.PASS,
        profile="github-level-1",
        evidence_sources=["SECURITY.md"],
        confidence="high",
        reason="found",
        remediation="-",
        lifecycle="stable",
        assurance="deterministic",
        evidence_collection_method="static",
        weight=1,
    )


def _report(schema_version: str) -> ExecutionReport:
    return ExecutionReport(
        schema_version=schema_version,
        generated_at=datetime.now(UTC).isoformat(),
        kit_version="5.0.0-test",
        target_path=str(Path.cwd()),
        profile_id="github-level-1",
        profile_title="GitHub starter (L1)",
        summary_by_status={"pass": 1},
        results=[_result()],
        operational_warnings=[],
        live_collection=LiveCollectionMetadata(performed=False),
        weighted_score=WeightedScore(earned=1, possible=1, percent=100.0),
    )


def test_default_v5_contract_is_1_0() -> None:
    assert report_json_schema_url("") == REPORT_JSON_SCHEMA_URL_V1_0
    assert report_json_schema_url("1.0") == REPORT_JSON_SCHEMA_URL_V1_0


def test_0_3_still_selectable() -> None:
    assert report_json_schema_url("0.3") == REPORT_JSON_SCHEMA_URL_V0_3


def test_0_2_still_selectable() -> None:
    assert report_json_schema_url("0.2") == REPORT_JSON_SCHEMA_URL_V0_2


def test_0_1_is_rejected_with_migration_text() -> None:
    import pytest

    from oss_policy_kit.domain.errors import LoadError

    with pytest.raises(LoadError, match="0.1.*removed in v5"):
        report_json_schema_url("0.1")


def test_0_3_payload_keeps_legacy_shape() -> None:
    """0.3 selectability must not adopt v1 keys (no results_digest, no evidence object)."""

    payload = report_to_dict(_report(REPORT_JSON_SCHEMA_URL_V0_3))
    assert payload["schema_version"].endswith("/reports/0.3")
    assert "summary_by_gate_role" in payload
    assert "gate_execution_model" in payload
    # v1-only fields must NOT appear in v0.3 payload
    assert "results_digest" not in payload
    assert "evidence_provenance_version" not in payload
    # v0.3 results carry flat fields, not the structured `evidence` object
    first = payload["results"][0]
    assert "evidence_sources" in first
    assert "evidence_collection_method" in first
    assert not isinstance(first.get("evidence"), dict)


def test_0_2_payload_keeps_legacy_shape() -> None:
    payload = report_to_dict(_report(REPORT_JSON_SCHEMA_URL_V0_2))
    assert payload["schema_version"].endswith("/reports/0.2")
    # v0.2 must NOT carry v0.3 gate-role keys
    assert "summary_by_gate_role" not in payload
    assert "gate_execution_model" not in payload


def test_override_to_v1_promotes_in_memory_v0_3_report() -> None:
    """schema_version_override should let callers re-emit a 0.3-bound report under 1.0."""

    payload = report_to_dict(_report(REPORT_JSON_SCHEMA_URL_V0_3), schema_version_override=REPORT_JSON_SCHEMA_URL_V1_0)
    assert payload["schema_version"].endswith("/reports/1.0")
    assert "results_digest" in payload
    assert isinstance(payload["results"][0]["evidence"], dict)
