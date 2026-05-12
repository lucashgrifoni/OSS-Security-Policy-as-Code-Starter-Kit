"""Schema and shape tests for the reports/1.0 contract."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from oss_policy_kit.application.reporting import (
    REPORT_JSON_SCHEMA_URL_V1_0,
    compute_results_digest,
    derive_profile_metadata,
    report_to_dict,
    report_to_dict_v1,
)
from oss_policy_kit.domain.models import (
    ControlResult,
    ControlStatus,
    ExecutionReport,
    LiveCollectionMetadata,
    WeightedScore,
)

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit" / "data" / "schema"
V1_SCHEMA_PATH = SCHEMA_DIR / "evaluation-report-v1.schema.json"


def _make_result(
    *,
    cid: str = "GOV-SEC-001",
    status: ControlStatus = ControlStatus.PASS,
    assurance: str = "deterministic",
    method: str = "static",
    profile: str = "github-level-1",
    sources: list[str] | None = None,
    confidence: str = "high",
) -> ControlResult:
    return ControlResult(
        control_id=cid,
        title=f"Title {cid}",
        category="governance",
        status=status,
        profile=profile,
        evidence_sources=sources or [],
        confidence=confidence,
        reason="reason text",
        remediation="do thing",
        lifecycle="stable",
        assurance=assurance,
        evidence_collection_method=method,
        weight=1,
    )


def _make_report(results: list[ControlResult]) -> ExecutionReport:
    summary = {}
    for r in results:
        summary[r.status.value] = summary.get(r.status.value, 0) + 1
    return ExecutionReport(
        schema_version=REPORT_JSON_SCHEMA_URL_V1_0,
        generated_at=datetime.now(UTC).isoformat(),
        kit_version="5.0.0-test",
        target_path=str(Path.cwd()),
        profile_id="github-level-1",
        profile_title="GitHub OSS starter baseline (level 1)",
        summary_by_status=summary,
        results=results,
        operational_warnings=[],
        scorecard_path=None,
        scorecard_supplemental=None,
        external_waiver_path=None,
        live_collection=LiveCollectionMetadata(performed=False),
        weighted_score=WeightedScore(earned=1, possible=1, percent=100.0),
    )


@pytest.fixture(scope="module")
def v1_validator() -> Draft202012Validator:
    schema = json.loads(V1_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_v1_schema_is_utf8_no_bom() -> None:
    raw = V1_SCHEMA_PATH.read_bytes()
    assert raw[:1] == b"{", "v1 schema must start with '{' (UTF-8 no BOM)"
    assert b"\xff\xfe" not in raw[:4], "v1 schema must not be UTF-16"


def test_v3_schema_is_utf8_no_bom() -> None:
    """Phase 0 hygiene: the v3 schema was UTF-16 with BOM in v4 and must be UTF-8 in v5."""

    raw = (SCHEMA_DIR / "evaluation-report-v3.schema.json").read_bytes()
    assert raw[:4] != b"\xff\xfe{\x00", "v3 schema must be re-encoded to UTF-8"
    assert raw[:1] == b"{"


def test_pass_result_validates_against_v1_schema(v1_validator: Draft202012Validator) -> None:
    report = _make_report([_make_result()])
    payload = report_to_dict_v1(report)
    v1_validator.validate(payload)


def test_fail_and_manual_review_validate(v1_validator: Draft202012Validator) -> None:
    results = [
        _make_result(cid="GOV-SEC-001", status=ControlStatus.FAIL, assurance="deterministic"),
        _make_result(cid="PLAT-BRPROT-015", status=ControlStatus.MANUAL_REVIEW_REQUIRED, assurance="evidence-backed"),
    ]
    payload = report_to_dict_v1(_make_report(results))
    v1_validator.validate(payload)
    gate_roles = {r["gate_role"] for r in payload["results"]}
    assert "ci_blocking_fail" in gate_roles
    assert "human_review_gate" in gate_roles


def test_signal_assurance_cannot_project_to_verified(v1_validator: Draft202012Validator) -> None:
    """No-silent-inflation rule: signal-grade evidence projects to inferred at most."""

    r = _make_result(
        cid="CI-WF-005",
        status=ControlStatus.PASS,
        assurance="signal",
        method="static",
        sources=["found 'codeql' keyword in workflow"],
        confidence="high",
    )
    payload = report_to_dict_v1(_make_report([r]))
    v1_validator.validate(payload)
    ev = payload["results"][0]["evidence"]
    assert ev["source_type"] == "heuristic_signal"
    assert ev["trust_level"] == "inferred"
    assert any("signal" in lim.lower() for lim in ev["limitations"])


def test_api_collected_fresh_evidence_can_be_verified(v1_validator: Draft202012Validator) -> None:
    """API-collected fresh evidence with attestation reaches trust_level=verified."""

    r = _make_result(
        cid="PLAT-BRPROT-015",
        status=ControlStatus.PASS,
        assurance="evidence-backed",
        method="live",
        sources=["evidence/branch-protection.json"],
    )
    # Inject collected_at and attested_by metadata via extra
    r = ControlResult(
        control_id=r.control_id,
        title=r.title,
        category=r.category,
        status=r.status,
        profile=r.profile,
        evidence_sources=r.evidence_sources,
        confidence=r.confidence,
        reason=r.reason,
        remediation=r.remediation,
        lifecycle=r.lifecycle,
        assurance=r.assurance,
        evidence_collection_method=r.evidence_collection_method,
        weight=r.weight,
        extra={"collected_at": datetime.now(UTC).isoformat(), "attested_by": "github-api"},
    )
    payload = report_to_dict_v1(_make_report([r]))
    v1_validator.validate(payload)
    ev = payload["results"][0]["evidence"]
    assert ev["trust_level"] == "verified"
    assert ev["freshness_status"] == "fresh"
    assert ev["attestation_status"] == "signed"


def test_stale_api_evidence_downgrades_trust(v1_validator: Draft202012Validator) -> None:
    """Old collection timestamp drops trust to declared and freshness to stale."""

    r = _make_result(
        cid="PLAT-BRPROT-015",
        status=ControlStatus.PASS,
        assurance="evidence-backed",
        method="live",
        sources=["evidence/branch-protection.json"],
    )
    r = ControlResult(
        control_id=r.control_id,
        title=r.title,
        category=r.category,
        status=r.status,
        profile=r.profile,
        evidence_sources=r.evidence_sources,
        confidence=r.confidence,
        reason=r.reason,
        remediation=r.remediation,
        lifecycle=r.lifecycle,
        assurance=r.assurance,
        evidence_collection_method=r.evidence_collection_method,
        weight=r.weight,
        extra={"collected_at": "2020-01-01T00:00:00+00:00", "attested_by": "github-api"},
    )
    payload = report_to_dict_v1(_make_report([r]))
    v1_validator.validate(payload)
    ev = payload["results"][0]["evidence"]
    assert ev["freshness_status"] == "stale"
    assert ev["trust_level"] == "declared"


def test_results_digest_is_deterministic() -> None:
    results = [
        _make_result(cid="GOV-SEC-001"),
        _make_result(cid="GOV-LIC-004", status=ControlStatus.FAIL),
    ]
    a = compute_results_digest(results)
    b = compute_results_digest(list(reversed(results)))  # order-independent
    assert a == b
    assert a.startswith("sha256:")
    assert len(a) == len("sha256:") + 64


def test_derive_profile_metadata_for_known_profiles() -> None:
    m = derive_profile_metadata("github-level-1")
    assert m["family"] == "github"
    assert m["level"] == "Llevel-1" or m["level"].startswith("L")
    assert m["posture"] == "starter"
    assert m["recommended_gate"] == "--fail-on fail"

    m = derive_profile_metadata("github-aws-level-2")
    assert m["family"] == "github"
    assert m["posture"] == "multi_platform_advisory_hybrid"
    assert m["recommended_gate"] == "--fail-on none"

    m = derive_profile_metadata("aws-release-hardening-3")
    assert m["family"] == "aws"
    assert m["is_release_track"] is True
    assert m["posture"] == "hard_gate"


def test_v1_payload_uses_repo_to_dict_dispatch(v1_validator: Draft202012Validator) -> None:
    """Calling report_to_dict with override 1.0 must produce v1 shape."""

    report = _make_report([_make_result()])
    payload = report_to_dict(report, schema_version_override=REPORT_JSON_SCHEMA_URL_V1_0)
    v1_validator.validate(payload)
    assert payload["schema_version"].endswith("/reports/1.0")
    assert "results_digest" in payload
    assert "evidence_provenance_version" in payload


def test_v1_controls_total_in_payload(v1_validator: Draft202012Validator) -> None:
    """reports/1.0 must surface controls_total at the top level (M-001)."""

    report = _make_report([_make_result()])
    payload = report_to_dict_v1(report)
    v1_validator.validate(payload)
    assert "controls_total" in payload
    assert payload["controls_total"] == sum(payload["summary_by_status"].values())


def test_v1_strict_no_unknown_top_level_keys(v1_validator: Draft202012Validator) -> None:
    """additionalProperties:false — adding a stray key must fail validation."""

    payload = report_to_dict_v1(_make_report([_make_result()]))
    payload["x_unauthorized_extra"] = True
    from jsonschema.exceptions import ValidationError

    with pytest.raises(ValidationError):
        v1_validator.validate(payload)


def test_v1_evidence_object_required_keys(v1_validator: Draft202012Validator) -> None:
    payload = report_to_dict_v1(_make_report([_make_result()]))
    ev = payload["results"][0]["evidence"]
    for k in (
        "source_type",
        "trust_level",
        "collection_method",
        "collected_at",
        "source_platform",
        "freshness_status",
        "attestation_status",
        "references",
        "limitations",
    ):
        assert k in ev, f"v1 evidence object missing required key: {k}"
