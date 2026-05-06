"""Promotion-rule tests for the Evidence Model v2 projection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from oss_policy_kit.application.evidence_projection import (
    DEFAULT_FRESHNESS_WINDOW_DAYS,
    EVIDENCE_PROVENANCE_VERSION,
    FreshnessContext,
    gate_role_for,
    normalize_confidence,
    project_evidence,
)
from oss_policy_kit.domain.models import ControlResult, ControlStatus


def _r(
    *,
    status: ControlStatus = ControlStatus.PASS,
    assurance: str = "signal",
    method: str = "static",
    sources: list[str] | None = None,
    extra: dict | None = None,
    cid: str = "CI-WF-005",
    confidence: str = "medium",
) -> ControlResult:
    return ControlResult(
        control_id=cid,
        title=f"Title {cid}",
        category="ci",
        status=status,
        profile="github-level-1",
        evidence_sources=sources or [],
        confidence=confidence,
        reason="r",
        remediation="x",
        lifecycle="stable",
        assurance=assurance,
        evidence_collection_method=method,
        weight=1,
        extra=extra or {},
    )


def test_evidence_provenance_version() -> None:
    assert EVIDENCE_PROVENANCE_VERSION == "evidence/2.0"


def test_signal_static_projects_to_heuristic_inferred() -> None:
    ev = project_evidence(_r(assurance="signal", method="static", sources=["found 'codeql' in workflow"]))
    assert ev["source_type"] == "heuristic_signal"
    assert ev["trust_level"] == "inferred"


def test_deterministic_static_projects_to_static_clone_declared() -> None:
    ev = project_evidence(_r(cid="GOV-SEC-001", assurance="deterministic", sources=["SECURITY.md"]))
    assert ev["source_type"] == "static_clone"
    assert ev["trust_level"] == "declared"


def test_evidence_backed_static_projects_to_user_supplied() -> None:
    ev = project_evidence(
        _r(
            cid="PLAT-BRPROT-015",
            assurance="evidence-backed",
            method="static",
            sources=[".oss-policy-kit/evidence/branch-protection.json"],
        )
    )
    assert ev["source_type"] == "user_supplied"
    assert ev["trust_level"] == "declared"


def test_api_collected_fresh_with_attestation_is_verified() -> None:
    ev = project_evidence(
        _r(
            cid="PLAT-BRPROT-015",
            status=ControlStatus.PASS,
            assurance="evidence-backed",
            method="live",
            sources=[".oss-policy-kit/evidence/branch-protection.json"],
            extra={"collected_at": datetime.now(UTC).isoformat(), "attested_by": "github-api"},
        )
    )
    assert ev["source_type"] == "api_collected"
    assert ev["trust_level"] == "verified"
    assert ev["freshness_status"] == "fresh"
    assert ev["attestation_status"] == "signed"


def test_api_collected_stale_drops_to_declared() -> None:
    old = datetime.now(UTC) - timedelta(days=DEFAULT_FRESHNESS_WINDOW_DAYS + 5)
    ev = project_evidence(
        _r(
            cid="PLAT-BRPROT-015",
            assurance="evidence-backed",
            method="live",
            sources=[".oss-policy-kit/evidence/branch-protection.json"],
            extra={"collected_at": old.isoformat(), "attested_by": "github-api"},
        )
    )
    assert ev["freshness_status"] == "stale"
    assert ev["trust_level"] == "declared"


def test_manual_review_required_projects_to_manual_review() -> None:
    ev = project_evidence(_r(status=ControlStatus.MANUAL_REVIEW_REQUIRED, assurance="evidence-backed"))
    assert ev["source_type"] == "manual_review"
    assert ev["trust_level"] == "inferred"
    assert ev["attestation_status"] == "not_applicable"


def test_not_observable_projects_to_unobserved() -> None:
    ev = project_evidence(_r(status=ControlStatus.NOT_OBSERVABLE, assurance="signal"))
    assert ev["source_type"] == "not_observable"
    assert ev["trust_level"] == "unobserved"


def test_not_applicable_projects_to_unobserved() -> None:
    ev = project_evidence(_r(status=ControlStatus.NOT_APPLICABLE, assurance="signal"))
    assert ev["trust_level"] == "unobserved"


def test_freshness_unknown_when_no_collected_at_for_live() -> None:
    ev = project_evidence(
        _r(
            cid="PLAT-BRPROT-015",
            assurance="evidence-backed",
            method="live",
            sources=[".oss-policy-kit/evidence/branch-protection.json"],
        )
    )
    assert ev["freshness_status"] == "unknown"


def test_freshness_not_applicable_for_static() -> None:
    ev = project_evidence(_r(cid="GOV-SEC-001", assurance="deterministic", method="static", sources=["SECURITY.md"]))
    assert ev["freshness_status"] == "not_applicable"


def test_absolute_path_in_evidence_source_is_redacted() -> None:
    windows_path = (
        "C:"
        + "\\"
        + "Users"
        + "\\"
        + "someone"
        + "\\"
        + "private"
        + "\\"
        + ".github"
        + "\\"
        + "workflows"
        + "\\"
        + "ci.yml"
    )
    ev = project_evidence(
        _r(
            cid="CI-WF-005",
            assurance="signal",
            sources=[windows_path],
        )
    )
    refs = ev["references"]
    assert refs, "expected a reference entry"
    assert refs[0]["redacted"] is True
    assert "Users\\someone\\private" not in refs[0]["value"]


def test_placeholder_paths_are_filtered_out() -> None:
    ev = project_evidence(
        _r(cid="GOV-SEC-001", assurance="deterministic", sources=["<placeholder>", "tbd", "TODO", ""])
    )
    assert ev["references"] == []


def test_source_platform_inferred_from_control_prefix() -> None:
    assert project_evidence(_r(cid="AZ-PIPE-027", assurance="deterministic"))["source_platform"] == "azure"
    assert project_evidence(_r(cid="AWS-CB-040", assurance="deterministic"))["source_platform"] == "aws"
    assert project_evidence(_r(cid="GH-WF-018", assurance="signal"))["source_platform"] == "github"
    assert project_evidence(_r(cid="PLAT-BRPROT-015", assurance="evidence-backed"))["source_platform"] == "github"


def test_signal_assurance_always_carries_limitation_text() -> None:
    ev = project_evidence(_r(assurance="signal", sources=["found in workflow"]))
    assert any("signal" in lim.lower() for lim in ev["limitations"])


def test_normalize_confidence_maps_known_strings() -> None:
    assert normalize_confidence("HIGH") == "high"
    assert normalize_confidence("strong") == "high"
    assert normalize_confidence("medium") == "medium"
    assert normalize_confidence("Low") == "low"
    assert normalize_confidence("n/a") == "none"
    assert normalize_confidence(None) == "none"
    assert normalize_confidence("unrecognized") == "low"


def test_gate_role_mapping_is_complete() -> None:
    expected = {
        ControlStatus.PASS: "passed_observation",
        ControlStatus.FAIL: "ci_blocking_fail",
        ControlStatus.MANUAL_REVIEW_REQUIRED: "human_review_gate",
        ControlStatus.SELF_ATTESTED: "self_attested_declarative",
        ControlStatus.NOT_EVALUATED: "not_evaluated_limit",
        ControlStatus.WAIVED: "waived",
        ControlStatus.NOT_APPLICABLE: "not_applicable",
        ControlStatus.NOT_OBSERVABLE: "not_observable",
    }
    for status, role in expected.items():
        assert gate_role_for(status) == role


def test_freshness_context_override_applies() -> None:
    """Custom freshness window can tighten the staleness boundary."""

    recent = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    r = _r(
        cid="PLAT-BRPROT-015",
        assurance="evidence-backed",
        method="live",
        sources=["evidence.json"],
        extra={"collected_at": recent, "attested_by": "x"},
    )
    fresh = project_evidence(r, ctx=FreshnessContext(window_days=30))
    stale = project_evidence(r, ctx=FreshnessContext(window_days=5))
    assert fresh["freshness_status"] == "fresh"
    assert stale["freshness_status"] == "stale"
