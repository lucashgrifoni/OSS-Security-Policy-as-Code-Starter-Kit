"""v5 invariants for Azure / AWS evidence handling.

These tests do NOT require live cloud credentials, network, or real account
identifiers. They exercise the placeholder-detection logic, the freshness
projection, and the v1 evidence projection on synthetic, clearly-fake payloads.

Privacy invariant: the synthetic identifiers used here MUST be on the
allow-list (e.g. ``000000000000``, ``example-org``). Any real-looking ID would
be a regression.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from oss_policy_kit.application.evidence_placeholders import (
    has_placeholder_values,
    is_placeholder_digest,
)
from oss_policy_kit.application.evidence_projection import project_evidence
from oss_policy_kit.domain.models import ControlResult, ControlStatus


def _result(
    *,
    cid: str,
    method: str = "live",
    sources: list[str] | None = None,
    extra: dict | None = None,
    status: ControlStatus = ControlStatus.PASS,
    assurance: str = "evidence-backed",
) -> ControlResult:
    return ControlResult(
        control_id=cid,
        title=f"Title {cid}",
        category="platform",
        status=status,
        profile="azure-level-3",
        evidence_sources=sources or [],
        confidence="high",
        reason="evidence-backed",
        remediation="-",
        lifecycle="stable",
        assurance=assurance,
        evidence_collection_method=method,
        weight=2,
        extra=extra or {},
    )


SCHEMA_DIR = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit" / "data" / "schema"


# --- Placeholder rejection ---------------------------------------------------


def test_synthetic_azure_evidence_with_placeholder_strings_is_detected() -> None:
    """A synthetic Azure branch-policy evidence file with REPLACE_ME tokens must be flagged."""

    synthetic = {
        "organization": "REPLACE_ME",
        "project": "example-project",
        "repository": "example-repo",
        "default_branch": "main",
        "branch_policies": [
            {"branch": "main", "min_reviewers": 1, "policy_id": "REPLACE_ME"},
        ],
        "collection": {
            "method": "manual",
            "collected_at": "YYYY-MM-DD",
        },
    }
    matches = has_placeholder_values(synthetic)
    assert "REPLACE_ME" in matches
    assert "YYYY-MM-DD" in matches


def test_synthetic_aws_codepipeline_evidence_with_placeholder_account_is_detected() -> None:
    """Synthetic CodePipeline evidence with placeholder strings must be flagged."""

    synthetic = {
        "pipeline_name": "example-pipeline",
        "account_id": "000000000000",  # synthetic but valid-looking; placeholder logic should not flag
        "stages": [
            {"name": "Source", "actions": [{"role_arn": "arn:aws:iam::000000000000:role/REPLACE_ME"}]},
        ],
    }
    matches = has_placeholder_values(synthetic)
    assert "REPLACE_ME" in matches


def test_template_sha256_digests_are_rejected() -> None:
    """Template digests from the scaffold (a*64, abcdef..., etc.) must be flagged."""

    assert is_placeholder_digest("a" * 64)
    assert is_placeholder_digest("0" * 64)
    assert is_placeholder_digest("abcdef0123456789" * 4)
    # A high-entropy digest must NOT be flagged.
    real_looking = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert not is_placeholder_digest(real_looking)


# --- v5 evidence projection on Azure/AWS shaped results ----------------------


def test_azure_live_evidence_fresh_projects_to_verified() -> None:
    """A control id starting with AZ- + live + fresh + attested → verified."""

    ev = project_evidence(
        _result(
            cid="AZ-PLAT-034",
            method="live",
            sources=[".oss-policy-kit/evidence/azure-branch-policies.json"],
            extra={
                "collected_at": datetime.now(UTC).isoformat(),
                "attested_by": "azure-devops-api-collection",
            },
        )
    )
    assert ev["source_platform"] == "azure"
    assert ev["source_type"] == "api_collected"
    assert ev["trust_level"] == "verified"
    assert ev["freshness_status"] == "fresh"


def test_azure_live_evidence_stale_drops_to_declared() -> None:
    old = datetime.now(UTC) - timedelta(days=180)
    ev = project_evidence(
        _result(
            cid="AZ-PLAT-035",
            method="live",
            sources=["evidence/azure-pipeline-governance.json"],
            extra={"collected_at": old.isoformat(), "attested_by": "azure-devops-api-collection"},
        )
    )
    assert ev["freshness_status"] == "stale"
    assert ev["trust_level"] == "declared"


def test_aws_live_evidence_fresh_projects_to_verified() -> None:
    ev = project_evidence(
        _result(
            cid="AWS-PIPE-042",
            method="live",
            sources=[".oss-policy-kit/evidence/aws-codepipeline.json"],
            extra={
                "collected_at": datetime.now(UTC).isoformat(),
                "attested_by": "aws-codepipeline-api-collection",
            },
        )
    )
    assert ev["source_platform"] == "aws"
    assert ev["trust_level"] == "verified"


def test_aws_manual_evidence_caps_at_declared_self_attested() -> None:
    """Manual evidence (no API collection) cannot reach 'verified' even when fresh."""

    ev = project_evidence(
        _result(
            cid="AWS-CB-045",
            method="manual",
            sources=[".oss-policy-kit/evidence/aws-codebuild-project.json"],
            extra={"collected_at": datetime.now(UTC).isoformat()},
        )
    )
    assert ev["source_type"] == "user_supplied"
    assert ev["attestation_status"] == "self_attested"
    assert ev["trust_level"] == "declared"


def test_unknown_freshness_for_live_without_collected_at() -> None:
    ev = project_evidence(
        _result(
            cid="AZ-PLAT-034",
            method="live",
            sources=["evidence/azure-branch-policies.json"],
            extra={"attested_by": "azure-devops-api-collection"},
        )
    )
    assert ev["freshness_status"] == "unknown"
    # without freshness, even attested live evidence cannot be 'verified' (rule §4.2.2)
    assert ev["trust_level"] in {"declared", "inferred"}


# --- Schema strictness (defense in depth) ------------------------------------


def test_azure_branch_policies_evidence_schema_is_loadable_utf8() -> None:
    """All evidence schemas should be UTF-8 parsable JSON (no UTF-16 BOM regressions)."""

    p = SCHEMA_DIR / "evidence-azure-branch-policies.schema.json"
    raw = p.read_bytes()
    assert raw[:4] != b"\xff\xfe{\x00", "evidence-azure-branch-policies.schema.json must be UTF-8"
    parsed = json.loads(raw.decode("utf-8"))
    assert "$schema" in parsed


def test_aws_codepipeline_evidence_schema_is_loadable_utf8() -> None:
    p = SCHEMA_DIR / "evidence-aws-codepipeline.schema.json"
    raw = p.read_bytes()
    assert raw[:4] != b"\xff\xfe{\x00"
    parsed = json.loads(raw.decode("utf-8"))
    assert "$schema" in parsed


def test_v1_payload_emits_evidence_for_azure_aws_controls() -> None:
    """End-to-end: every control in an Azure profile gets a structured evidence object."""

    from tests.conftest import EXAMPLE_HARDENED

    from oss_policy_kit.application.engine import evaluate_repository
    from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
    from oss_policy_kit.application.reporting import report_to_dict_v1

    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "azure-level-1")
    report = evaluate_repository(
        repo_root=Path(EXAMPLE_HARDENED),
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
        external_waiver_path=None,
        verbose_emit=None,
        report_json_contract="1.0",
    )
    payload = report_to_dict_v1(report)
    az_results = [r for r in payload["results"] if r["control_id"].startswith("AZ-")]
    assert az_results, "expected azure-level-1 to include AZ-* controls"
    for r in az_results:
        assert isinstance(r["evidence"], dict)
        assert r["evidence"]["source_platform"] == "azure"
        assert r["evidence"]["source_type"] in {
            "static_clone",
            "api_collected",
            "user_supplied",
            "heuristic_signal",
            "manual_review",
            "not_observable",
            "derived",
        }
