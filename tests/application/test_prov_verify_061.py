"""PROV-VERIFY-061: signed-provenance verification across github/azure/aws families."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from oss_policy_kit.application.evaluators import EvalContext, eval_prov_verify_061
from oss_policy_kit.domain.models import ControlStatus, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, profile_id: str) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id=profile_id,
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


_FRESH_TS = "2026-05-01T12:00:00Z"


def _write_evidence(tmp_path: Path, filename: str, payload: dict) -> Path:
    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = evidence_dir / filename
    evidence_file.write_text(json.dumps(payload), encoding="utf-8")
    return evidence_file


def _gh_payload(*, verified_at: str = _FRESH_TS, transparency: bool = True, omit_verification: bool = False) -> dict:
    payload: dict = {
        "schema_version": "github-provenance-artifact/v1",
        "attested_at": "2026-04-21",
        "attested_by": "release-bot",
        "artifact": {
            "uri": "https://github.com/example-org/example-repo/releases/download/v1/example.tgz",
            "digest_sha256": "e7c2a4d8f1b6c9d2e5a8b1c4d7e0f3a6b9c2d5e8f1a4b7c0d3e6f9a2b5c8d1e4",
        },
        "attestation": {
            "kind": "github-artifact-attestation",
            "digest_sha256": "b3a6c9d2e5f8a1b4c7d0e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0a3b6",
        },
        "posture": {
            "attestation_covers_release_artifact": True,
            "attestation_digest_recorded": True,
            "artifact_digest_recorded": True,
        },
    }
    if not omit_verification:
        payload["verification"] = {
            "method": "gh-attestation-verify",
            "verified_at": verified_at,
            "transparency_log_inclusion": transparency,
            "issuer": "https://token.actions.githubusercontent.com",
            "tool_version": "gh 2.62.0",
        }
    return payload


def test_prov_verify_061_manual_review_when_no_evidence(tmp_path: Path) -> None:
    out = eval_prov_verify_061(_ctx(tmp_path, "github-level-3"))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "provenance-artifact" in out.reason.lower() or "verification" in out.reason.lower()


def test_prov_verify_061_pass_when_github_evidence_with_verification(tmp_path: Path) -> None:
    _write_evidence(tmp_path, "github-provenance-artifact.json", _gh_payload())
    out = eval_prov_verify_061(_ctx(tmp_path, "github-level-3"))
    assert out.status == ControlStatus.PASS
    assert out.evidence_collection_method == EvidenceCollectionMethod.LIVE
    assert out.confidence == "high"


def test_prov_verify_061_manual_review_when_verification_block_missing(tmp_path: Path) -> None:
    _write_evidence(tmp_path, "github-provenance-artifact.json", _gh_payload(omit_verification=True))
    out = eval_prov_verify_061(_ctx(tmp_path, "github-level-3"))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "verification block" in out.reason.lower()


def test_prov_verify_061_fail_when_transparency_log_false(tmp_path: Path) -> None:
    _write_evidence(tmp_path, "github-provenance-artifact.json", _gh_payload(transparency=False))
    out = eval_prov_verify_061(_ctx(tmp_path, "github-level-3"))
    assert out.status == ControlStatus.FAIL
    assert "transparency_log_inclusion" in out.reason


def test_prov_verify_061_fail_when_verification_stale(tmp_path: Path) -> None:
    stale = (datetime.now(UTC) - timedelta(days=120)).isoformat()
    _write_evidence(tmp_path, "github-provenance-artifact.json", _gh_payload(verified_at=stale))
    out = eval_prov_verify_061(_ctx(tmp_path, "github-level-3"))
    assert out.status == ControlStatus.FAIL
    assert "stale" in out.reason.lower() or "older than" in out.reason.lower()


def test_prov_verify_061_manual_review_when_verified_at_unparseable(tmp_path: Path) -> None:
    _write_evidence(tmp_path, "github-provenance-artifact.json", _gh_payload(verified_at="not-a-date"))
    out = eval_prov_verify_061(_ctx(tmp_path, "github-level-3"))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_prov_verify_061_uses_azure_evidence_for_azure_profile(tmp_path: Path) -> None:
    az_payload = {
        "schema_version": "azure-provenance-artifact/v1",
        "attested_at": "2026-04-21",
        "attested_by": "release-bot",
        "artifact": {
            "uri": "https://dev.azure.com/example-org/_apis/build/builds/1/artifacts",
            "digest_sha256": "0" * 32 + "1" * 32,
        },
        "attestation": {
            "kind": "cosign",
            "digest_sha256": "f" * 64,
        },
        "posture": {
            "attestation_covers_release_artifact": True,
            "attestation_digest_recorded": True,
            "artifact_digest_recorded": True,
        },
        "verification": {
            "method": "cosign-verify-bundle",
            "verified_at": _FRESH_TS,
            "transparency_log_inclusion": True,
        },
    }
    _write_evidence(tmp_path, "azure-provenance-artifact.json", az_payload)
    out = eval_prov_verify_061(_ctx(tmp_path, "azure-level-3"))
    assert out.status == ControlStatus.PASS


def test_prov_verify_061_falls_back_to_azure_when_only_azure_present_for_github(tmp_path: Path) -> None:
    """github-* profile with only azure evidence still resolves (cross-family fallback)."""

    az_payload = {
        "schema_version": "azure-provenance-artifact/v1",
        "attested_at": "2026-04-21",
        "attested_by": "release-bot",
        "artifact": {"uri": "https://dev.azure.com/x/_apis/y", "digest_sha256": "a" * 64},
        "attestation": {"kind": "cosign", "digest_sha256": "b" * 64},
        "posture": {
            "attestation_covers_release_artifact": True,
            "attestation_digest_recorded": True,
            "artifact_digest_recorded": True,
        },
        "verification": {
            "method": "cosign-verify-bundle",
            "verified_at": _FRESH_TS,
            "transparency_log_inclusion": True,
        },
    }
    _write_evidence(tmp_path, "azure-provenance-artifact.json", az_payload)
    out = eval_prov_verify_061(_ctx(tmp_path, "github-level-3"))
    assert out.status == ControlStatus.PASS


def test_prov_verify_061_manual_review_on_invalid_schema(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "github-provenance-artifact.json",
        {"schema_version": "github-provenance-artifact/v1", "invalid": "data"},
    )
    out = eval_prov_verify_061(_ctx(tmp_path, "github-level-3"))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
