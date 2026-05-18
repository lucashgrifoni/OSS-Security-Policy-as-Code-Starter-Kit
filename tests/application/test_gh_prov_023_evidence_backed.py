"""GH-PROV-023 evidence-backed promotion (PR-12, ADR-007)."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import EvalContext, eval_gh_prov_023
from oss_policy_kit.domain.models import ControlStatus, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, *, with_attestation: bool, release: bool = True) -> EvalContext:
    wa = WorkflowAnalysis()
    if release:
        wa.workflow_paths = [tmp_path / ".github" / "workflows" / "release.yml"]
        wa.release_workflow_paths = list(wa.workflow_paths)
    wa.has_artifact_attestation = with_attestation
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-release-hardening-1",
        workflows=wa,
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write_verification_evidence(tmp_path: Path, *, transparency: bool = True) -> Path:
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "github-provenance-artifact.json"
    payload = {
        "schema_version": "github-provenance-artifact/v1",
        "attested_at": "2026-05-01",
        "attested_by": "release-bot",
        "artifact": {
            "uri": "https://github.com/example/repo/releases/download/v1/artifact.tgz",
            "digest_sha256": "a" * 64,
        },
        "attestation": {"kind": "github-artifact-attestation", "digest_sha256": "b" * 64},
        "posture": {
            "attestation_covers_release_artifact": True,
            "attestation_digest_recorded": True,
            "artifact_digest_recorded": True,
        },
        "verification": {
            "method": "gh-attestation-verify",
            "verified_at": "2026-05-01T12:00:00Z",
            "transparency_log_inclusion": transparency,
        },
    }
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_gh_prov_023_fail_when_no_attestation_signal(tmp_path: Path) -> None:
    out = eval_gh_prov_023(_ctx(tmp_path, with_attestation=False))
    assert out.status == ControlStatus.FAIL


def test_gh_prov_023_pass_signal_grade_when_attestation_but_no_evidence(tmp_path: Path) -> None:
    """Backward-compatible path: workflow signal alone keeps the v5.x signal-grade PASS."""
    out = eval_gh_prov_023(_ctx(tmp_path, with_attestation=True))
    assert out.status == ControlStatus.PASS
    assert "workflow signal only" in out.reason
    assert out.confidence == "low"


def test_gh_prov_023_pass_evidence_backed_when_verification_present(tmp_path: Path) -> None:
    """ADR-007 promotion: evidence-backed PASS when verification block is recorded."""
    _write_verification_evidence(tmp_path)
    out = eval_gh_prov_023(_ctx(tmp_path, with_attestation=True))
    assert out.status == ControlStatus.PASS
    assert "evidence-backed" in out.reason
    assert "verification block" in out.reason
    assert out.confidence == "high"
    assert out.evidence_collection_method == EvidenceCollectionMethod.LIVE


def test_gh_prov_023_signal_grade_when_verification_transparency_false(tmp_path: Path) -> None:
    """A verification block without transparency-log inclusion does not promote to evidence-backed.
    (PROV-VERIFY-061 fails outright in that case; GH-PROV-023 keeps the signal PASS so adopters
    are not surprised by a stricter gate at this layer.)"""
    _write_verification_evidence(tmp_path, transparency=False)
    out = eval_gh_prov_023(_ctx(tmp_path, with_attestation=True))
    assert out.status == ControlStatus.PASS
    assert "workflow signal only" in out.reason


def test_gh_prov_023_not_applicable_without_release_intent(tmp_path: Path) -> None:
    out = eval_gh_prov_023(_ctx(tmp_path, with_attestation=False, release=False))
    assert out.status == ControlStatus.NOT_APPLICABLE
