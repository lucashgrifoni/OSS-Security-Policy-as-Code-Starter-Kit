"""AWS profile coverage and evidence behavior."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from tests.conftest import AWS_HARDENED_FIXTURE, AWS_MINIMAL_FIXTURE, ROOT

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id


def _evaluate(repo: Path, profile_id: str):
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, profile_id)
    return evaluate_repository(
        repo_root=repo,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )


def test_aws_minimal_level1_secret_heuristic_is_manual_review() -> None:
    report = _evaluate(AWS_MINIMAL_FIXTURE, "aws-level-1")
    status = {r.control_id: r.status.value for r in report.results}
    assert status["AWS-CI-037"] == "pass"
    assert status["AWS-SECRET-038"] == "manual-review-required"
    assert status["AWS-SEC-039"] == "fail"


def test_aws_hardened_level2_passes_strict_aws_controls() -> None:
    report = _evaluate(AWS_HARDENED_FIXTURE, "aws-level-2")
    status = {r.control_id: r.status.value for r in report.results}
    assert status["AWS-CI-037"] == "pass"
    assert status["AWS-SECRET-038"] == "pass"
    assert status["AWS-PIPE-042"] == "pass"
    assert status["AWS-PROV-043"] == "pass"


def test_aws_release_hardening_3_platform_evidence_self_attested(tmp_path: Path) -> None:
    repo = tmp_path / "aws-release"
    shutil.copytree(AWS_HARDENED_FIXTURE, repo)
    evidence_dir = repo / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    # Valid 64-char lowercase hex digests (schema); avoid repeating blocks (is_placeholder_digest).
    digest_a = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    digest_b = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    (evidence_dir / "aws-codepipeline.json").write_text(
        json.dumps(
            {
                "schema_version": "aws-codepipeline/v1",
                "attested_at": "2026-04-15",
                "attested_by": "aws-api-collection",
                "pipeline": "prod",
                "posture": {
                    "manual_approval_before_production": True,
                    "artifact_store_encryption_enabled": True,
                    "production_execution_mode_not_parallel": True,
                },
                "iam": {"pipeline_service_role_arn_configured": True},
            }
        ),
        encoding="utf-8",
    )
    (evidence_dir / "aws-codebuild-project.json").write_text(
        json.dumps(
            {
                "schema_version": "aws-codebuild-project/v1",
                "attested_at": "2026-04-15",
                "attested_by": "qa",
                "project": "build",
                "posture": {
                    "privileged_mode_disabled": True,
                    "no_plaintext_credentials_in_project_config": True,
                    "codebuild_service_role_configured": True,
                },
                "identity": {
                    "service_role_arn_present": True,
                    "no_plaintext_environment_credentials": True,
                },
            }
        ),
        encoding="utf-8",
    )
    (evidence_dir / "aws-sbom-artifact.json").write_text(
        json.dumps(
            {
                "schema_version": "aws-sbom-artifact/v1",
                "attested_at": "2026-04-15",
                "attested_by": "qa",
                "artifact": {"uri": "s3://example/artifact.tgz", "digest_sha256": digest_a},
                "sbom": {"format": "cyclonedx", "digest_sha256": digest_b},
                "posture": {
                    "sbom_covers_release_artifact": True,
                    "sbom_digest_recorded": True,
                    "artifact_digest_recorded": True,
                },
            }
        ),
        encoding="utf-8",
    )
    (evidence_dir / "aws-provenance-artifact.json").write_text(
        json.dumps(
            {
                "schema_version": "aws-provenance-artifact/v1",
                "attested_at": "2026-04-15",
                "attested_by": "qa",
                "artifact": {"uri": "s3://example/artifact.tgz", "digest_sha256": digest_a},
                "attestation": {"kind": "cosign", "digest_sha256": digest_b},
                "posture": {
                    "attestation_covers_release_artifact": True,
                    "attestation_digest_recorded": True,
                    "artifact_digest_recorded": True,
                },
            }
        ),
        encoding="utf-8",
    )
    report = _evaluate(repo, "aws-release-hardening-3")
    status = {r.control_id: r.status.value for r in report.results}
    assert status["GOV-EVIDFRESH-054"] == "pass"
    assert status["AWS-CP-044"] == "pass"
    assert status["AWS-CB-045"] == "self-attested"
    assert status["AWS-PIPEIAM-056"] == "pass"
    assert status["AWS-CBIDENT-057"] == "self-attested"
    assert status["AWS-SBOMART-058"] == "self-attested"
    assert status["AWS-PROVART-059"] == "self-attested"


def test_aws_codepipeline_api_evidence_yields_pass_for_cp044(tmp_path: Path) -> None:
    repo = tmp_path / "aws-api-ev"
    shutil.copytree(AWS_HARDENED_FIXTURE, repo)
    evidence_dir = repo / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    collected = "2026-04-15T12:00:00Z"
    (evidence_dir / "aws-codepipeline.json").write_text(
        json.dumps(
            {
                "schema_version": "aws-codepipeline/v1",
                "attested_at": "2026-04-15",
                "attested_by": "aws-api-collection",
                "pipeline": "prod",
                "posture": {
                    "manual_approval_before_production": True,
                    "artifact_store_encryption_enabled": True,
                    "production_execution_mode_not_parallel": True,
                },
                "collection": {
                    "evidence_collection_method": "live",
                    "collected_at": collected,
                    "source_url": "aws:codepipeline:GetPipeline?name=prod",
                    "mode": "api",
                },
                "iam": {"pipeline_service_role_arn_configured": True},
            }
        ),
        encoding="utf-8",
    )
    report = _evaluate(repo, "aws-release-hardening-2")
    by_id = {r.control_id: r for r in report.results}
    assert by_id["AWS-CP-044"].status.value == "pass"
    assert by_id["AWS-CP-044"].evidence_collection_method == "live"


def test_aws_schema_copies_match_reports_schema() -> None:
    names = (
        "evidence-aws-codebuild-project.schema.json",
        "evidence-aws-codepipeline.schema.json",
        "evidence-aws-sbom-artifact.schema.json",
        "evidence-aws-provenance-artifact.schema.json",
    )
    for name in names:
        public_text = (ROOT / "reports" / "schema" / name).read_text(encoding="utf-8")
        packaged_text = (ROOT / "src" / "oss_policy_kit" / "data" / "schema" / name).read_text(encoding="utf-8")
        assert public_text == packaged_text
