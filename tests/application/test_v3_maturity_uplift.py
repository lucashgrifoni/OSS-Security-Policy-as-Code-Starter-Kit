"""v3 maturity uplift regression tests.

These tests lock in the v3 maturity behaviors for AZ-IDENT-036, AWS-PIPEIAM-056, AWS-CBIDENT-057,
PLAT-BRPROT-015, GH-REL-021, GH-PROV-023, GH-DEPLOY-022, AZ-ARTSBOM-058, AZ-ARTPRV-059,
AWS-SBOMART-058, AWS-PROVART-059, AZ-SCONN-056, AZ-WIFEV-057, GOV-EVIDFRESH-054,
CI-WFCALLSHA-055 and ORG-MFA-001.

Each scenario captures the honest downgrade from "inflated confidence via keyword heuristics"
to MANUAL_REVIEW_REQUIRED / NOT_EVALUATED / NOT_APPLICABLE where platform evidence is absent
or ambiguous, while preserving legitimate PASS/SELF_ATTESTED paths when real evidence exists.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from textwrap import dedent

import pytest

from oss_policy_kit.application.evaluators import (
    EvalContext,
    eval_aws_cbident_057,
    eval_aws_pipeiam_056,
    eval_aws_provart_059,
    eval_aws_sbomart_058,
    eval_az_artprv_059,
    eval_az_artsbom_058,
    eval_az_ident_036,
    eval_az_sconn_056,
    eval_az_wifev_057,
    eval_ci_wfcallsha_055,
    eval_gh_dep_022,
    eval_gh_prov_023,
    eval_gh_rel_021,
    eval_gov_evidfresh_054,
    eval_org_mfa_001,
)
from oss_policy_kit.domain.models import ControlStatus, utc_now
from oss_policy_kit.infrastructure.aws_ci_parser import (
    AwsCiAnalysis,
    analyze_aws_ci,
)
from oss_policy_kit.infrastructure.azure_pipeline_parser import (
    AzurePipelineAnalysis,
    analyze_azure_pipelines,
)
from oss_policy_kit.infrastructure.workflow_parser import (
    WorkflowAnalysis,
    analyze_workflows,
)


def _empty_ctx(tmp_path: Path) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-release-hardening-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _ctx_with_analysis(tmp_path: Path) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-release-hardening-1",
        workflows=analyze_workflows(tmp_path),
        azure_pipelines=analyze_azure_pipelines(tmp_path),
        aws_ci=analyze_aws_ci(tmp_path),
        scorecard=None,
    )


def _write_workflow(tmp_path: Path, name: str, content: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / name
    p.write_text(dedent(content).lstrip("\n"), encoding="utf-8")
    return p


def _write_evidence(tmp_path: Path, filename: str, payload: dict) -> Path:
    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    p = evidence_dir / filename
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


# ── Task 1 — P1-A ──────────────────────────────────────────────────────────────


def test_az_ident_036_without_evidence_returns_manual_review(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "azure-deploy.yml",
        """
        azure-pipelines: {}
        """,
    )
    (tmp_path / "azure-pipelines.yml").write_text(
        dedent(
            """
            trigger: main
            stages:
              - stage: deploy
                jobs:
                  - deployment: DeployProd
                    environment: prod
                    strategy:
                      runOnce:
                        deploy:
                          steps:
                            - task: AzureCLI@2
                              inputs:
                                azureSubscription: example-wif-connection
                                scriptType: bash
                                scriptLocation: inlineScript
                                inlineScript: echo WorkloadIdentityFederation
            """
        ).lstrip("\n"),
        encoding="utf-8",
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_az_ident_036(ctx)
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert out.confidence == "low"
    assert "AZ-IDENT-036" in out.reason
    assert "No evidence file found" in out.reason


def test_az_ident_036_with_valid_live_evidence_passes(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "azure-pipeline-governance.json",
        {
            "schema_version": "azure-pipeline-governance/v1",
            "attested_at": "2026-04-15",
            "attested_by": "qa",
            "project": "proj",
            "posture": {
                "approvals_required": True,
                "environment_checks_enabled": True,
                "service_connection_restricted": True,
                "federated_identity_preferred": True,
            },
            "posture_support": {
                "pipelines_api_reachable": True,
                "environments_api_reachable": True,
                "service_endpoints_api_verified": True,
                "environment_approval_checks_observable": True,
            },
            "collection": {
                "evidence_collection_method": "live",
                "collected_at": "2026-04-15T10:00:00Z",
                "source_url": "https://dev.azure.com/example",
                "mode": "api",
            },
            "service_connections": [
                {
                    "name": "example-wif",
                    "authentication": "workload_identity_federation",
                    "federation_subject": "repo:org/repo:ref:refs/heads/main",
                    "issuer_url": "https://token.actions.githubusercontent.com",
                    "audience": "api://AzureADTokenExchange",
                }
            ],
        },
    )
    ctx = _empty_ctx(tmp_path)
    out = eval_az_ident_036(ctx)
    assert out.status == ControlStatus.PASS
    assert out.confidence == "high"


def test_aws_pipeiam_056_without_evidence_returns_manual_review(tmp_path: Path) -> None:
    # Provide a committed CodePipeline export that declares a service role so the
    # committed-export branch is exercised without evidence present.
    pipelines_dir = tmp_path / "pipelines" / "aws"
    pipelines_dir.mkdir(parents=True, exist_ok=True)
    (pipelines_dir / "codepipeline.json").write_text(
        json.dumps(
            {
                "pipeline": {
                    "name": "my-pipeline",
                    "roleArn": "arn:aws:iam::123456789012:role/pipeline-role",
                    "stages": [{"name": "Source"}],
                }
            }
        ),
        encoding="utf-8",
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_aws_pipeiam_056(ctx)
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert out.confidence == "low"
    assert "AWS-PIPEIAM-056" in out.reason


def test_aws_pipeiam_056_with_valid_live_evidence_passes(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "aws-codepipeline.json",
        {
            "schema_version": "aws-codepipeline/v1",
            "attested_at": "2026-04-15",
            "attested_by": "qa",
            "pipeline": "example-pipeline",
            "posture": {
                "manual_approval_before_production": True,
                "artifact_store_encryption_enabled": True,
                "production_execution_mode_not_parallel": True,
            },
            "iam": {
                "pipeline_service_role_arn_configured": True,
            },
            "collection": {
                "evidence_collection_method": "live",
                "collected_at": "2026-04-15T10:00:00Z",
                "source_url": "https://codepipeline.example/aws",
                "mode": "api",
            },
        },
    )
    ctx = _empty_ctx(tmp_path)
    out = eval_aws_pipeiam_056(ctx)
    assert out.status == ControlStatus.PASS
    assert out.confidence == "high"


def test_aws_cbident_057_without_evidence_returns_manual_review(tmp_path: Path) -> None:
    ctx = _empty_ctx(tmp_path)
    out = eval_aws_cbident_057(ctx)
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert out.confidence == "low"
    assert "AWS-CBIDENT-057" in out.reason
    assert "No evidence file found" in out.reason


def test_aws_cbident_057_with_valid_live_evidence_passes(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "aws-codebuild-project.json",
        {
            "schema_version": "aws-codebuild-project/v1",
            "attested_at": "2026-04-15",
            "attested_by": "qa",
            "project": "example-build",
            "posture": {
                "privileged_mode_disabled": True,
                "no_plaintext_credentials_in_project_config": True,
                "codebuild_service_role_configured": True,
            },
            "identity": {
                "service_role_arn_present": True,
                "no_plaintext_environment_credentials": True,
            },
            "collection": {
                "evidence_collection_method": "live",
                "collected_at": "2026-04-15T10:00:00Z",
                "source_url": "https://codebuild.example/aws",
                "mode": "api",
            },
        },
    )
    ctx = _empty_ctx(tmp_path)
    out = eval_aws_cbident_057(ctx)
    assert out.status == ControlStatus.PASS
    assert out.confidence == "high"


# ── Task 3 — P1-C ──────────────────────────────────────────────────────────────


def test_gh_rel_021_fail_reason_contains_workflow_filename(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "release.yml",
        """
        name: release
        on:
          release:
            types: [published]
          push:
            branches: [main]
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """,
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_gh_rel_021(ctx)
    assert out.status == ControlStatus.FAIL
    assert out.confidence == "medium"
    assert "release.yml" in out.reason


def test_gh_rel_021_fail_has_medium_confidence(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "deploy.yml",
        """
        name: deploy
        on:
          push:
            branches: [main]
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """,
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_gh_rel_021(ctx)
    assert out.status == ControlStatus.FAIL
    assert out.confidence == "medium"


# ── Task 4 — P2-A ──────────────────────────────────────────────────────────────


def test_gh_prov_023_not_applicable_without_release_intent(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
        name: ci
        on:
          pull_request:
            branches: [main]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: pytest
        """,
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_gh_prov_023(ctx)
    assert out.status == ControlStatus.NOT_APPLICABLE
    assert out.confidence == "high"
    assert "release" in out.reason.lower() or "publication" in out.reason.lower()


def test_gh_prov_023_fail_when_release_without_provenance(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "release.yml",
        """
        name: release
        on:
          release:
            types: [published]
          push:
            branches: [main]
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
        """,
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_gh_prov_023(ctx)
    assert out.status == ControlStatus.FAIL


def test_gh_prov_023_pass_when_release_with_provenance(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "release.yml",
        """
        name: release
        on:
          release:
            types: [published]
          push:
            branches: [main]
        jobs:
          publish:
            runs-on: ubuntu-latest
            permissions:
              id-token: write
              attestations: write
            steps:
              - uses: actions/attest-build-provenance@v1
              - run: npm publish
        """,
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_gh_prov_023(ctx)
    assert out.status == ControlStatus.PASS


# ── Task 5 — P2-B ──────────────────────────────────────────────────────────────


def test_gh_deploy_022_pass_when_oidc(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "deploy-aws.yml",
        """
        name: deploy
        on:
          push:
            branches: [main]
        permissions:
          id-token: write
          contents: read
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: aws-actions/configure-aws-credentials@v4
                with:
                  role-to-assume: arn:aws:iam::123456789012:role/deploy
                  aws-region: us-east-1
              - run: aws s3 cp ./dist s3://bucket/
        """,
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_gh_dep_022(ctx)
    assert out.status == ControlStatus.PASS


def test_gh_deploy_022_fail_when_long_lived_secret(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "deploy-aws.yml",
        """
        name: deploy
        on:
          push:
            branches: [main]
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: aws-actions/configure-aws-credentials@v4
                with:
                  aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
                  aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
                  aws-region: us-east-1
              - run: aws s3 cp ./dist s3://bucket/
        """,
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_gh_dep_022(ctx)
    assert out.status == ControlStatus.FAIL
    assert "long-lived" in out.reason.lower() or "aws_secret_access_key" in out.reason.lower()


def test_gh_deploy_022_not_applicable_without_cloud_signals(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
        name: ci
        on:
          pull_request:
            branches: [main]
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: pytest
        """,
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_gh_dep_022(ctx)
    assert out.status == ControlStatus.NOT_APPLICABLE


def test_gh_deploy_022_manual_review_when_deploy_without_oidc(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "deploy-k8s.yml",
        """
        name: deploy
        on:
          push:
            branches: [main]
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: kubectl apply -f manifests/
              - run: helm upgrade --install app charts/app
        """,
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_gh_dep_022(ctx)
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


# ── Task 6 — P3-A ──────────────────────────────────────────────────────────────


_SBOM_ARTIFACT_BASE = {
    "schema_version": "azure-sbom-artifact/v1",
    "attested_at": "2026-04-15",
    "attested_by": "qa",
    "project": "proj",
    "artifact": {"name": "app.tgz", "digest_sha256": "f" * 64},
    "sbom": {"name": "app.sbom.json", "digest_sha256": "e" * 64, "format": "spdx-json"},
    "posture": {
        "sbom_covers_release_artifact": True,
        "sbom_digest_recorded": True,
        "artifact_digest_recorded": True,
    },
}


_AWS_SBOM_BASE = {
    "schema_version": "aws-sbom-artifact/v1",
    "attested_at": "2026-04-15",
    "attested_by": "qa",
    "project_name": "app",
    "artifact": {"name": "app.tgz", "digest_sha256": "a3f2" + "b" * 60},
    "sbom": {"name": "app.sbom.json", "digest_sha256": "a3f2" + "c" * 60, "format": "spdx-json"},
    "posture": {
        "sbom_covers_release_artifact": True,
        "sbom_digest_recorded": True,
        "artifact_digest_recorded": True,
    },
}


_PROV_ARTIFACT_BASE = {
    "schema_version": "azure-provenance-artifact/v1",
    "attested_at": "2026-04-15",
    "attested_by": "qa",
    "project": "proj",
    "artifact": {"name": "app.tgz", "digest_sha256": "d" * 64},
    "attestation": {"name": "app.intoto.jsonl", "digest_sha256": "c" * 64, "format": "in-toto"},
    "posture": {
        "attestation_covers_release_artifact": True,
        "attestation_digest_recorded": True,
        "artifact_digest_recorded": True,
    },
}


_AWS_PROV_BASE = {
    "schema_version": "aws-provenance-artifact/v1",
    "attested_at": "2026-04-15",
    "attested_by": "qa",
    "project_name": "app",
    "artifact": {"name": "app.tgz", "digest_sha256": "9f8e" + "a" * 60},
    "attestation": {"name": "app.intoto.jsonl", "digest_sha256": "9f8e" + "b" * 60, "format": "in-toto"},
    "posture": {
        "attestation_covers_release_artifact": True,
        "attestation_digest_recorded": True,
        "artifact_digest_recorded": True,
    },
}


@pytest.mark.parametrize(
    ("filename", "base", "evaluator"),
    [
        ("azure-sbom-artifact.json", _SBOM_ARTIFACT_BASE, eval_az_artsbom_058),
        ("azure-provenance-artifact.json", _PROV_ARTIFACT_BASE, eval_az_artprv_059),
        ("aws-sbom-artifact.json", _AWS_SBOM_BASE, eval_aws_sbomart_058),
        ("aws-provenance-artifact.json", _AWS_PROV_BASE, eval_aws_provart_059),
    ],
)
def test_artifact_digest_placeholder_zeros_not_evaluated(
    tmp_path: Path,
    filename: str,
    base: dict,
    evaluator,
) -> None:
    payload = json.loads(json.dumps(base))
    payload["artifact"]["digest_sha256"] = "0" * 64
    _write_evidence(tmp_path, filename, payload)
    ctx = _empty_ctx(tmp_path)
    out = evaluator(ctx)
    # '0'*64 matches the existing placeholder detector → MANUAL_REVIEW_REQUIRED wins;
    # either outcome (NOT_EVALUATED or MANUAL_REVIEW_REQUIRED) is acceptable as a hard downgrade.
    assert out.status in (ControlStatus.NOT_EVALUATED, ControlStatus.MANUAL_REVIEW_REQUIRED)


@pytest.mark.parametrize(
    ("filename", "base", "evaluator"),
    [
        ("azure-sbom-artifact.json", _SBOM_ARTIFACT_BASE, eval_az_artsbom_058),
        ("azure-provenance-artifact.json", _PROV_ARTIFACT_BASE, eval_az_artprv_059),
        ("aws-sbom-artifact.json", _AWS_SBOM_BASE, eval_aws_sbomart_058),
        ("aws-provenance-artifact.json", _AWS_PROV_BASE, eval_aws_provart_059),
    ],
)
def test_artifact_digest_invalid_length_not_evaluated(
    tmp_path: Path,
    filename: str,
    base: dict,
    evaluator,
) -> None:
    payload = json.loads(json.dumps(base))
    payload["artifact"]["digest_sha256"] = "a" * 63  # 63 chars, invalid SHA-256 length
    _write_evidence(tmp_path, filename, payload)
    ctx = _empty_ctx(tmp_path)
    out = evaluator(ctx)
    # Schema may reject invalid-length digests (MANUAL_REVIEW_REQUIRED from schema validation);
    # digest validator rejects weak/placeholder digests (NOT_EVALUATED). Either is a hard downgrade.
    assert out.status in (ControlStatus.NOT_EVALUATED, ControlStatus.MANUAL_REVIEW_REQUIRED)


# ── Task 7 — P3-B ──────────────────────────────────────────────────────────────


def test_az_sconn_056_rejects_unknown_authentication(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "azure-pipeline-governance.json",
        {
            "schema_version": "azure-pipeline-governance/v1",
            "attested_at": "2026-04-15",
            "attested_by": "qa",
            "project": "proj",
            "posture": {
                "approvals_required": True,
                "environment_checks_enabled": True,
                "service_connection_restricted": True,
                "federated_identity_preferred": True,
            },
            "service_connections": [
                {"name": "mystery-conn", "authentication": "unknown"},
            ],
        },
    )
    ctx = _empty_ctx(tmp_path)
    out = eval_az_sconn_056(ctx)
    assert out.status == ControlStatus.NOT_EVALUATED
    assert "unknown" in out.reason.lower()


def test_az_sconn_056_accepts_workload_identity(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "azure-pipeline-governance.json",
        {
            "schema_version": "azure-pipeline-governance/v1",
            "attested_at": "2026-04-15",
            "attested_by": "qa",
            "project": "proj",
            "posture": {
                "approvals_required": True,
                "environment_checks_enabled": True,
                "service_connection_restricted": True,
                "federated_identity_preferred": True,
            },
            "service_connections": [
                {
                    "name": "example-wif",
                    "authentication": "workload_identity_federation",
                    "federation_subject": "repo:org/repo:ref:refs/heads/main",
                    "issuer_url": "https://token.actions.githubusercontent.com",
                    "audience": "api://AzureADTokenExchange",
                }
            ],
        },
    )
    ctx = _empty_ctx(tmp_path)
    out = eval_az_sconn_056(ctx)
    assert out.status in (ControlStatus.PASS, ControlStatus.SELF_ATTESTED)


# ── Task 8 — P3-C ──────────────────────────────────────────────────────────────


def test_az_wifev_057_rejects_placeholder_federation_subject(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "azure-pipeline-governance.json",
        {
            "schema_version": "azure-pipeline-governance/v1",
            "attested_at": "2026-04-15",
            "attested_by": "qa",
            "project": "proj",
            "posture": {
                "approvals_required": True,
                "environment_checks_enabled": True,
                "service_connection_restricted": True,
                "federated_identity_preferred": True,
            },
            "service_connections": [
                {
                    "name": "example-wif",
                    "authentication": "workload_identity_federation",
                    "federation_subject": "<subject>",
                    "issuer_url": "<issuer>",
                    "audience": "<audience>",
                }
            ],
        },
    )
    ctx = _empty_ctx(tmp_path)
    out = eval_az_wifev_057(ctx)
    assert out.status == ControlStatus.NOT_EVALUATED
    assert "federation_subject" in out.reason or "issuer_url" in out.reason


def test_az_wifev_057_rejects_empty_proof_fields(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "azure-pipeline-governance.json",
        {
            "schema_version": "azure-pipeline-governance/v1",
            "attested_at": "2026-04-15",
            "attested_by": "qa",
            "project": "proj",
            "posture": {
                "approvals_required": True,
                "environment_checks_enabled": True,
                "service_connection_restricted": True,
                "federated_identity_preferred": True,
            },
            "service_connections": [
                {
                    "name": "example-wif",
                    "authentication": "workload_identity_federation",
                    "federation_subject": "   ",
                    "issuer_url": "   ",
                    "audience": "   ",
                }
            ],
        },
    )
    ctx = _empty_ctx(tmp_path)
    out = eval_az_wifev_057(ctx)
    assert out.status == ControlStatus.NOT_EVALUATED


def test_az_wifev_057_accepts_populated_proof_fields(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "azure-pipeline-governance.json",
        {
            "schema_version": "azure-pipeline-governance/v1",
            "attested_at": "2026-04-15",
            "attested_by": "qa",
            "project": "proj",
            "posture": {
                "approvals_required": True,
                "environment_checks_enabled": True,
                "service_connection_restricted": True,
                "federated_identity_preferred": True,
            },
            "service_connections": [
                {
                    "name": "example-wif",
                    "authentication": "workload_identity_federation",
                    "federation_subject": "repo:org/repo:ref:refs/heads/main",
                    "issuer_url": "https://token.actions.githubusercontent.com",
                    "audience": "api://AzureADTokenExchange",
                }
            ],
        },
    )
    ctx = _empty_ctx(tmp_path)
    out = eval_az_wifev_057(ctx)
    assert out.status in (ControlStatus.PASS, ControlStatus.SELF_ATTESTED)


# ── Task 9 — P4-A ──────────────────────────────────────────────────────────────


def test_gov_evidfresh_054_uses_configured_max_age(tmp_path: Path) -> None:
    stale_day = (utc_now().date() - timedelta(days=45)).isoformat()
    _write_evidence(
        tmp_path,
        "branch-protection.json",
        {
            "schema_version": "branch-protection/v1",
            "attested_at": stale_day,
            "attested_by": "qa",
            "branch": "main",
            "protections": {"require_pull_request_reviews": True},
        },
    )
    ctx = EvalContext(
        repo_root=tmp_path,
        profile_id="github-release-hardening-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
        evidence_max_age_days=30,
    )
    out = eval_gov_evidfresh_054(ctx)
    assert out.status == ControlStatus.FAIL
    assert "30 days" in out.reason


def test_gov_evidfresh_054_warns_when_close_to_expiry(tmp_path: Path) -> None:
    recent_but_near_expiry = (utc_now().date() - timedelta(days=80)).isoformat()
    _write_evidence(
        tmp_path,
        "branch-protection.json",
        {
            "schema_version": "branch-protection/v1",
            "attested_at": recent_but_near_expiry,
            "attested_by": "qa",
            "branch": "main",
            "protections": {"require_pull_request_reviews": True},
        },
    )
    ctx = _empty_ctx(tmp_path)  # default max_age = 90
    out = eval_gov_evidfresh_054(ctx)
    assert out.status == ControlStatus.PASS
    assert any("expire" in w.lower() or "stale" in w.lower() for w in out.operational_warnings)


# ── Task 10 — P4-B ─────────────────────────────────────────────────────────────


def test_ci_wfcallsha_055_ignores_sha_in_yaml_comments(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "orchestrator.yml",
        """
        name: orchestrator
        on: [push]
        jobs:
          call:
            # reference SHA in comment: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            uses: ./.github/workflows/reusable.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        """,
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_ci_wfcallsha_055(ctx)
    assert out.status == ControlStatus.PASS


def test_ci_wfcallsha_055_fail_points_to_specific_step(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "orchestrator.yml",
        """
        name: orchestrator
        on: [push]
        jobs:
          bad:
            uses: ./.github/workflows/reusable.yml@main
        """,
    )
    ctx = _ctx_with_analysis(tmp_path)
    out = eval_ci_wfcallsha_055(ctx)
    assert out.status == ControlStatus.FAIL
    assert any("jobs.bad" in src or "orchestrator.yml" in src for src in out.evidence_sources)


# ── Task 11 — P4-C ─────────────────────────────────────────────────────────────


def test_org_mfa_001_all_members_scope_passes(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "org-mfa-posture.json",
        {
            "schema_version": "org-mfa-posture/v1",
            "attested_at": "2026-04-19",
            "attested_by": "security-team",
            "org_name": "my-org",
            "platform": "github",
            "mfa_required_for_all_members": True,
            "mfa_required_for_admins": True,
            "enforcement_scope": "all_members",
        },
    )
    ctx = _empty_ctx(tmp_path)
    out = eval_org_mfa_001(ctx)
    assert out.status in (ControlStatus.PASS, ControlStatus.SELF_ATTESTED)


def test_org_mfa_001_admins_only_scope_manual_review(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "org-mfa-posture.json",
        {
            "schema_version": "org-mfa-posture/v1",
            "attested_at": "2026-04-19",
            "attested_by": "security-team",
            "org_name": "my-org",
            "platform": "github",
            "mfa_required_for_all_members": True,
            "mfa_required_for_admins": True,
            "enforcement_scope": "admins_only",
        },
    )
    ctx = _empty_ctx(tmp_path)
    out = eval_org_mfa_001(ctx)
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "admins_only" in out.reason


def test_org_mfa_001_without_scope_has_operational_warning(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "org-mfa-posture.json",
        {
            "schema_version": "org-mfa-posture/v1",
            "attested_at": "2026-04-19",
            "attested_by": "security-team",
            "org_name": "my-org",
            "platform": "github",
            "mfa_required_for_all_members": True,
            "mfa_required_for_admins": True,
        },
    )
    ctx = _empty_ctx(tmp_path)
    out = eval_org_mfa_001(ctx)
    assert out.status in (ControlStatus.PASS, ControlStatus.SELF_ATTESTED)
    assert any("enforcement_scope" in w or "scope" in w.lower() for w in out.operational_warnings)
