"""Branch coverage for AWS evidence-backed evaluators AWS-CBIDENT-057 / AWS-PIPEIAM-056."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import aws as awsev
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, aws: AwsCiAnalysis | None = None) -> awsev.EvalContext:
    return awsev.EvalContext(
        repo_root=tmp_path,
        profile_id="aws-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=aws or AwsCiAnalysis(),
        scorecard=None,
    )


def _ev(tmp_path: Path, name: str, payload: dict) -> None:
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


def _cb_evidence(*, identity: dict | None, api: bool) -> dict:
    d = {
        "schema_version": "aws-codebuild-project/v1",
        "attested_at": "2026-05-01",
        "attested_by": "aws-api-collection" if api else "platform team",
        "project": "build",
        "posture": {"privileged_mode_disabled": True, "no_plaintext_credentials_in_project_config": True},
    }
    if identity is not None:
        d["identity"] = identity
    return d


# --------------------------------------------------------------------------- #
# AWS-CBIDENT-057
# --------------------------------------------------------------------------- #


def test_cbident_057_missing(tmp_path: Path) -> None:
    assert awsev.eval_aws_cbident_057(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_cbident_057_no_identity_block(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-codebuild-project.json", _cb_evidence(identity=None, api=False))
    assert awsev.eval_aws_cbident_057(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_cbident_057_missing_flag(tmp_path: Path) -> None:
    ident = {"service_role_arn_present": True, "no_plaintext_environment_credentials": False}
    _ev(tmp_path, "aws-codebuild-project.json", _cb_evidence(identity=ident, api=False))
    assert awsev.eval_aws_cbident_057(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_cbident_057_self_attested(tmp_path: Path) -> None:
    ident = {"service_role_arn_present": True, "no_plaintext_environment_credentials": True}
    _ev(tmp_path, "aws-codebuild-project.json", _cb_evidence(identity=ident, api=False))
    assert awsev.eval_aws_cbident_057(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_cbident_057_api_pass(tmp_path: Path) -> None:
    ident = {"service_role_arn_present": True, "no_plaintext_environment_credentials": True}
    _ev(tmp_path, "aws-codebuild-project.json", _cb_evidence(identity=ident, api=True))
    assert awsev.eval_aws_cbident_057(_ctx(tmp_path)).status == ControlStatus.PASS


# --------------------------------------------------------------------------- #
# AWS-PIPEIAM-056
# --------------------------------------------------------------------------- #


def _cp_evidence(*, role_configured: bool, api: bool) -> dict:
    return {
        "schema_version": "aws-codepipeline/v1",
        "attested_at": "2026-05-01",
        "attested_by": "aws-api-collection" if api else "platform team",
        "pipeline": "prod",
        "posture": {
            "manual_approval_before_production": True,
            "artifact_store_encryption_enabled": True,
            "production_execution_mode_not_parallel": True,
        },
        "iam": {"pipeline_service_role_arn_configured": role_configured},
    }


def test_pipeiam_056_missing(tmp_path: Path) -> None:
    assert awsev.eval_aws_pipeiam_056(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_pipeiam_056_api_pass(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-codepipeline.json", _cp_evidence(role_configured=True, api=True))
    assert awsev.eval_aws_pipeiam_056(_ctx(tmp_path)).status == ControlStatus.PASS


def test_pipeiam_056_self_attested(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-codepipeline.json", _cp_evidence(role_configured=True, api=False))
    assert awsev.eval_aws_pipeiam_056(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_pipeiam_056_role_not_configured_falls_through(tmp_path: Path) -> None:
    # iam role not configured -> evidence path returns None -> committed-signal manual-review branch.
    _ev(tmp_path, "aws-codepipeline.json", _cp_evidence(role_configured=False, api=True))
    aws = AwsCiAnalysis(codepipeline_committed_iam_role_paths=[tmp_path / "pipelines" / "aws" / "codepipeline.json"])
    assert awsev.eval_aws_pipeiam_056(_ctx(tmp_path, aws)).status == ControlStatus.MANUAL_REVIEW_REQUIRED
