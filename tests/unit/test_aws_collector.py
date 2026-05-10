"""Unit tests for :mod:`oss_policy_kit.infrastructure.collectors.aws_collector`."""

from __future__ import annotations

import json
import os
from typing import Any, cast
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from oss_policy_kit.domain.errors import (
    CollectionNetworkError,
    CollectionPermissionError,
    RateLimitError,
)
from oss_policy_kit.infrastructure.collectors.aws_collector import (
    _ENV_CODEBUILD,
    _ENV_CODEPIPELINE,
    AWSEvidenceCollector,
)


def _iam_role_arn(iam: Any, *, name: str, service: str) -> str:
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
            }
        ),
    )
    return str(iam.get_role(RoleName=name)["Role"]["Arn"])


@mock_aws
def test_collect_codebuild_project_via_env() -> None:
    region = "us-east-1"
    iam = boto3.client("iam", region_name=region)
    cb_role = _iam_role_arn(iam, name="codebuild-kit-role", service="codebuild.amazonaws.com")

    s3 = boto3.client("s3", region_name=region)
    s3.create_bucket(Bucket="kit-cb-src")
    s3.put_object(Bucket="kit-cb-src", Key="dummy.zip", Body=b"x")

    cb = boto3.client("codebuild", region_name=region)
    cb.create_project(
        name="kit-test-build",
        source={"type": "S3", "location": "kit-cb-src/dummy.zip"},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
            "privilegedMode": False,
            "environmentVariables": [],
        },
        serviceRole=cb_role,
    )
    old = os.environ.get(_ENV_CODEBUILD)
    os.environ[_ENV_CODEBUILD] = "kit-test-build"
    try:
        rows = AWSEvidenceCollector(region_name=region).collect("")
        assert {r.evidence_key for r in rows} == {"aws-codebuild-project"}
        data = rows[0].data
        assert data["posture"]["privileged_mode_disabled"] is True
        assert data["posture"]["no_plaintext_credentials_in_project_config"] is True
        assert data["collection"]["evidence_collection_method"] == "live"
        assert data["identity"]["service_role_arn_present"] is True
    finally:
        if old is None:
            os.environ.pop(_ENV_CODEBUILD, None)
        else:
            os.environ[_ENV_CODEBUILD] = old


@mock_aws
def test_collect_codepipeline_encryption_and_approval() -> None:
    region = "us-east-1"
    iam = boto3.client("iam", region_name=region)
    pipe_role = _iam_role_arn(iam, name="codepipeline-kit-role", service="codepipeline.amazonaws.com")

    s3 = boto3.client("s3", region_name=region)
    s3.create_bucket(Bucket="pipeline-artifacts-kit")
    s3.put_object(Bucket="pipeline-artifacts-kit", Key="src.zip", Body=b"x")

    cp = boto3.client("codepipeline", region_name=region)
    cp.create_pipeline(
        pipeline={
            "name": "kit-pipe",
            "roleArn": pipe_role,
            "artifactStore": {
                "type": "S3",
                "location": "pipeline-artifacts-kit",
                "encryptionKey": {"id": "alias/aws/s3", "type": "KMS"},
            },
            "stages": [
                {
                    "name": "Source",
                    "actions": [
                        {
                            "name": "Source",
                            "actionTypeId": {
                                "category": "Source",
                                "owner": "AWS",
                                "provider": "S3",
                                "version": "1",
                            },
                            "runOrder": 1,
                            "configuration": {"S3Bucket": "pipeline-artifacts-kit", "S3ObjectKey": "src.zip"},
                            "outputArtifacts": [{"name": "src"}],
                        }
                    ],
                },
                {
                    "name": "Approve",
                    "actions": [
                        {
                            "name": "Manual",
                            "actionTypeId": {
                                "category": "Approval",
                                "owner": "AWS",
                                "provider": "Manual",
                                "version": "1",
                            },
                            "runOrder": 1,
                        }
                    ],
                },
                {
                    "name": "Deploy",
                    "actions": [
                        {
                            "name": "Deploy",
                            "actionTypeId": {
                                "category": "Deploy",
                                "owner": "AWS",
                                "provider": "S3",
                                "version": "1",
                            },
                            "inputArtifacts": [{"name": "src"}],
                            "runOrder": 1,
                        }
                    ],
                },
            ],
        }
    )

    old = os.environ.get(_ENV_CODEPIPELINE)
    os.environ[_ENV_CODEPIPELINE] = "kit-pipe"
    try:
        rows = AWSEvidenceCollector(region_name=region).collect("")
        assert {r.evidence_key for r in rows} == {"aws-codepipeline"}
        row0 = rows[0]
        posture = cast(dict[str, Any], row0.data["posture"])
        assert posture["manual_approval_before_production"] is True
        assert posture["artifact_store_encryption_enabled"] is True
        assert posture["production_execution_mode_not_parallel"] is True
        assert row0.data["collection"]["evidence_collection_method"] == "live"
        assert row0.data["iam"]["pipeline_service_role_arn_configured"] is True
    finally:
        if old is None:
            os.environ.pop(_ENV_CODEPIPELINE, None)
        else:
            os.environ[_ENV_CODEPIPELINE] = old


def test_collect_raises_value_error_when_no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without CodeBuild/CodePipeline env, the collector must abort early with actionable guidance."""

    monkeypatch.delenv(_ENV_CODEBUILD, raising=False)
    monkeypatch.delenv(_ENV_CODEPIPELINE, raising=False)
    with pytest.raises(ValueError) as excinfo:
        AWSEvidenceCollector(region_name="us-east-1").collect("")
    msg = str(excinfo.value)
    assert _ENV_CODEBUILD in msg
    assert _ENV_CODEPIPELINE in msg
    assert "--dry-run" in msg


def test_access_denied_on_codebuild_is_permission_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """``AccessDeniedException`` from any AWS API surfaces as a typed ``CollectionPermissionError``."""

    cb_client = MagicMock()
    cb_client.batch_get_projects.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        "BatchGetProjects",
    )

    class _FakeSession:
        def __init__(self, region_name: str | None = None) -> None:
            self._region = region_name

        def client(self, name: str, **kwargs: Any) -> Any:
            if name == "codebuild":
                return cb_client
            raise AssertionError(f"unexpected client {name}")

    monkeypatch.setattr("boto3.Session", _FakeSession)
    monkeypatch.setenv(_ENV_CODEBUILD, "restricted-build")
    monkeypatch.delenv(_ENV_CODEPIPELINE, raising=False)

    with pytest.raises(CollectionPermissionError) as excinfo:
        AWSEvidenceCollector(region_name="us-east-1").collect("")
    # Error text must mention the operation name (actionable for IAM policy widening).
    assert "BatchGetProjects" in str(excinfo.value)


def test_throttling_on_codepipeline_is_rate_limit_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """``ThrottlingException`` surfaces as ``RateLimitError`` so CI runners can back off correctly."""

    cp_client = MagicMock()
    cp_client.get_pipeline.side_effect = ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "slow down"}},
        "GetPipeline",
    )

    class _FakeSession:
        def __init__(self, region_name: str | None = None) -> None:
            self._region = region_name

        def client(self, name: str, **kwargs: Any) -> Any:
            if name == "codepipeline":
                return cp_client
            raise AssertionError(f"unexpected client {name}")

    monkeypatch.setattr("boto3.Session", _FakeSession)
    monkeypatch.delenv(_ENV_CODEBUILD, raising=False)
    monkeypatch.setenv(_ENV_CODEPIPELINE, "busy-pipe")

    with pytest.raises(RateLimitError):
        AWSEvidenceCollector(region_name="us-east-1").collect("")


def test_unmapped_codebuild_client_error_wrapped_as_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unknown AWS client error codes must still surface as a typed collector failure, not raw boto3."""

    cb_client = MagicMock()
    cb_client.batch_get_projects.side_effect = ClientError(
        {"Error": {"Code": "InternalServerError", "Message": "broken"}},
        "BatchGetProjects",
    )

    class _FakeSession:
        def __init__(self, region_name: str | None = None) -> None:
            self._region = region_name

        def client(self, name: str, **kwargs: Any) -> Any:
            if name == "codebuild":
                return cb_client
            raise AssertionError(f"unexpected client {name}")

    monkeypatch.setattr("boto3.Session", _FakeSession)
    monkeypatch.setenv(_ENV_CODEBUILD, "some-build")
    monkeypatch.delenv(_ENV_CODEPIPELINE, raising=False)

    with pytest.raises(CollectionNetworkError):
        AWSEvidenceCollector(region_name="us-east-1").collect("")
