"""Not-found ValueError branch coverage for the AWS collector (moto)."""

from __future__ import annotations

import pytest
from moto import mock_aws

from oss_policy_kit.infrastructure.collectors.aws_collector import (
    _ENV_CODEBUILD,
    _ENV_CODEPIPELINE,
    AWSEvidenceCollector,
)


@mock_aws
def test_codebuild_project_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv(_ENV_CODEBUILD, "no-such-project")
    monkeypatch.delenv(_ENV_CODEPIPELINE, raising=False)
    with pytest.raises(ValueError, match="not found"):
        AWSEvidenceCollector().collect("")


@mock_aws
def test_codepipeline_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv(_ENV_CODEBUILD, raising=False)
    monkeypatch.setenv(_ENV_CODEPIPELINE, "no-such-pipeline")
    with pytest.raises(ValueError, match="not found"):
        AWSEvidenceCollector().collect("")
