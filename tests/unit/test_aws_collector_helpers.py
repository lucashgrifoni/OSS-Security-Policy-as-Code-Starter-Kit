"""Pure-helper coverage for the AWS evidence collector (no boto3/moto needed)."""

from __future__ import annotations

import pytest

from oss_policy_kit.domain.errors import CollectionNetworkError, CollectionPermissionError, RateLimitError
from oss_policy_kit.infrastructure.collectors import aws_collector as ac


class _ClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def test_timestamps() -> None:
    assert ac._utc_iso_timestamp().endswith("Z")
    assert ac._iso_date_prefix("2026-05-01T00:00:00Z") == "2026-05-01"
    assert ac._iso_date_prefix("x") == "x"


def test_client_error_code() -> None:
    assert ac._client_error_code(_ClientError("AccessDeniedException")) == "AccessDeniedException"
    assert ac._client_error_code(Exception("no response attr")) == ""


def test_map_client_error_permission() -> None:
    with pytest.raises(CollectionPermissionError):
        ac._map_client_error(_ClientError("AccessDeniedException"), operation="BatchGetProjects")


def test_map_client_error_rate_limit() -> None:
    with pytest.raises(RateLimitError):
        ac._map_client_error(_ClientError("ThrottlingException"), operation="GetPipeline")


def test_map_client_error_network() -> None:
    with pytest.raises(CollectionNetworkError):
        ac._map_client_error(_ClientError("SomethingElse"), operation="GetPipeline")


def test_artifact_store_encryption_enabled() -> None:
    assert ac._artifact_store_encryption_enabled({"artifactStore": {"encryptionKey": {"id": "k"}}})
    assert ac._artifact_store_encryption_enabled({"artifactStores": {"us": {"encryptionKey": {"id": "k"}}}})
    assert not ac._artifact_store_encryption_enabled({"artifactStores": {"us": {"location": "x"}}})
    assert not ac._artifact_store_encryption_enabled({})


def test_manual_approval_before_production() -> None:
    stages = [
        {"name": "Source", "actions": [{"actionTypeId": {"category": "Source"}}]},
        {"name": "Approve", "actions": [{"actionTypeId": {"category": "Approval", "provider": "Manual"}}]},
        {"name": "Deploy", "actions": []},
    ]
    assert ac._manual_approval_before_production(stages)
    assert not ac._manual_approval_before_production([{"name": "only"}])  # < 2 stages
    no_approval = [{"name": "a", "actions": []}, {"name": "b", "actions": []}]
    assert not ac._manual_approval_before_production(no_approval)


def test_production_execution_mode_not_parallel() -> None:
    assert ac._production_execution_mode_not_parallel({"executionMode": "QUEUED"})
    assert not ac._production_execution_mode_not_parallel({"executionMode": "PARALLEL"})
    assert ac._production_execution_mode_not_parallel({})


def test_codebuild_posture() -> None:
    project = {
        "environment": {
            "privilegedMode": False,
            "environmentVariables": [{"name": "X", "type": "PLAINTEXT"}],
        },
        "serviceRole": "arn:aws:iam::123456789012:role/build",
    }
    posture = ac._codebuild_posture(project)
    assert posture["privileged_mode_disabled"] is True
    assert posture["no_plaintext_credentials_in_project_config"] is False
    assert posture["codebuild_service_role_configured"] is True

    clean = {
        "environment": {"privilegedMode": True, "environmentVariables": [{"name": "Y", "type": "PARAMETER_STORE"}]},
        "serviceRole": "not-an-arn",
    }
    posture2 = ac._codebuild_posture(clean)
    assert posture2["privileged_mode_disabled"] is False
    assert posture2["no_plaintext_credentials_in_project_config"] is True
    assert posture2["codebuild_service_role_configured"] is False
