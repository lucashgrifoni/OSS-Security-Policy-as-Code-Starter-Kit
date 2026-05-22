"""Helper + HTTP-branch coverage for the Azure DevOps evidence collector."""

from __future__ import annotations

from typing import Any

import pytest

from oss_policy_kit.domain.errors import CollectionPermissionError, RateLimitError
from oss_policy_kit.infrastructure.collectors import azure_collector as ac


class _Resp:
    def __init__(self, status: int, body: Any = None, headers: dict[str, str] | None = None) -> None:
        self.status_code = status
        self._body = body if body is not None else {}
        self.headers = headers or {}

    def json(self) -> Any:
        return self._body


class _Client:
    """Minimal stub: returns queued responses by call order; exposes base_url."""

    def __init__(self, responses: list[_Resp]) -> None:
        self._responses = responses
        self._i = 0
        self.base_url = "https://dev.azure.com/org"

    def get(self, _url: str) -> _Resp:
        r = self._responses[min(self._i, len(self._responses) - 1)]
        self._i += 1
        return r


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #


def test_parse_project_repo() -> None:
    assert ac._parse_project_repo("Proj/repo") == ("Proj", "repo")
    for bad in ("noslash", "P/", "/r", "a/b/c"):
        with pytest.raises(ValueError, match="Invalid Azure repo slug"):
            ac._parse_project_repo(bad)


def test_azure_headers_and_timestamps() -> None:
    h = ac._azure_headers("pat123")
    assert h["Authorization"].startswith("Basic ")
    assert ac._iso_date_prefix("2026-05-01T10:00:00Z") == "2026-05-01"
    assert ac._iso_date_prefix("short") == "short"
    assert ac._utc_iso_timestamp().endswith("Z")


def test_policy_applies_to_repository() -> None:
    assert ac._policy_applies_to_repository({"settings": {"scope": [{"repositoryId": "ABC"}]}}, "abc")
    assert ac._policy_applies_to_repository({"settings": {"scope": {"repositoryId": "abc"}}}, "abc")
    assert not ac._policy_applies_to_repository({"settings": {"scope": [{"repositoryId": "x"}]}}, "abc")
    assert not ac._policy_applies_to_repository({"settings": "notdict"}, "abc")


def test_infer_branch_posture_all_types() -> None:
    rid = "repo1"
    configs = [
        {
            "type": {"id": ac._POLICY_MINIMUM_REVIEWERS},
            "settings": {"scope": [{"repositoryId": rid}], "minimumApproverCount": 2},
        },
        {"type": {"id": ac._POLICY_BUILD}, "settings": {"scope": [{"repositoryId": rid}]}},
        {"type": {"id": ac._POLICY_COMMENT_REQUIREMENTS}, "settings": {"scope": [{"repositoryId": rid}]}},
        {"type": {"id": ac._POLICY_RESET_REVIEWER_VOTES}, "settings": {"scope": [{"repositoryId": rid}]}},
        {"type": {"id": ac._POLICY_BLOCK_LAST_PUSHER}, "settings": {"scope": [{"repositoryId": rid}]}},
        {"type": {"id": ac._POLICY_BYPASS}, "settings": {"scope": [{"repositoryId": rid}], "allowBypass": False}},
        "not-a-dict",
        {"type": {"id": "other"}, "settings": {"scope": [{"repositoryId": "elsewhere"}]}},
    ]
    posture = ac._infer_branch_posture(configs, rid)
    assert all(posture.values())


def test_service_endpoint_auth_kind() -> None:
    assert (
        ac._service_endpoint_auth_kind({"authorization": {"scheme": "WorkloadIdentityFederation"}})
        == "workload_identity_federation"
    )
    assert ac._service_endpoint_auth_kind({"authorization": {"scheme": "ManagedServiceIdentity"}}) == "managed_identity"
    assert ac._service_endpoint_auth_kind({"authorization": {"scheme": "UsernamePassword"}}) == "secret"
    assert ac._service_endpoint_auth_kind({"authorization": {"scheme": "Certificate"}}) == "certificate"
    assert ac._service_endpoint_auth_kind({"authorization": {"scheme": "weird"}}) == "unknown"


def test_check_configuration_looks_like_approval() -> None:
    assert ac._check_configuration_looks_like_approval({"type": {"name": "Approval"}})
    assert not ac._check_configuration_looks_like_approval({"type": {"name": "Build"}})
    assert not ac._check_configuration_looks_like_approval({"type": "notdict"})


def test_default_branch_name() -> None:
    assert ac._default_branch_name({"defaultBranch": "refs/heads/main"}) == "main"
    assert ac._default_branch_name({"defaultBranch": "feature/x"}) == "x"
    assert ac._default_branch_name({}) == "main"


def test_collection_block() -> None:
    b = ac._azure_collection_block("2026-05-01T00:00:00Z", "https://dev.azure.com/org/_apis/x")
    assert b["mode"] == "api" and b["evidence_collection_method"] == "live"


def test_rate_limit_and_permission() -> None:
    with pytest.raises(RateLimitError):
        ac._enforce_rate_limit(_Resp(429, headers={"retry-after": "30"}))
    ac._enforce_rate_limit(_Resp(200))  # no raise
    with pytest.raises(CollectionPermissionError):
        ac._raise_permission("https://x", 403)


# --------------------------------------------------------------------------- #
# HTTP-branch helpers via stub client
# --------------------------------------------------------------------------- #


def test_environment_has_approval_check() -> None:
    ok = _Client([_Resp(200, {"value": [{"type": {"name": "Approval"}}]})])
    assert ac._environment_has_approval_check(ok, "Proj", "1") is True
    none_403 = _Client([_Resp(403)])
    assert ac._environment_has_approval_check(none_403, "Proj", "1") is None
    # 404 on first api-version -> continue -> 200 on second
    fallthrough = _Client([_Resp(404), _Resp(200, {"value": []})])
    assert ac._environment_has_approval_check(fallthrough, "Proj", "1") is False


def test_service_connection_posture() -> None:
    body = {
        "value": [
            {"name": "wif", "authorization": {"scheme": "WorkloadIdentityFederation"}},
            {"name": "pw", "authorization": {"scheme": "UsernamePassword"}},
        ]
    }
    conns, posture, _notes, status = ac._azure_service_connection_posture(_Client([_Resp(200, body)]), "Proj")
    assert status == 200
    assert posture["federated_identity_preferred"] is True
    # has username/password -> not restricted
    assert posture["service_connection_restricted"] is False
    assert len(conns) == 2


def test_service_connection_posture_permission_error() -> None:
    with pytest.raises(CollectionPermissionError):
        ac._azure_service_connection_posture(_Client([_Resp(403)]), "Proj")


def test_service_connection_posture_non_200() -> None:
    conns, posture, _notes, status = ac._azure_service_connection_posture(_Client([_Resp(500)]), "Proj")
    assert status == 500 and conns == [] and posture["service_connection_restricted"] is False
