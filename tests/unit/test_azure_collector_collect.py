"""Happy-path + degradation coverage for ``AzureDevOpsEvidenceCollector.collect`` (httpx mocked)."""

from __future__ import annotations

import httpx
import pytest

from oss_policy_kit.domain.errors import CollectionPermissionError
from oss_policy_kit.infrastructure.collectors.azure_collector import AzureDevOpsEvidenceCollector


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def _client(**kwargs: object) -> httpx.Client:
        merged = dict(kwargs)
        merged["transport"] = transport
        return real_client(**merged)

    monkeypatch.setattr(httpx, "Client", _client)


def _full_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.endswith("/_apis/git/repositories"):
        return httpx.Response(200, json={"value": [{"name": "repo", "id": "RID", "defaultBranch": "refs/heads/main"}]})
    if path.endswith("/_apis/policy/configurations"):
        return httpx.Response(200, json={"value": [
            {"type": {"id": "fa4e907d-c16f-4ac8-9af7-9a14fae485e1"},
             "settings": {"scope": [{"repositoryId": "RID"}], "minimumApproverCount": 2}},
        ]})
    if path.endswith("/_apis/serviceendpoint/endpoints"):
        return httpx.Response(200, json={"value": [
            {"name": "wif", "authorization": {"scheme": "WorkloadIdentityFederation"}},
        ]})
    if path.endswith("/_apis/pipelines"):
        return httpx.Response(200, json={"value": []})
    if path.endswith("/_apis/distributedtask/environments"):
        return httpx.Response(200, json={"value": [{"id": 1, "name": "prod"}]})
    if "/_apis/check/configurations" in path:
        return httpx.Response(200, json={"value": [{"type": {"name": "Approval"}}]})
    return httpx.Response(404, json={"message": "unexpected"})


def test_collect_full_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, _full_handler)
    rows = AzureDevOpsEvidenceCollector(organization="org", personal_access_token="pat").collect("Proj/repo")
    keys = {r.evidence_key for r in rows}
    assert "azure-branch-policies" in keys
    bp = next(r for r in rows if r.evidence_key == "azure-branch-policies").data
    assert bp["schema_version"] == "azure-branch-policies/v1"
    assert bp["posture"]["minimum_reviewers_enabled"] is True
    assert bp["attested_by"] == "azure-devops-api-collection"


def test_collect_permission_error_on_repos_403(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, lambda r: httpx.Response(403, json={"message": "denied"}))
    with pytest.raises(CollectionPermissionError):
        AzureDevOpsEvidenceCollector(organization="org", personal_access_token="pat").collect("Proj/repo")


def test_collect_repo_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/_apis/git/repositories"):
            return httpx.Response(200, json={"value": [{"name": "other", "id": "X"}]})
        return httpx.Response(200, json={"value": []})

    _patch_client(monkeypatch, handler)
    with pytest.raises(ValueError, match="not found"):
        AzureDevOpsEvidenceCollector(organization="org", personal_access_token="pat").collect("Proj/repo")


def test_collect_repos_422_aborts(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/_apis/git/repositories"):
            return httpx.Response(422, json={"message": "unprocessable"})
        return httpx.Response(200, json={"value": []})

    _patch_client(monkeypatch, handler)
    rows = AzureDevOpsEvidenceCollector(organization="org", personal_access_token="pat").collect("Proj/repo")
    assert rows == []  # 422 on repos -> abort, no evidence
