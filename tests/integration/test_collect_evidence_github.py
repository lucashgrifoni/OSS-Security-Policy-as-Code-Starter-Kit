"""Live checks of the GitHub collector against the real API (requires network and a token).

Runs weekly in `.github/workflows/live-collector-canary.yml` with the workflow's own token,
which has `contents: read` on this repository and nothing on `octocat/Hello-World`.

This module used to collect from `octocat/Hello-World` and evaluate the result end to end. It
never passed: every scheduled run from the first, on 2026-09-21, stopped at HTTP 403 on
`GET /repos/octocat/Hello-World/branches/master/protection`. That endpoint needs
`administration: read` on the repository, which no token here can hold for a repository GitHub
owns, and the collector raises on that 403 on purpose (see `GitHubEvidenceCollector.collect`), so
an operator widens the scope instead of getting a report built on missing evidence. The test
asked for something the token cannot have.

What only a live call can show is the shape GitHub returns. So this checks the two things the
collector depends on that a workflow token can reach: the repository object it reads first, and
the 403 it relies on to refuse a token without the administration scope. Every other path is
exercised offline in `tests/unit/test_github_collector_degraded_api.py`.
"""

from __future__ import annotations

import os

import httpx
import pytest

from oss_policy_kit.domain.errors import CollectionPermissionError
from oss_policy_kit.infrastructure.collectors.github_collector import (
    GITHUB_API,
    GitHubEvidenceCollector,
    _fetch_repo_metadata,
    _github_headers,
)

pytestmark = pytest.mark.skipif(not os.environ.get("GITHUB_TOKEN"), reason="GITHUB_TOKEN not set")

_OWNER, _REPO = "octocat", "Hello-World"


def _repository_object() -> dict[str, object]:
    with httpx.Client(base_url=GITHUB_API, headers=_github_headers(os.environ["GITHUB_TOKEN"]), timeout=60.0) as client:
        repo_json = _fetch_repo_metadata(client, _OWNER, _REPO)
    assert repo_json is not None, "GitHub answered 422 for a public repository"
    return repo_json


def test_the_repository_object_carries_what_the_collector_reads() -> None:
    """`default_branch` names the protection URL; `security_and_analysis` feeds secret scanning."""

    repo_json = _repository_object()

    assert repo_json["full_name"] == f"{_OWNER}/{_REPO}"
    assert isinstance(repo_json["default_branch"], str)
    assert repo_json["default_branch"]
    # GitHub omits `security_and_analysis` for callers without admin rights; the collector
    # reads it with `.get(...) or {}`, so absent is a supported shape and only a wrong type is not.
    assert isinstance(repo_json.get("security_and_analysis") or {}, dict)


def test_a_token_without_administration_read_is_refused_on_branch_protection() -> None:
    """The collector's contract: 403 on branch protection stops collection with a scope hint."""

    branch = _repository_object()["default_branch"]

    with pytest.raises(CollectionPermissionError) as excinfo:
        GitHubEvidenceCollector(os.environ["GITHUB_TOKEN"]).collect(f"{_OWNER}/{_REPO}")

    message = str(excinfo.value)
    assert "HTTP 403" in message
    assert f"/repos/{_OWNER}/{_REPO}/branches/{branch}/protection" in message
    assert "administration" in message
