"""Error/degradation-branch coverage for the GitHub evidence collector."""

from __future__ import annotations

import httpx
import pytest

from oss_policy_kit.infrastructure.collectors import github_collector as gc
from oss_policy_kit.infrastructure.collectors.github_collector import GitHubEvidenceCollector


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #


def test_parse_owner_repo() -> None:
    assert gc._parse_owner_repo("o/r") == ("o", "r")
    for bad in ("noslash", "o/", "/r", "a/b/c"):
        with pytest.raises(ValueError, match="Invalid GitHub repo slug"):
            gc._parse_owner_repo(bad)


def test_status_block_enabled() -> None:
    assert gc._status_block_enabled({"status": "enabled"})
    assert not gc._status_block_enabled({"status": "disabled"})
    assert not gc._status_block_enabled("not-a-dict")


def test_github_collection_block() -> None:
    b = gc._github_collection_block("2026-05-01T00:00:00Z", "https://api.github.com/repos/o/r")
    assert b["evidence_collection_method"] == "live" and b["mode"] == "api"


# --------------------------------------------------------------------------- #
# graceful degradation on optional-endpoint 404 / 422
# --------------------------------------------------------------------------- #


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def _client(**kwargs: object) -> httpx.Client:
        merged = dict(kwargs)
        merged["transport"] = transport
        return real_client(**merged)

    monkeypatch.setattr(httpx, "Client", _client)


def test_collect_graceful_on_404_and_422(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/o/r":
            return httpx.Response(200, json={"default_branch": "main", "security_and_analysis": {}})
        if path.endswith("/protection"):
            return httpx.Response(404, json={"message": "not protected"})
        if path.endswith("/rulesets"):
            return httpx.Response(422, json={"message": "unprocessable"})
        if path.endswith("/environments"):
            return httpx.Response(404, json={"message": "none"})
        return httpx.Response(404, json={"message": "x"})

    _patch_client(monkeypatch, handler)
    rows = GitHubEvidenceCollector("tok").collect("o/r")
    # Collection still succeeds with conservative payloads despite 404/422 on optional endpoints.
    assert rows
    keys = {r.evidence_key for r in rows}
    assert "branch-protection" in keys


def test_collect_invalid_slug(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, lambda r: httpx.Response(200, json={}))
    with pytest.raises(ValueError, match="Invalid GitHub repo slug"):
        GitHubEvidenceCollector("tok").collect("bogus-no-slash")


def test_collect_repo_metadata_422_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/o/r":
            return httpx.Response(422, json={"message": "unprocessable"})
        return httpx.Response(200, json={})

    _patch_client(monkeypatch, handler)
    rows = GitHubEvidenceCollector("tok").collect("o/r")
    assert rows == []  # 422 on repo metadata -> skip repo entirely
