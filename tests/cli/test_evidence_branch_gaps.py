"""Branch-coverage gaps for cli.evidence collector helpers and command error dispatch."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import evidence
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()


# --------------------------------------------------------------------------- #
# _build_evidence_collector unsupported platform (line 196)
# --------------------------------------------------------------------------- #


def test_build_collector_unsupported_platform(tmp_path: Path) -> None:
    with pytest.raises(InvalidInputError):
        evidence._build_evidence_collector("bogus", "bogus", tmp_path, None)


# --------------------------------------------------------------------------- #
# _github_collector missing slug (lines 207-211)
# --------------------------------------------------------------------------- #


def test_github_collector_missing_slug(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_dummy")
    monkeypatch.setattr(evidence, "read_github_repo_slug_from_git_config", lambda _repo: None)
    with pytest.raises(InvalidInputError):
        evidence._github_collector(tmp_path, None)


# --------------------------------------------------------------------------- #
# _azure_collector missing slug (lines 222-225)
# --------------------------------------------------------------------------- #


def test_azure_collector_missing_slug(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_DEVOPS_ORG", "acme")
    monkeypatch.setenv("AZURE_DEVOPS_TOKEN", "pat")
    with pytest.raises(InvalidInputError):
        evidence._azure_collector(None)


# --------------------------------------------------------------------------- #
# _aws_collector requires env, then returns a collector (lines 231-233)
# --------------------------------------------------------------------------- #


def test_aws_collector_requires_env(monkeypatch) -> None:
    monkeypatch.delenv("AWS_CODEBUILD_PROJECT", raising=False)
    monkeypatch.delenv("AWS_CODEPIPELINE_NAME", raising=False)
    with pytest.raises(InvalidInputError):
        evidence._aws_collector(None)


def test_aws_collector_returns_with_env(monkeypatch) -> None:
    monkeypatch.setenv("AWS_CODEBUILD_PROJECT", "my-build")
    collector, slug = evidence._aws_collector("org/repo")
    assert collector is not None and slug == "org/repo"


# --------------------------------------------------------------------------- #
# collect-evidence unexpected-error dispatch (lines 311-315)
# --------------------------------------------------------------------------- #


def test_collect_evidence_unexpected_error_exit3(tmp_path: Path, monkeypatch) -> None:
    def _explode(*_a, **_k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(evidence, "_build_evidence_collector", _explode)
    res = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "github"])
    assert res.exit_code == 3
