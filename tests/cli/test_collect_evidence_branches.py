"""Branch coverage for ``collect-evidence`` (dry-run preview, collector builders, write path)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import evidence as ev
from oss_policy_kit.cli.main import app

runner = CliRunner()

_CRED_VARS = (
    "GITHUB_TOKEN",
    "AZURE_DEVOPS_ORG",
    "AZURE_DEVOPS_TOKEN",
    "AWS_CODEBUILD_PROJECT",
    "AWS_CODEPIPELINE_NAME",
)


@pytest.fixture(autouse=True)
def _clear_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in _CRED_VARS:
        monkeypatch.delenv(v, raising=False)


# --------------------------------------------------------------------------- #
# dry-run preview (no credentials needed)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("platform", ["github", "azure", "aws"])
def test_collect_dry_run(tmp_path: Path, platform: str) -> None:
    res = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", platform, "--dry-run"])
    assert res.exit_code == 0, res.output
    assert "collect-evidence dry-run" in res.output
    assert platform in res.output


def test_collect_dry_run_with_env_probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secretvalue")
    res = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "github", "--dry-run"])
    assert res.exit_code == 0
    assert "set" in res.output
    assert "ghp_secretvalue" not in res.output  # value never echoed


def test_env_probe_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("X_PROBE", "v")
    assert ev._env_probe_status("X_PROBE") == "set"
    monkeypatch.setenv("X_PROBE", "  ")
    assert ev._env_probe_status("X_PROBE") == "not set"
    monkeypatch.delenv("X_PROBE", raising=False)
    assert ev._env_probe_status("X_PROBE") == "not set"


# --------------------------------------------------------------------------- #
# collector credential errors (real run, missing creds -> exit 2)
# --------------------------------------------------------------------------- #


def test_collect_github_missing_token(tmp_path: Path) -> None:
    res = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "github", "--repo", "o/r"])
    assert res.exit_code == 2
    assert "GITHUB_TOKEN" in res.output


def test_collect_azure_missing_creds(tmp_path: Path) -> None:
    res = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "azure", "--repo", "P/r"])
    assert res.exit_code == 2


def test_collect_aws_missing_creds(tmp_path: Path) -> None:
    res = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "aws"])
    assert res.exit_code == 2


def test_collect_unsupported_platform(tmp_path: Path) -> None:
    res = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "gitlab"])
    assert res.exit_code == 2


def test_github_collector_missing_slug(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    # No --repo and no git remote -> slug cannot be resolved.
    res = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "github"])
    assert res.exit_code == 2


# --------------------------------------------------------------------------- #
# success path (collector mocked)
# --------------------------------------------------------------------------- #


def test_collect_success_writes_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        SimpleNamespace(evidence_key="branch-protection", data={"x": 1}, source_url="https://api/x"),
        SimpleNamespace(evidence_key="org-mfa-posture", data={"y": 2}, source_url="https://api/y"),
    ]

    class _FakeCollector:
        def collect(self, _slug: str) -> list:
            return rows

    monkeypatch.setattr(ev, "_build_evidence_collector", lambda *a, **k: (_FakeCollector(), "o/r"))
    res = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "github", "--repo", "o/r"])
    assert res.exit_code == 0, res.output
    ev_dir = tmp_path / ".oss-policy-kit" / "evidence"
    assert (ev_dir / "branch-protection.json").is_file()
    assert (ev_dir / "org-mfa-posture.json").is_file()


def test_collect_collector_value_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _BadCollector:
        def collect(self, _slug: str) -> list:
            raise ValueError("bad slug format")

    monkeypatch.setattr(ev, "_build_evidence_collector", lambda *a, **k: (_BadCollector(), "o/r"))
    res = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "github", "--repo", "o/r"])
    assert res.exit_code == 2
