"""Branch coverage for the ``scan-k8s`` command (human diagnostics, helm-render, json, error)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli import scan_k8s as sk
from oss_policy_kit.cli.main import app

runner = CliRunner()

_DEPLOY = (
    "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\nspec:\n  template:\n    spec:\n"
    "      containers:\n        - name: c\n          image: nginx:1.25\n"
)


def test_scan_k8s_human(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(_DEPLOY, encoding="utf-8")
    res = runner.invoke(app, ["scan-k8s", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "scan-k8s:" in res.output


def test_scan_k8s_json(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(_DEPLOY, encoding="utf-8")
    res = runner.invoke(app, ["scan-k8s", "--target", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["status"] == "ok"


def test_scan_k8s_helm_render_no_helm(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(_DEPLOY, encoding="utf-8")
    res = runner.invoke(app, ["scan-k8s", "--target", str(tmp_path), "--format", "human", "--helm-render"])
    assert res.exit_code == 0, res.output
    # helm not installed in CI -> warning about missing helm CLI.
    assert "scan-k8s:" in res.output


def test_scan_k8s_templated_manifest_skipped(tmp_path: Path) -> None:
    # A manifest containing Helm {{ ... }} markers is skipped without --helm-render.
    (tmp_path / "tmpl.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\nspec:\n  template:\n    spec:\n"
        "      containers:\n        - name: c\n          image: {{ .Values.image }}\n",
        encoding="utf-8",
    )
    res = runner.invoke(app, ["scan-k8s", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output


def test_scan_k8s_bad_format(tmp_path: Path) -> None:
    res = runner.invoke(app, ["scan-k8s", "--target", str(tmp_path), "--format", "xml"])
    assert res.exit_code != 0


def test_scan_k8s_error_status(tmp_path: Path, monkeypatch) -> None:
    from oss_policy_kit.infrastructure.k8s.scanner import K8sScanOutcome

    def _err(*_a, **_k) -> K8sScanOutcome:
        return K8sScanOutcome(status="error", tool_version="1.0", diagnostics="boom")

    monkeypatch.setattr(sk, "run_scan", _err)
    res = runner.invoke(app, ["scan-k8s", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 2
