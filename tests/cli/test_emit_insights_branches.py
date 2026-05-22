"""Branch coverage for the ``emit-insights`` command + document builder."""

from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from oss_policy_kit.cli import emit_insights as ei
from oss_policy_kit.cli.main import app

runner = CliRunner()


def _w(tmp_path: Path, rel: str, text: str = "x\n") -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _rich_repo(tmp_path: Path) -> None:
    _w(tmp_path, "SECURITY.md", "Report to security@example.com\n")
    _w(tmp_path, "LICENSE", "MIT License\n")
    _w(tmp_path, "README.md", "# Project\n")
    _w(tmp_path, ".github/dependabot.yml", "version: 2\n")
    _w(tmp_path, ".github/workflows/ci.yml", "on: push\n")


def test_emit_insights_writes_yaml(tmp_path: Path) -> None:
    _rich_repo(tmp_path)
    out = tmp_path / "insights.yml"
    res = runner.invoke(app, ["emit-insights", "--target", str(tmp_path), "--output", str(out)])
    assert res.exit_code == 0, res.output
    assert out.is_file()
    doc = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert isinstance(doc, dict) and doc


def test_emit_insights_validate(tmp_path: Path) -> None:
    _rich_repo(tmp_path)
    out = tmp_path / "insights.yml"
    res = runner.invoke(app, ["emit-insights", "--target", str(tmp_path), "--output", str(out), "--validate"])
    assert res.exit_code == 0, res.output


def test_emit_insights_minimal_repo(tmp_path: Path) -> None:
    out = tmp_path / "insights.yml"
    res = runner.invoke(app, ["emit-insights", "--target", str(tmp_path), "--output", str(out)])
    assert res.exit_code == 0, res.output


def test_emit_insights_bad_target(tmp_path: Path) -> None:
    res = runner.invoke(app, ["emit-insights", "--target", str(tmp_path / "nope"), "--output", str(tmp_path / "o.yml")])
    assert res.exit_code != 0


def test_build_insights_document_directly(tmp_path: Path) -> None:
    _rich_repo(tmp_path)
    doc = ei._build_insights_document(tmp_path.resolve())
    assert isinstance(doc, dict)
    errs = ei._validate_insights_structure(doc)
    assert isinstance(errs, list)
