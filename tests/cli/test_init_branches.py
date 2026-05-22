"""Branch coverage for the ``init`` command (formats, flags, force re-run, validation errors)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()


def test_init_human(tmp_path: Path) -> None:
    res = runner.invoke(app, ["init", "--target", str(tmp_path), "--profile", "github-level-1"])
    assert res.exit_code == 0, res.output


def test_init_json(tmp_path: Path) -> None:
    res = runner.invoke(app, ["init", "--target", str(tmp_path), "--profile", "github-level-1", "--format", "json"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.stdout)
    assert isinstance(payload, dict)


def test_init_with_all_extras_and_force(tmp_path: Path) -> None:
    args = [
        "init",
        "--target",
        str(tmp_path),
        "--profile",
        "github-level-1",
        "--with-waivers",
        "--with-evidence",
        "--with-workflow",
    ]
    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.output
    # Second run without --force keeps existing files (exercises the "kept" path).
    second = runner.invoke(app, args)
    assert second.exit_code == 0, second.output
    # Third run with --force replaces them.
    third = runner.invoke(app, [*args, "--force"])
    assert third.exit_code == 0, third.output


def test_init_dry_run(tmp_path: Path) -> None:
    res = runner.invoke(app, ["init", "--target", str(tmp_path), "--profile", "github-level-1", "--dry-run"])
    assert res.exit_code == 0, res.output


def test_init_bad_format(tmp_path: Path) -> None:
    res = runner.invoke(app, ["init", "--target", str(tmp_path), "--profile", "github-level-1", "--format", "xml"])
    assert res.exit_code != 0


def test_init_bad_target() -> None:
    res = runner.invoke(app, ["init", "--target", "/nonexistent/path/xyz", "--profile", "github-level-1"])
    assert res.exit_code != 0
