"""Branch-coverage gaps for the cli.init command error handlers and target validation."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import init as init_mod
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()


# --------------------------------------------------------------------------- #
# _resolve_target rejects a non-directory path (line 68)
# --------------------------------------------------------------------------- #


def test_resolve_target_rejects_file(tmp_path: Path) -> None:
    f = tmp_path / "afile.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        init_mod._resolve_target(str(f))


def test_init_cmd_target_is_file_exit2(tmp_path: Path) -> None:
    f = tmp_path / "afile.txt"
    f.write_text("x", encoding="utf-8")
    res = runner.invoke(app, ["init", "--target", str(f), "--profile", "github-level-2"])
    assert res.exit_code == 2


# --------------------------------------------------------------------------- #
# init_cmd OSError handler (lines 347-349)
# --------------------------------------------------------------------------- #


def test_init_cmd_oserror_exit2(tmp_path: Path, monkeypatch) -> None:
    def _boom(**_k):
        raise OSError("disk gone")

    monkeypatch.setattr(init_mod, "build_init_plan", _boom)
    res = runner.invoke(app, ["init", "--target", str(tmp_path), "--profile", "github-level-2"])
    assert res.exit_code == 2


# --------------------------------------------------------------------------- #
# init_cmd unexpected-error handler (lines 352-354)
# --------------------------------------------------------------------------- #


def test_init_cmd_unexpected_error_exit3(tmp_path: Path, monkeypatch) -> None:
    def _boom(**_k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(init_mod, "build_init_plan", _boom)
    res = runner.invoke(app, ["init", "--target", str(tmp_path), "--profile", "github-level-2"])
    assert res.exit_code == 3
