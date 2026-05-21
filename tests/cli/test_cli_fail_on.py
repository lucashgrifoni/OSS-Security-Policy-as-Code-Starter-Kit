"""CLI exit-code behavior for automation."""

from __future__ import annotations

from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED, EXAMPLE_VULNERABLE, INVALID_WORKFLOW_FIXTURE
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app, prepare_cli_args


def test_fail_on_fail_exits_1_on_vulnerable(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "v"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(EXAMPLE_VULNERABLE),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(out),
                "--fail-on",
                "fail",
            ]
        ),
    )
    assert result.exit_code == 1
    assert (out / "evaluation-report.json").is_file()


def test_fail_on_fail_exits_0_on_hardened(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "h"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(EXAMPLE_HARDENED),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(out),
                "--fail-on",
                "fail",
            ]
        ),
    )
    assert result.exit_code == 0


def test_fail_on_degraded_exits_1_when_manual_review_present(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "d"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(INVALID_WORKFLOW_FIXTURE),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(out),
                "--fail-on",
                "degraded",
            ]
        ),
    )
    assert result.exit_code == 1


def test_format_json_writes_summary_to_stdout(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "j"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(EXAMPLE_HARDENED),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(out),
                "--format",
                "json",
            ]
        ),
    )
    assert result.exit_code == 0
    # CliRunner captures stdout; capsys does not see writes inside invoke isolation.
    assert '"summary_by_status"' in (result.stdout or "")
    assert '"profile_id"' in (result.stdout or "")
