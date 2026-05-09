"""Tests for the ``oss-policy-kit init`` subcommand.

Coverage targets:

- Dry-run never writes anything but reports the planned actions.
- Non-interactive default produces a valid ``oss-policy-kit.yaml``.
- ``--with-waivers`` / ``--with-evidence`` / ``--with-workflow`` create
  the matching artifacts in a single run.
- Idempotency: re-running without ``--force`` preserves existing files;
  re-running with ``--force`` replaces them.
- ``--platform`` selects the matching default profile when no signals
  are present.
- ``--profile`` always wins over recommendations.
- ``--format json`` emits the documented stable shape.
- Invalid ``--target`` / ``--fail-on`` / ``--platform`` map to exit 2.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from oss_policy_kit.application.init_planner import (
    CONFIG_FILENAME,
    CONFIG_SCHEMA_VERSION,
    INIT_RESULT_SCHEMA_VERSION,
    WAIVERS_FILENAME,
)
from oss_policy_kit.cli.main import app, prepare_cli_args


def _make_github_repo(tmp_path: Path) -> Path:
    """Create a minimal GitHub-flavored repo for signal-driven recommendations."""

    repo = tmp_path / "github-repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.0.1"\n',
        encoding="utf-8",
    )
    return repo


def _make_empty_repo(tmp_path: Path, name: str = "empty-repo") -> Path:
    """Create an empty directory so init can run with no signals."""

    repo = tmp_path / name
    repo.mkdir()
    return repo


def test_init_dry_run_writes_nothing(tmp_path: Path) -> None:
    repo = _make_github_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "init",
                "--target",
                str(repo),
                "--dry-run",
                "--with-waivers",
                "--with-evidence",
                "--with-workflow",
            ]
        ),
    )

    assert result.exit_code == 0, result.output
    # Dry-run path: no real artifact on disk.
    assert not (repo / CONFIG_FILENAME).exists()
    assert not (repo / WAIVERS_FILENAME).exists()
    assert not (repo / ".oss-policy-kit" / "evidence").exists()
    assert "dry-run" in result.output.lower() or "Plan" in result.output


def test_init_default_writes_config_yaml(tmp_path: Path) -> None:
    repo = _make_github_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(["init", "--target", str(repo)]),
    )

    assert result.exit_code == 0, result.output
    cfg = repo / CONFIG_FILENAME
    assert cfg.is_file(), "init must write oss-policy-kit.yaml"
    parsed = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    assert parsed["schema_version"] == CONFIG_SCHEMA_VERSION
    assert parsed["profile"].startswith("github-")
    assert parsed["fail_on"] == "fail"
    assert parsed["detected"]["platform"] == "github"
    # No optional artifacts should be created without explicit flags.
    assert not (repo / WAIVERS_FILENAME).exists()


def test_init_with_all_options_creates_every_artifact(tmp_path: Path) -> None:
    repo = _make_github_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "init",
                "--target",
                str(repo),
                "--with-waivers",
                "--with-evidence",
                "--with-workflow",
            ]
        ),
    )

    assert result.exit_code == 0, result.output
    assert (repo / CONFIG_FILENAME).is_file()
    assert (repo / WAIVERS_FILENAME).is_file()
    evidence_dir = repo / ".oss-policy-kit" / "evidence"
    assert evidence_dir.is_dir()
    # Scaffolding always produces at least one JSON template per platform.
    assert any(evidence_dir.glob("*.json"))
    workflow_path = repo / ".github" / "workflows" / "oss-policy-check.yml"
    assert workflow_path.is_file()


def test_init_is_idempotent_without_force(tmp_path: Path) -> None:
    repo = _make_github_repo(tmp_path)
    runner = CliRunner()

    first = runner.invoke(app, prepare_cli_args(["init", "--target", str(repo)]))
    assert first.exit_code == 0, first.output
    cfg = repo / CONFIG_FILENAME
    original_body = cfg.read_text(encoding="utf-8")

    # Tweak the file; the second run must not clobber the user's edit.
    cfg.write_text(original_body + "\n# user edit\n", encoding="utf-8")

    second = runner.invoke(app, prepare_cli_args(["init", "--target", str(repo)]))
    assert second.exit_code == 0, second.output
    assert "# user edit" in cfg.read_text(encoding="utf-8")
    assert "kept" in second.output or "skipped" in second.output.lower()


def test_init_force_overwrites_existing(tmp_path: Path) -> None:
    repo = _make_github_repo(tmp_path)
    runner = CliRunner()

    runner.invoke(app, prepare_cli_args(["init", "--target", str(repo)]))
    cfg = repo / CONFIG_FILENAME
    cfg.write_text("schema_version: tampered\n", encoding="utf-8")

    result = runner.invoke(
        app,
        prepare_cli_args(["init", "--target", str(repo), "--force"]),
    )
    assert result.exit_code == 0, result.output
    parsed = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    assert parsed["schema_version"] == CONFIG_SCHEMA_VERSION


def test_init_platform_flag_picks_platform_default(tmp_path: Path) -> None:
    # Empty repo has no signals; --platform azure must still produce an
    # azure-* profile so the user gets a working baseline.
    repo = _make_empty_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(
            ["init", "--target", str(repo), "--platform", "azure"]
        ),
    )

    assert result.exit_code == 0, result.output
    parsed = yaml.safe_load((repo / CONFIG_FILENAME).read_text(encoding="utf-8"))
    assert parsed["profile"] == "azure-level-1"
    assert parsed["profile_source"] == "platform_default"
    assert parsed["detected"]["platform"] == "azure"


def test_init_profile_flag_overrides_recommendation(tmp_path: Path) -> None:
    repo = _make_github_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "init",
                "--target",
                str(repo),
                "--profile",
                "github-level-3",
            ]
        ),
    )

    assert result.exit_code == 0, result.output
    parsed = yaml.safe_load((repo / CONFIG_FILENAME).read_text(encoding="utf-8"))
    assert parsed["profile"] == "github-level-3"
    assert parsed["profile_source"] == "user"


def test_init_json_format_payload_is_stable(tmp_path: Path) -> None:
    repo = _make_github_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(
            ["init", "--target", str(repo), "--format", "json"]
        ),
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == INIT_RESULT_SCHEMA_VERSION
    assert payload["profile_chosen"].startswith("github-")
    assert payload["detected"]["platform"] == "github"
    assert "actions" in payload
    assert "next_steps" in payload


def test_init_missing_target_returns_exit_code_2(tmp_path: Path) -> None:
    runner = CliRunner()
    bogus = tmp_path / "does-not-exist"

    result = runner.invoke(
        app,
        prepare_cli_args(["init", "--target", str(bogus)]),
    )

    assert result.exit_code == 2
    # Stderr is bundled into output by Typer's CliRunner.
    assert "does not exist" in result.output


def test_init_invalid_fail_on_returns_exit_code_2(tmp_path: Path) -> None:
    repo = _make_github_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "init",
                "--target",
                str(repo),
                "--fail-on",
                "ridiculous",
            ]
        ),
    )

    assert result.exit_code == 2
    assert "fail-on" in result.output


def test_init_invalid_platform_returns_exit_code_2(tmp_path: Path) -> None:
    repo = _make_github_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "init",
                "--target",
                str(repo),
                "--platform",
                "alibaba",
            ]
        ),
    )

    assert result.exit_code == 2
    assert "platform" in result.output.lower()


def test_init_workflow_skipped_for_non_github_platform(tmp_path: Path) -> None:
    # Even though --with-workflow is set, an Azure target should not get a
    # GitHub workflow file. Init must surface the reason in notes.
    repo = _make_empty_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "init",
                "--target",
                str(repo),
                "--platform",
                "azure",
                "--with-workflow",
            ]
        ),
    )

    assert result.exit_code == 0, result.output
    assert not (repo / ".github" / "workflows" / "oss-policy-check.yml").exists()
    assert "Workflow templates are only generated for GitHub" in result.output
