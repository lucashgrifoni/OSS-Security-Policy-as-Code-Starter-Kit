"""Integration tests for ``evaluate`` reading ``oss-policy-kit.yaml``.

Verifies that:

- ``evaluate`` succeeds without ``--profile`` when a valid config is
  present under the target.
- An explicit ``--profile`` overrides the config (config does not silently
  win when the user is explicit).
- Missing both flag and config produces exit 2 with a clear message.
- Broken config files surface as exit 2 (never as a generic crash).
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli.main import app, prepare_cli_args


def _hardened_repo() -> Path:
    """Return the bundled hardened example repo (used by other tests too)."""

    return Path(__file__).resolve().parents[2] / "examples" / "hardened-repo"


def _write_config(target: Path, profile: str = "github-level-1") -> None:
    body = (
        "schema_version: oss-policy-kit/config/v1\n"
        f"profile: {profile}\n"
        "profile_source: recommended\n"
        "fail_on: none\n"
        'output_dir: "./oss-policy-reports"\n'
        'report_json_contract: "1.0"\n'
        "detected:\n"
        "  platform: github\n"
        "  primary_stack: null\n"
        "  signals: []\n"
    )
    (target / "oss-policy-kit.yaml").write_text(body, encoding="utf-8")


def test_evaluate_uses_profile_from_config_when_flag_omitted(tmp_path: Path) -> None:
    repo = tmp_path / "with-config"
    repo.mkdir()
    # Mirror the minimal layout the example hardened repo exposes so the
    # engine runs without operational warnings about missing files.
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        encoding="utf-8",
    )
    (repo / "README.md").write_text("# demo\n", encoding="utf-8")
    _write_config(repo, profile="github-level-1")

    runner = CliRunner()
    out_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--output-dir",
                str(out_dir),
                "--summary-only",
                "--format",
                "json",
            ]
        ),
    )
    # Exit may be 0 (no fails with --fail-on none) regardless of result content.
    assert result.exit_code == 0, result.output
    assert (out_dir / "evaluation-report.json").is_file()
    assert "Using profile from oss-policy-kit.yaml" in result.output


def test_evaluate_explicit_profile_overrides_config(tmp_path: Path) -> None:
    repo = tmp_path / "override"
    repo.mkdir()
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        encoding="utf-8",
    )
    _write_config(repo, profile="github-level-1")

    runner = CliRunner()
    out_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--profile",
                "github-level-2",
                "--output-dir",
                str(out_dir),
                "--summary-only",
                "--format",
                "json",
            ]
        ),
    )
    assert result.exit_code in {0, 1}, result.output  # may trip --fail-on if level-2
    # Explicit flag wins: the "using profile from config" stderr must NOT appear.
    assert "Using profile from oss-policy-kit.yaml" not in result.output


def test_evaluate_without_profile_or_config_exits_2(tmp_path: Path) -> None:
    repo = tmp_path / "no-config"
    repo.mkdir()
    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--output-dir",
                str(tmp_path / "out"),
            ]
        ),
    )
    assert result.exit_code == 2
    assert "--profile is required" in result.output


def test_evaluate_with_broken_config_exits_2(tmp_path: Path) -> None:
    repo = tmp_path / "broken"
    repo.mkdir()
    (repo / "oss-policy-kit.yaml").write_text(
        "schema_version: oss-policy-kit/config/v999\nprofile: github-level-1\nfail_on: fail\noutput_dir: out\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--output-dir",
                str(tmp_path / "out"),
            ]
        ),
    )
    assert result.exit_code == 2
    assert "unsupported schema_version" in result.output
