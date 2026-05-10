"""CLI smoke tests."""

from pathlib import Path

import pytest
from tests.conftest import EXAMPLE_HARDENED, EXAMPLE_VULNERABLE, ROOT
from typer.testing import CliRunner

from oss_policy_kit import __version__
from oss_policy_kit.cli.main import app, prepare_cli_args


def _result_stdout(result: object) -> str:
    """Return stdout when available, otherwise fall back to Click's combined output."""

    stdout = getattr(result, "stdout", None)
    if isinstance(stdout, str) and stdout:
        return stdout
    output = getattr(result, "output", "")
    return output if isinstance(output, str) else ""


def test_cli_version_flag_exits_zero() -> None:
    runner = CliRunner()
    for flag in ("--version", "-V"):
        result = runner.invoke(app, [flag])
        assert result.exit_code == 0, result.output
        assert __version__ in (result.stdout or "").strip()


def test_prepare_cli_args_inserts_evaluate_for_path_first_invocation() -> None:
    assert prepare_cli_args(["./repo", "--profile", "p"]) == ["evaluate", "./repo", "--profile", "p"]
    assert prepare_cli_args(["evaluate", "./repo"]) == ["evaluate", "./repo"]
    assert prepare_cli_args(["--target", "./repo", "--profile", "p"]) == ["--target", "./repo", "--profile", "p"]
    assert prepare_cli_args(["profiles"]) == ["profiles"]


def test_cli_profiles_command_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["profiles"])
    out = _result_stdout(result)
    assert result.exit_code == 0, result.output
    assert "Profile" in out
    assert "Title" in out
    assert "Platform" in out
    assert "Level" in out
    assert "Audience" in out
    assert "Description" in out
    assert "github-level-1" in out
    assert "github-release-hardening-1" in out
    assert "Bundled profiles" in out
    assert "GitHub" in out and "baseline" in out and "level" in out
    assert "maintainers" in out.lower() and "starting" in out.lower()
    assert "baseline" in out.lower()
    assert "Maintainers adopting a" not in out
    assert "minimal, honest OSS security" not in out
    assert "Starter" in out and "GitHub" in out and "clone-visible" in out.replace("\n", "")
    assert "repositories: governance files, safe workflow" not in out
    assert "Details" not in out
    # Note: "Track" is now legitimate vocabulary in profile titles
    # ("SLSA v1.1 Build Track Level 2", "EU CRA strict track" etc.)
    # introduced in v5.4.0. The old guard was against an obsolete column label.
    assert "Summary" not in out


def test_cli_show_profiles_flag_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--show-profiles"])
    out = _result_stdout(result)
    assert result.exit_code == 0, result.output
    assert "github-level-1" in out
    assert "github-release-hardening-1" in out
    assert "azure-level-1" in out
    assert "aws-level-1" in out
    assert "Bundled profiles" in out
    assert "Profile" in out
    assert "Title" in out
    assert "Platform" in out
    assert "Level" in out
    assert "Recommended" in out and "gate" in out
    assert "Audience" in out
    assert "Description" in out
    # Normalize Rich table wrapping and box-drawing borders before substring checks:
    # the new "Recommended gate" column narrows Audience and can wrap mid-word under
    # narrow terminals, with box chars sitting between broken halves.
    normalized_out = " ".join("".join(ch if ch.isascii() or ch.isspace() else " " for ch in out).split())
    assert "GitHub maintainers starting" not in normalized_out
    # "Maintainers adopting ..." is the compact audience; it may wrap mid-word under
    # narrow layouts, so check distinctive prefix/words that survive column wrapping.
    assert "Maintainer" in normalized_out and "adopting" in normalized_out
    assert "--fail-on fail" in normalized_out
    assert "minimal" in out and "honest" in out and "OSS" in out and "security" in out
    assert "baseline" in out.lower()
    assert "Starter GitHub baseline for clone-visible checks." not in normalized_out
    assert "governance" in out and "workflow" in out
    assert "Details" not in out
    # Note: "Track" is now legitimate vocabulary in profile titles
    # ("SLSA v1.1 Build Track Level 2", "EU CRA strict track" etc.)
    # introduced in v5.4.0. The old guard was against an obsolete column label.
    assert "Summary" not in out


def test_cli_evaluate_hardened(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "o"
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
            ]
        ),
    )
    assert result.exit_code == 0, result.output
    assert (out / "evaluation-report.json").is_file()


def test_cli_invalid_target() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(ROOT / "does-not-exist-xyz"),
                "--profile",
                "github-level-1",
                "--output-dir",
                "out-x",
            ]
        ),
    )
    assert result.exit_code == 2


def test_cli_evaluate_vulnerable(tmp_path: Path) -> None:
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
            ]
        ),
    )
    assert result.exit_code == 0
    assert (out / "evaluation-report.md").is_file()


def test_cli_root_top_level_invocation(tmp_path: Path) -> None:
    """Backward-compatible form: same flags as `evaluate`, without the subcommand name."""

    runner = CliRunner()
    out = tmp_path / "root"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "--target",
                str(EXAMPLE_HARDENED),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(out),
            ]
        ),
    )
    assert result.exit_code == 0, result.output
    assert (out / "evaluation-report.json").is_file()


def test_cli_root_top_level_profile_short_flag(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "root-short-profile"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "--target",
                str(EXAMPLE_HARDENED),
                "-p",
                "github-level-1",
                "--output-dir",
                str(out),
            ]
        ),
    )
    assert result.exit_code == 0, result.output
    assert (out / "evaluation-report.json").is_file()


def test_cli_root_positional_repo_path(tmp_path: Path) -> None:
    """Path-first invocation is normalized to `evaluate` (matches `python -m` entrypoint)."""

    runner = CliRunner()
    out = tmp_path / "pos"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                str(EXAMPLE_HARDENED),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(out),
            ]
        ),
    )
    assert result.exit_code == 0, result.output
    assert (out / "evaluation-report.json").is_file()


def test_cli_evaluate_profile_short_flag(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "eval-short-profile"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(EXAMPLE_HARDENED),
                "-p",
                "github-level-1",
                "--output-dir",
                str(out),
            ]
        ),
    )
    assert result.exit_code == 0, result.output
    assert (out / "evaluation-report.json").is_file()


def test_cli_root_requires_profile(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "--target",
                str(EXAMPLE_HARDENED),
                "--output-dir",
                str(tmp_path / "o"),
            ]
        ),
    )
    assert result.exit_code == 2


def test_cli_recommend_profile_human_no_unicode_arrow() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["recommend-profile", "--target", str(EXAMPLE_HARDENED), "--format", "human"])
    assert result.exit_code == 0, result.output
    out = _result_stdout(result)
    assert "\u2192" not in out
    assert "->" in out


def test_cli_scaffold_evidence_respects_force(tmp_path: Path) -> None:
    runner = CliRunner()
    repo = tmp_path / "s"
    repo.mkdir()
    r1 = runner.invoke(app, ["scaffold-evidence", "--target", str(repo), "--platform", "github"])
    assert r1.exit_code == 0, r1.output
    bp = repo / ".oss-policy-kit" / "evidence" / "branch-protection.json"
    bp.write_text(bp.read_text(encoding="utf-8").replace("REPLACE_ME", "HOLD"), encoding="utf-8")
    r2 = runner.invoke(app, ["scaffold-evidence", "--target", str(repo), "--platform", "github"])
    assert r2.exit_code == 0
    assert "HOLD" in bp.read_text(encoding="utf-8")
    r3 = runner.invoke(app, ["scaffold-evidence", "--target", str(repo), "--platform", "github", "--force"])
    assert r3.exit_code == 0
    assert "HOLD" not in bp.read_text(encoding="utf-8")


def test_cli_scaffold_evidence_creates_missing_target_dir(tmp_path: Path) -> None:
    """``scaffold-evidence`` auto-creates a missing ``--target`` (with parents)."""

    runner = CliRunner()
    nested = tmp_path / "deep" / "nested" / "repo"
    assert not nested.exists()
    result = runner.invoke(app, ["scaffold-evidence", "--target", str(nested), "--platform", "github"])
    assert result.exit_code == 0, result.output
    assert nested.is_dir()
    assert (nested / ".oss-policy-kit" / "evidence" / "branch-protection.json").is_file()
    assert (nested / ".oss-policy-kit" / "evidence" / "README.md").is_file()


def test_cli_scaffold_evidence_existing_target_no_extra_create(tmp_path: Path) -> None:
    """``scaffold-evidence`` does not require auto-create when ``--target`` exists."""

    runner = CliRunner()
    repo = tmp_path / "exists"
    repo.mkdir()
    result = runner.invoke(app, ["scaffold-evidence", "--target", str(repo), "--platform", "azure"])
    assert result.exit_code == 0, result.output
    assert (repo / ".oss-policy-kit" / "evidence" / "azure-branch-policies.json").is_file()


def test_cli_collect_evidence_aws_dry_run_lists_three_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``collect-evidence --platform aws --dry-run`` must preview the three AWS files without credentials.

    The preview must also report which credential-related environment variables are set (by name only)
    so operators can confirm their shell is ready before committing to a live collection.
    """

    runner = CliRunner()
    repo = tmp_path / "aws-target"
    repo.mkdir()
    for name in (
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_PROFILE",
        "AWS_CODEBUILD_PROJECT",
        "AWS_CODEPIPELINE_NAME",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_REGION", "us-east-2")

    result = runner.invoke(
        app,
        ["collect-evidence", "--target", str(repo), "--platform", "aws", "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    out = _result_stdout(result)
    # Strip whitespace/newlines so Rich-wrapped long Windows tmp paths do not break substring checks.
    flat = "".join(out.split())
    assert "collect-evidence" in out and "dry-run" in out
    assert "platform:aws" in flat
    assert "aws-codebuild-project.json" in flat
    assert "aws-codepipeline.json" in flat
    # Env probes are reported for the AWS-relevant variables with presence markers only.
    assert "AWS_REGION:set" in flat
    assert "AWS_ACCESS_KEY_ID:notset" in flat
    assert "AWS_CODEBUILD_PROJECT:notset" in flat
    assert "us-east-2" not in out, "Probe must never echo variable values"


def test_cli_collect_evidence_azure_dry_run_lists_two_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    repo = tmp_path / "az-target"
    repo.mkdir()
    monkeypatch.delenv("AZURE_DEVOPS_ORG", raising=False)
    monkeypatch.delenv("AZURE_DEVOPS_TOKEN", raising=False)

    result = runner.invoke(
        app,
        [
            "collect-evidence",
            "--target",
            str(repo),
            "--platform",
            "azure",
            "--repo",
            "Proj/myrepo",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    out = _result_stdout(result)
    flat = "".join(out.split())
    assert "platform:azure" in flat
    assert "azure-branch-policies.json" in flat
    assert "azure-pipeline-governance.json" in flat
    assert "AZURE_DEVOPS_ORG:notset" in flat
    assert "AZURE_DEVOPS_TOKEN:notset" in flat
    # Repo slug is shown as passed even without credentials.
    assert "Proj/myrepo" in flat


def test_cli_evaluate_many_profiles_short_flag(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "batch-short-profile"
    result = runner.invoke(
        app,
        [
            "evaluate-many",
            "--target-root",
            str(ROOT / "tests" / "fixtures" / "repositories"),
            "-p",
            "github-level-1",
            "--output-dir",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (out / "evaluation-batch.json").is_file()


def test_cli_evaluate_format_table_alias(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "fmt-table"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(EXAMPLE_HARDENED),
                "--profile",
                "github-level-1",
                "--format",
                "table",
                "--output-dir",
                str(out),
            ]
        ),
    )
    assert result.exit_code == 0, result.output


def test_cli_profiles_format_human_alias() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["profiles", "--format", "human"])
    assert result.exit_code == 0, result.output


def test_cli_profiles_recommended_gate_column_renders_without_polluting_json() -> None:
    """Recommended gate column shows up in human listings; JSON contract stays the same."""

    import json as _json

    runner = CliRunner()

    human = runner.invoke(app, ["profiles", "--format", "compact"])
    assert human.exit_code == 0, human.output
    human_out = _result_stdout(human)
    assert "Recommended" in human_out and "gate" in human_out
    assert "--fail-on fail" in human_out
    assert "--fail-on none" in human_out
    # v5.0.0: the legacy 'github-release-hardening' alias was removed; no '(migrate)' row.
    assert "(migrate)" not in human_out

    payload = runner.invoke(app, ["profiles", "--format", "json"])
    assert payload.exit_code == 0, payload.output
    data = _json.loads(_result_stdout(payload))
    assert data["schema_version"] == "oss-policy-kit/profile-list/v2"
    keys_seen: set[str] = set()
    for profile in data["profiles"]:
        keys_seen.update(profile.keys())
    assert "recommended_gate" not in keys_seen, "profile-list JSON must not gain new fields"


def test_cli_recommend_profile_format_table_alias() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["recommend-profile", "--target", str(EXAMPLE_HARDENED), "--format", "table"])
    assert result.exit_code == 0, result.output


def test_cli_evaluate_verbose_writes_to_stderr(tmp_path: Path) -> None:
    # Click 8.x merges stdout/stderr in result.output; check combined output.
    runner = CliRunner()
    out = tmp_path / "verb"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(EXAMPLE_HARDENED),
                "--profile",
                "github-level-1",
                "--verbose",
                "--output-dir",
                str(out),
            ]
        ),
    )
    assert result.exit_code == 0, result.output
    assert "GOV-SEC-001" in result.output or "\u2192" in result.output or "→" in result.output


def test_cli_evaluate_json_summary_only_is_stdout_only(tmp_path: Path) -> None:
    # ``--summary-only --format json``: combined output is JSON (no stderr chatter for machine mode).
    runner = CliRunner()
    out = tmp_path / "json-out"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(EXAMPLE_HARDENED),
                "--profile",
                "github-level-1",
                "--format",
                "json",
                "--summary-only",
                "--output-dir",
                str(out),
            ]
        ),
    )
    assert result.exit_code == 0, result.output
    assert "kit_version" in result.output
    assert "Reports written to:" not in result.output
    assert "Operational warnings" not in result.output
