"""CLI subprocess tests: exercise real `python -m oss_policy_kit` behavior (not only CliRunner)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from tests.conftest import EXAMPLE_HARDENED, INVALID_WORKFLOW_FIXTURE, REPO_WITH_SPACES_FIXTURE, ROOT, TEST_FIXTURES

_INVALID_WORKFLOW = INVALID_WORKFLOW_FIXTURE
_REPO_WITH_SPACES = REPO_WITH_SPACES_FIXTURE
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _subprocess_env() -> dict[str, str]:
    """Return a deterministic environment for CLI subprocess tests."""

    env = os.environ.copy()
    for key in (
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONBREAKPOINT",
        "PYTHONINSPECT",
        "PYTHONEXECUTABLE",
    ):
        env.pop(key, None)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["COLUMNS"] = "120"
    env["LINES"] = "40"
    env["PYTHONFAULTHANDLER"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    # Do not set PYTHONNOUSERSITE=1: the subprocess uses sys.executable and must see the same
    # third-party paths as the pytest process (often typer/click in user site-packages on Windows).
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONUTF8"] = "1"
    return env


def _run_module(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "oss_policy_kit", *argv]
    return subprocess.run(
        cmd,
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_subprocess_env(),
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )


def _clean_output(proc: subprocess.CompletedProcess[str]) -> str:
    """Normalize subprocess help output across Rich/ANSI rendering differences."""

    combined = proc.stdout + proc.stderr
    combined = _ANSI_RE.sub("", combined)
    return combined


def test_subprocess_version_prints_package_version() -> None:
    for flag in ("--version", "-V"):
        proc = _run_module([flag])
        assert proc.returncode == 0, proc.stderr + proc.stdout
        out = (proc.stdout or "").strip()
        assert len(out) > 0


def test_subprocess_root_help_lists_evaluate() -> None:
    proc = _run_module(["--help"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    out = _clean_output(proc)
    assert "evaluate" in out.lower()
    assert "profiles" in out.lower()
    assert "--show-profiles" in out
    assert "-sp" in out
    assert "-sj" in out
    assert "-fo" in out


def test_subprocess_show_profiles_short_flag_sp() -> None:
    proc = _run_module(["-sp"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "Bundled profiles" in proc.stdout
    assert "github-level-1" in proc.stdout


def test_subprocess_evaluate_help_distinct_from_root() -> None:
    root_help = _run_module(["--help"])
    eval_help = _run_module(["evaluate", "--help"])
    assert root_help.returncode == 0
    assert eval_help.returncode == 0
    assert "Evaluate a local repository clone" in eval_help.stdout
    assert "evaluate" in root_help.stdout.lower()
    assert "FAIL-ON MODES" in eval_help.stdout or "fail-on" in eval_help.stdout.lower()


def test_subprocess_profiles_command() -> None:
    proc = _run_module(["profiles"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "Profile" in proc.stdout
    assert "Title" in proc.stdout
    assert "Platform" in proc.stdout
    assert "Level" in proc.stdout
    assert "Audience" in proc.stdout
    assert "Description" in proc.stdout
    assert "github-level-1" in proc.stdout
    assert "github-release-hardening-1" in proc.stdout
    assert "Bundled profiles" in proc.stdout
    assert "GitHub" in proc.stdout and "baseline" in proc.stdout and "level" in proc.stdout
    assert "maintainers" in proc.stdout.lower() and "starting" in proc.stdout.lower()
    assert "baseline" in proc.stdout.lower()
    assert "Maintainers adopting a" not in proc.stdout
    assert "minimal, honest OSS security" not in proc.stdout
    assert "Starter" in proc.stdout and "clone-visible" in proc.stdout.replace("\n", "")
    assert "repositories: governance files, safe workflow" not in proc.stdout
    assert "Details" not in proc.stdout
    # Note: "Track" is now legitimate vocabulary in profile titles
    # ("SLSA v1.1 Build Track Level 2", "EU CRA strict track" etc.)
    # introduced in v5.4.0. The old guard was against an obsolete column label.
    assert "Summary" not in proc.stdout


def test_subprocess_profiles_json_on_stdout() -> None:
    proc = _run_module(["profiles", "--format", "json"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(proc.stdout)
    assert data["schema_version"] == "oss-policy-kit/profile-list/v2"
    ids = {row["profile_id"] for row in data["profiles"]}
    assert "github-level-1" in ids
    assert "azure-level-1" in ids


def test_subprocess_profiles_family_github_filters_json() -> None:
    proc = _run_module(["profiles", "--format", "json", "--family", "github"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(proc.stdout)
    for row in data["profiles"]:
        assert row["family"] == "github"
        assert row["posture"]
        assert row["live_signal_posture"]


def test_subprocess_profiles_only_extreme_subset() -> None:
    proc = _run_module(["profiles", "--format", "json", "--only-extreme"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(proc.stdout)
    assert data["profiles"]
    for row in data["profiles"]:
        pid = row["profile_id"]
        assert "-level-3" in pid or "-release-hardening-3" in pid


def test_subprocess_profiles_advisory_only_subset() -> None:
    proc = _run_module(["profiles", "--format", "json", "--advisory-only"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(proc.stdout)
    assert data["profiles"]
    for row in data["profiles"]:
        pid = row["profile_id"]
        mature = row["maturity_label"].lower()
        assert "-level-2" in pid or "advisory" in mature


def test_subprocess_show_profiles_flag() -> None:
    proc = _run_module(["--show-profiles"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "github-level-1" in proc.stdout
    assert "github-release-hardening-1" in proc.stdout
    assert "azure-level-1" in proc.stdout
    assert "aws-level-1" in proc.stdout
    assert "Bundled profiles" in proc.stdout
    assert "Profile" in proc.stdout
    assert "Title" in proc.stdout
    assert "Platform" in proc.stdout
    assert "Level" in proc.stdout
    assert "Recommended" in proc.stdout and "gate" in proc.stdout
    assert "Audience" in proc.stdout
    assert "Description" in proc.stdout
    # Normalize Rich table wrapping and box-drawing borders before substring checks:
    # the new "Recommended gate" column narrows Audience under COLUMNS=120 subprocess
    # rendering and can wrap mid-word, with box chars sitting between broken halves.
    normalized_stdout = " ".join("".join(ch if ch.isascii() or ch.isspace() else " " for ch in proc.stdout).split())
    assert "GitHub maintainers starting" not in normalized_stdout
    # "Maintainers adopting ..." is the compact audience; it may wrap mid-word under
    # narrow layouts, so check distinctive prefix/words that survive column wrapping.
    assert "Maintainer" in normalized_stdout and "adopting" in normalized_stdout
    assert "--fail-on fail" in normalized_stdout
    assert "minimal" in proc.stdout and "honest" in proc.stdout and "OSS" in proc.stdout and "security" in proc.stdout
    assert "baseline" in proc.stdout.lower()
    assert "Starter GitHub baseline for clone-visible checks." not in normalized_stdout
    assert "governance" in proc.stdout and "workflow" in proc.stdout
    assert "Details" not in proc.stdout
    # Note: "Track" is now legitimate vocabulary in profile titles
    # ("SLSA v1.1 Build Track Level 2", "EU CRA strict track" etc.)
    # introduced in v5.4.0. The old guard was against an obsolete column label.
    assert "Summary" not in proc.stdout


def test_subprocess_evaluate_with_target_flag(tmp_path: Path) -> None:
    out_dir = tmp_path / "pytest-subprocess-target"
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            "evaluate",
            "--target",
            str(EXAMPLE_HARDENED),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert (out_dir / "evaluation-report.json").is_file()


def test_subprocess_evaluate_with_profile_short_flag(tmp_path: Path) -> None:
    out_dir = tmp_path / "pytest-subprocess-target-short-profile"
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            "evaluate",
            "--target",
            str(EXAMPLE_HARDENED),
            "-p",
            "github-level-1",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert (out_dir / "evaluation-report.json").is_file()


def test_subprocess_evaluate_positional_target(tmp_path: Path) -> None:
    out_dir = tmp_path / "pytest-subprocess-positional"
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            "evaluate",
            str(EXAMPLE_HARDENED),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout


def test_subprocess_root_top_level_target(tmp_path: Path) -> None:
    out_dir = tmp_path / "pytest-subprocess-root-top"
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            "--target",
            str(EXAMPLE_HARDENED),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout


def test_subprocess_root_top_level_profile_short_flag(tmp_path: Path) -> None:
    out_dir = tmp_path / "pytest-subprocess-root-top-short-profile"
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            "--target",
            str(EXAMPLE_HARDENED),
            "-p",
            "github-level-1",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert (out_dir / "evaluation-report.json").is_file()


def test_subprocess_root_positional_target(tmp_path: Path) -> None:
    out_dir = tmp_path / "pytest-subprocess-root-pos"
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            str(EXAMPLE_HARDENED),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout


def test_subprocess_missing_target_exit_code_2(tmp_path: Path) -> None:
    proc = _run_module(
        [
            "--target",
            str(ROOT / "does-not-exist-oss-policy-kit-xyz"),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(tmp_path / "pytest-subprocess-missing"),
        ]
    )
    assert proc.returncode == 2


def test_subprocess_missing_waivers_exit_code_2(tmp_path: Path) -> None:
    proc = _run_module(
        [
            "evaluate",
            "--target",
            str(EXAMPLE_HARDENED),
            "--profile",
            "github-level-1",
            "--waivers",
            str(TEST_FIXTURES / "missing-waivers.yaml"),
            "--output-dir",
            str(tmp_path / "pytest-subprocess-missing-waivers"),
        ]
    )
    assert proc.returncode == 2


@pytest.mark.skipif(not _INVALID_WORKFLOW.is_dir(), reason="invalid-workflow fixture not present")
def test_subprocess_invalid_workflow_emits_operational_warnings(tmp_path: Path) -> None:
    out_dir = tmp_path / "pytest-subprocess-invalid-wf"
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            "evaluate",
            "--target",
            str(_INVALID_WORKFLOW),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    combined = proc.stdout + proc.stderr
    assert "Operational warnings" in combined
    assert "Workflow parse issue" in combined or "workflow" in combined.lower()


@pytest.mark.skipif(not _INVALID_WORKFLOW.is_dir(), reason="invalid-workflow fixture not present")
def test_subprocess_invalid_workflow_quiet_suppresses_operational_warnings(tmp_path: Path) -> None:
    out_dir = tmp_path / "pytest-subprocess-invalid-wf-quiet"
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            "evaluate",
            "--target",
            str(_INVALID_WORKFLOW),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(out_dir),
            "--summary-only",
            "--quiet",
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "Operational warnings (" not in proc.stderr
    assert "Workflow parse issue" not in proc.stderr
    assert "Outcome:" in proc.stdout


@pytest.mark.skipif(not _REPO_WITH_SPACES.is_dir(), reason="repo with spaces fixture not present")
def test_subprocess_target_with_spaces(tmp_path: Path) -> None:
    out_dir = tmp_path / "pytest-subprocess-spaces"
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            "evaluate",
            "--target",
            str(_REPO_WITH_SPACES),
            "--profile",
            "github-release-hardening-1",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout


def test_subprocess_recommend_profile_human_ascii_no_unicode_arrow() -> None:
    proc = _run_module(["recommend-profile", "--target", str(EXAMPLE_HARDENED), "--format", "human"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    out = proc.stdout or ""
    assert "\u2192" not in out
    assert "->" in out or "Profile suggestions" in out
    # Hardened fixture now includes AWS/Azure-shaped signals; suggestions may prioritize those ladders first.
    assert "github-level" in out or "aws-release" in out or "azure-release" in out


def test_subprocess_recommend_profile_json_schema_v2() -> None:
    proc = _run_module(["recommend-profile", "--target", str(EXAMPLE_HARDENED), "--format", "json"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(proc.stdout)
    # M-003 (v6.0.0, ADR-008): schema_version is now an absolute URL.
    # The legacy shorthand is still accepted by internal consumers for one
    # minor; this test asserts the new canonical value.
    assert data["schema_version"] == (
        "https://schemas.lucashgrifoni.io/oss-policy-kit/recommend-profile/v2.json"
    )
    assert "signals_detected" in data
    assert "suggestions" in data
    assert "notes" in data


def test_subprocess_scaffold_evidence_skip_then_force(tmp_path: Path) -> None:
    repo = tmp_path / "scaffold-cli"
    repo.mkdir()
    p1 = _run_module(["scaffold-evidence", "--target", str(repo), "--platform", "github"])
    assert p1.returncode == 0, p1.stderr + p1.stdout
    assert "created:" in p1.stdout
    bp = repo / ".oss-policy-kit" / "evidence" / "branch-protection.json"
    bp.write_text(bp.read_text(encoding="utf-8").replace("REPLACE_ME", "KEEP"), encoding="utf-8")

    p2 = _run_module(["scaffold-evidence", "--target", str(repo), "--platform", "github"])
    assert p2.returncode == 0
    assert "KEEP" in bp.read_text(encoding="utf-8")

    p3 = _run_module(["scaffold-evidence", "--target", str(repo), "--platform", "github", "--force"])
    assert p3.returncode == 0
    assert "KEEP" not in bp.read_text(encoding="utf-8")


def test_subprocess_evaluate_many_profiles_short_flag(tmp_path: Path) -> None:
    out_dir = tmp_path / "pytest-subprocess-batch-short-profile"
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            "evaluate-many",
            "--target-root",
            str(ROOT / "tests" / "fixtures" / "repositories"),
            "-p",
            "github-level-1",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert (out_dir / "evaluation-batch.json").is_file()
