"""Batch evaluation aggregates and gates."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.conftest import EXAMPLE_HARDENED, EXAMPLE_VULNERABLE, ROOT

from oss_policy_kit.application.batch_evaluate import (
    _is_meta_directory,
    discover_batch_targets,
    is_likely_repository,
    run_batch_evaluation,
)


def test_discover_skips_dot_directories(tmp_path: Path) -> None:
    (tmp_path / "visible").mkdir()
    (tmp_path / ".hidden").mkdir()
    found = discover_batch_targets(tmp_path, include=None, exclude=None)
    assert [p.name for p in found] == ["visible"]


def test_discover_include_filters_by_fnmatch(tmp_path: Path) -> None:
    """``--include`` selects only matching child directories (fnmatch on name)."""

    for name in ("lab-foo", "lab-bar", "service-x", "service-y"):
        (tmp_path / name).mkdir()
    found = discover_batch_targets(tmp_path, include="lab-*", exclude=None)
    assert sorted(p.name for p in found) == ["lab-bar", "lab-foo"]


def test_discover_exclude_removes_matching_dirs(tmp_path: Path) -> None:
    """``--exclude`` removes matching child directories (fnmatch on name)."""

    for name in ("svc-app", "svc-out", "out-build", "out-cache"):
        (tmp_path / name).mkdir()
    found = discover_batch_targets(tmp_path, include=None, exclude="out-*")
    assert sorted(p.name for p in found) == ["svc-app", "svc-out"]


def test_discover_include_and_exclude_combine(tmp_path: Path) -> None:
    """``--include`` and ``--exclude`` combine: include narrows first, then exclude trims.

    With ``--include "svc-*" --exclude "*-deprecated"``, only ``svc-app`` survives —
    ``svc-deprecated`` matches include but is filtered out by exclude, and the other
    children never matched include.
    """

    for name in ("svc-app", "svc-deprecated", "lab-x", "out-build"):
        (tmp_path / name).mkdir()
    found = discover_batch_targets(tmp_path, include="svc-*", exclude="*-deprecated")
    assert [p.name for p in found] == ["svc-app"]


def test_run_batch_evaluation_applies_include_filter(tmp_path: Path) -> None:
    """``run_batch_evaluation`` honors ``--include`` end-to-end (no excluded child gets evaluated)."""

    mono = tmp_path / "mono"
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "lab-foo")
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "service-x")
    out = tmp_path / "out"
    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include="lab-*",
        exclude=None,
    )
    payload = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    processed = {r["target_name"] for r in payload.get("runs", [])}
    assert processed == {"lab-foo"}


def test_run_batch_evaluation_applies_exclude_filter(tmp_path: Path) -> None:
    """``run_batch_evaluation`` honors ``--exclude`` end-to-end."""

    mono = tmp_path / "mono"
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "svc-keep")
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "out-build")
    out = tmp_path / "out"
    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude="out-*",
    )
    payload = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    processed = {r["target_name"] for r in payload.get("runs", [])}
    assert processed == {"svc-keep"}


def test_readme_alone_is_not_a_repository(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# just docs", encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is False
    assert sig == ""


def test_readme_plus_package_json_is_a_repository(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# app", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == "package.json"


def test_git_dir_is_a_repository(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == ".git"


def test_scripts_dir_with_readme_not_a_repository(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# utility scripts", encoding="utf-8")
    (tmp_path / "helper.py").write_text("print('hello')", encoding="utf-8")
    ok, _sig = is_likely_repository(tmp_path)
    assert ok is False


def test_nested_azure_pipeline_marks_likely_repository(tmp_path: Path) -> None:
    nested = tmp_path / "pipelines" / "azure"
    nested.mkdir(parents=True)
    (nested / "ci.yml").write_text("trigger: [main]\n", encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == "pipelines/azure/*.yml"


def test_github_workflows_yml_is_a_repository_signal(tmp_path: Path) -> None:
    """A directory with at least one ``.github/workflows/*.yml`` is repo-like.

    Catches the case where a project owns CI workflows but no manifest file at the
    target root (for example, a docs-bearing repo that only ships GitHub Actions).
    """

    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("on: [push]\njobs: {}\n", encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == ".github/workflows/*.yml"


def test_github_workflows_yaml_extension_is_a_repository_signal(tmp_path: Path) -> None:
    """The same signal works for the ``.yaml`` extension."""

    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yaml").write_text("on: [push]\njobs: {}\n", encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == ".github/workflows/*.yaml"


def test_monorepo_fallback_detects_dockerfile_at_depth_1(tmp_path: Path) -> None:
    """Layout ``infra/Dockerfile`` (depth-1 signal) must mark the root as a repository.

    Closes the v5.7.0 monorepo gap where cloud-native repos hold their primary
    build files one level deep under ``infra/`` or ``targets/``.
    """

    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == "*/Dockerfile"


def test_monorepo_fallback_detects_dockerfile_at_depth_2(tmp_path: Path) -> None:
    """Layout ``targets/svc/Dockerfile`` (depth-2 signal) must mark the root as a repository."""

    nested = tmp_path / "targets" / "svc"
    nested.mkdir(parents=True)
    (nested / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == "*/*/Dockerfile"


def test_monorepo_fallback_detects_k8s_manifests_pattern(tmp_path: Path) -> None:
    """Layout ``infra/k8s-manifests/*.yaml`` must be recognized as a repo signal."""

    manifests = tmp_path / "infra" / "k8s-manifests"
    manifests.mkdir(parents=True)
    (manifests / "deployment.yaml").write_text("kind: Deployment\n", encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == "*/k8s-manifests/*.yaml"


def test_monorepo_fallback_detects_package_json_at_depth_1(tmp_path: Path) -> None:
    """Layout ``app/package.json`` (frontend-only monorepo subdir) must qualify."""

    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == "*/package.json"


def test_monorepo_fallback_does_not_trip_on_nested_readmes(tmp_path: Path) -> None:
    """Nested ``README.md`` files alone never make a directory look repo-like.

    The fallback only triggers on primary signals (build manifests, ``.git``,
    Dockerfile, CI files). This keeps utility / docs subdirectories filtered out
    of ``evaluate-many`` discovery.
    """

    docs = tmp_path / "docs" / "section"
    docs.mkdir(parents=True)
    (docs / "README.md").write_text("# docs", encoding="utf-8")
    (tmp_path / "README.md").write_text("# root docs", encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is False
    assert sig == ""


def test_empty_github_workflows_directory_is_not_a_repository(tmp_path: Path) -> None:
    """A bare ``.github/workflows/`` (no YAML files) must NOT count as a repo signal.

    This prevents false positives from a parent project that only carries a templates
    or docs folder under ``.github/`` without actual workflow files.
    """

    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    ok, sig = is_likely_repository(tmp_path)
    assert ok is False
    assert sig == ""


def test_skip_non_repos_processes_workflows_only_target(tmp_path: Path) -> None:
    """``--skip-non-repos`` must process a child whose only signal is ``.github/workflows/``."""

    mono = tmp_path / "mono"
    workflows_only = mono / "ci-only"
    workflows_only.mkdir(parents=True)
    wf = workflows_only / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("on: [push]\njobs: {}\n", encoding="utf-8")
    manifest_child = mono / "with-manifest"
    manifest_child.mkdir()
    (manifest_child / "package.json").write_text('{"name":"x"}', encoding="utf-8")
    noise = mono / "scripts"
    noise.mkdir()
    out = tmp_path / "out"
    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        skip_non_repos=True,
    )
    payload = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    processed = sorted({r["target_name"] for r in payload.get("runs", [])})
    skipped = [s["name"] for s in payload.get("skipped_directories", [])]
    assert "ci-only" in processed
    assert "with-manifest" in processed
    assert "scripts" in skipped


def test_batch_all_tied_true_when_same_fail_counts(tmp_path: Path) -> None:
    mono = tmp_path / "mono"
    a = mono / "a"
    b = mono / "b"
    shutil.copytree(EXAMPLE_VULNERABLE, a)
    shutil.copytree(EXAMPLE_VULNERABLE, b)
    out = tmp_path / "out"
    result = run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        fail_on="none",
    )
    assert result.gate_violated is False
    payload = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    assert payload["all_tied"] is True
    assert payload["common_fail_count"] is not None
    md = (out / "evaluation-batch.md").read_text(encoding="utf-8")
    assert "share the same failure count" in md
    assert "failure_distribution" in md or "Failure distribution" in md


def test_batch_not_all_tied_mixed_scores(tmp_path: Path) -> None:
    mono = tmp_path / "mono"
    shutil.copytree(EXAMPLE_HARDENED, mono / "good")
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "bad")
    out = tmp_path / "out"
    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
    )
    payload = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    assert payload["all_tied"] is False
    assert payload["common_fail_count"] is None


def test_batch_fail_on_gate_violated(tmp_path: Path) -> None:
    mono = tmp_path / "mono"
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "bad")
    out = tmp_path / "out"
    result = run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        fail_on="fail",
    )
    assert result.gate_violated is True


def test_skip_non_repos_lists_skipped(tmp_path: Path) -> None:
    mono = tmp_path / "mono"
    good = mono / "svc"
    good.mkdir(parents=True)
    (good / "README.md").write_text("# svc", encoding="utf-8")
    (good / "pyproject.toml").write_text('[project]\nname = "svc"\nversion = "0.0.0"\n', encoding="utf-8")
    noise = mono / "scripts"
    noise.mkdir()
    out = tmp_path / "out"
    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        skip_non_repos=True,
    )
    payload = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    skipped = payload.get("skipped_directories") or []
    assert len(skipped) == 1
    assert skipped[0]["name"] == "scripts"
    md = (out / "evaluation-batch.md").read_text(encoding="utf-8")
    assert "Skipped directories" in md


def test_progress_callback_invoked_per_run(tmp_path: Path) -> None:
    mono = tmp_path / "mono"
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "a")
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "b")
    out = tmp_path / "out"
    cb = MagicMock()
    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1", "github-level-2"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        progress_callback=cb,
    )
    assert cb.call_count == 4


def test_repositories_fixture_batch_smoke(tmp_path: Path) -> None:
    """Existing regression target: fixture folder under tests/fixtures/repositories."""

    root = ROOT / "tests" / "fixtures" / "repositories"
    if not root.is_dir():
        pytest.skip("fixture repositories dir missing")
    out = tmp_path / "batch"
    run_batch_evaluation(
        target_root=root,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
    )
    assert (out / "evaluation-batch.json").is_file()


# --- MELHORIA-002 / F-007: meta-directory skip ------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "out",
        "Out",
        "OUTPUT",
        "dist",
        "build",
        ".tmp",
        "_output",
        "node_modules",
        "venv",
        ".venv",
        "out-fullsuite-2026-05-11",
        "out_archived",
        "build-2025",
        "dist-rc1",
        "coverage",
        "htmlcov",
    ],
)
def test_meta_directory_names_are_recognized(name: str) -> None:
    assert _is_meta_directory(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "01-core-saas-lab",
        "07-oss-policy-fixtures-lab",
        "Projeto - Threat Modeling",
        "my-real-repo",
        "outpost",  # starts with 'out' but not 'out-' / 'out_' prefix
        "buildup-lab",  # starts with 'build' but not 'build-' prefix
    ],
)
def test_real_project_names_are_not_meta(name: str) -> None:
    assert _is_meta_directory(name) is False


def test_run_batch_skips_meta_dirs_with_skip_non_repos(tmp_path: Path) -> None:
    """Even when an output dir happens to contain repo signals, --skip-non-repos
    should skip it because the folder name screams 'output / build artifact'."""
    # Real repo (kept)
    real = tmp_path / "real-app"
    real.mkdir()
    (real / "package.json").write_text("{}", encoding="utf-8")

    # Meta dir that LOOKS like a repo (has package.json from a build) — must be skipped.
    meta = tmp_path / "out-fullsuite-2026-05-11"
    meta.mkdir()
    (meta / "package.json").write_text("{}", encoding="utf-8")

    out = tmp_path / "_out"
    run_batch_evaluation(
        target_root=tmp_path,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        skip_non_repos=True,
    )
    batch = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    skipped = batch.get("skipped_directories", [])
    skipped_names = {s["name"] for s in skipped}
    assert "out-fullsuite-2026-05-11" in skipped_names
    assert "real-app" not in skipped_names
