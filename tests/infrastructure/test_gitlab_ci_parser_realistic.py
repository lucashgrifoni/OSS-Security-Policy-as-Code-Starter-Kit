"""Smoke test: GitLab CI parser against a realistic, multi-job, multi-include pipeline."""

from __future__ import annotations

import shutil
from pathlib import Path

from oss_policy_kit.infrastructure.gitlab_ci_parser import analyze_gitlab_ci

_FIXTURE = Path(__file__).parent.parent / "fixtures" / "gitlab-ci-realistic.yml"


def test_realistic_pipeline_parses_without_errors(tmp_path: Path) -> None:
    """Realistic ~120-line .gitlab-ci.yml must parse cleanly (no parse_errors)."""
    shutil.copy(_FIXTURE, tmp_path / ".gitlab-ci.yml")
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.pipeline_paths) == 1
    assert a.parse_errors == [], f"unexpected parse errors: {a.parse_errors}"


def test_realistic_pipeline_classifies_all_images(tmp_path: Path) -> None:
    """All `image:` references in the realistic fixture are explicitly versioned —
    parser must classify them as pinned (not unpinned, not mutable-tag)."""
    shutil.copy(_FIXTURE, tmp_path / ".gitlab-ci.yml")
    a = analyze_gitlab_ci(tmp_path)
    assert a.image_refs_pinned, "expected at least one pinned image"
    assert a.image_refs_unpinned == [], f"unexpected unpinned: {[r for _, r in a.image_refs_unpinned]}"
    assert a.image_refs_mutable_tag == [], f"unexpected mutable-tag: {[r for _, r in a.image_refs_mutable_tag]}"


def test_realistic_pipeline_detects_inherit_secrets_listform(tmp_path: Path) -> None:
    """`inherit: secrets: [PROD_DEPLOY_KEY, PROD_SIGNING_KEY]` is a LIST, not
    `true`. The parser flags broad-inherit only on `: true`, so this fixture
    should NOT trip jobs_with_inherit_secrets."""
    shutil.copy(_FIXTURE, tmp_path / ".gitlab-ci.yml")
    a = analyze_gitlab_ci(tmp_path)
    assert a.jobs_with_inherit_secrets == []


def test_realistic_pipeline_detects_remote_include(tmp_path: Path) -> None:
    """`include: - remote: https://...` should be tracked in includes_remote."""
    shutil.copy(_FIXTURE, tmp_path / ".gitlab-ci.yml")
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.includes_remote) >= 1
    assert any("gitlab.example.com" in ref for _, ref in a.includes_remote)


def test_realistic_pipeline_detects_trigger_restrictions(tmp_path: Path) -> None:
    """Most jobs in the realistic fixture declare rules: — coarse trigger
    restriction signal should fire."""
    shutil.copy(_FIXTURE, tmp_path / ".gitlab-ci.yml")
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.jobs_with_trigger_restrictions) >= 1


def test_realistic_pipeline_no_curl_pipe_shell(tmp_path: Path) -> None:
    """Fixture is intentionally clean — no `curl ... | sh`."""
    shutil.copy(_FIXTURE, tmp_path / ".gitlab-ci.yml")
    a = analyze_gitlab_ci(tmp_path)
    assert a.script_uses_curl_pipe_shell == []
