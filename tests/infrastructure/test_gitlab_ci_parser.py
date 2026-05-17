"""GitLab CI parser: image pinning, script safety, secret inheritance, remote includes."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure.gitlab_ci_parser import analyze_gitlab_ci


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_analyze_returns_empty_when_no_gitlab_ci(tmp_path: Path) -> None:
    a = analyze_gitlab_ci(tmp_path)
    assert a.pipeline_paths == []
    assert a.image_refs_pinned == []
    assert a.image_refs_unpinned == []
    assert a.parse_errors == []


def test_analyze_detects_root_pipeline(tmp_path: Path) -> None:
    _write(tmp_path, ".gitlab-ci.yml", "stages: [test]\ntest:\n  script: ['echo hi']\n")
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.pipeline_paths) == 1
    assert a.pipeline_paths[0].name == ".gitlab-ci.yml"


def test_analyze_classifies_image_pinned_tag(tmp_path: Path) -> None:
    _write(tmp_path, ".gitlab-ci.yml", "test:\n  image: python:3.12-slim\n  script: ['pytest']\n")
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.image_refs_pinned) == 1
    assert a.image_refs_pinned[0][1] == "python:3.12-slim"
    assert a.image_refs_unpinned == []


def test_analyze_classifies_image_pinned_digest(tmp_path: Path) -> None:
    digest = "alpine@sha256:" + ("a" * 64)
    _write(tmp_path, ".gitlab-ci.yml", f"test:\n  image: {digest}\n  script: ['echo']\n")
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.image_refs_pinned) == 1
    assert a.image_refs_pinned[0][1] == digest


def test_analyze_classifies_image_unpinned(tmp_path: Path) -> None:
    _write(tmp_path, ".gitlab-ci.yml", "test:\n  image: ubuntu\n  script: ['echo']\n")
    a = analyze_gitlab_ci(tmp_path)
    assert a.image_refs_unpinned == [(tmp_path / ".gitlab-ci.yml", "ubuntu")]


def test_analyze_classifies_mutable_tag_latest(tmp_path: Path) -> None:
    """python:latest is technically tagged but the tag drifts; should NOT count as pinned."""
    _write(tmp_path, ".gitlab-ci.yml", "test:\n  image: python:latest\n  script: ['echo']\n")
    a = analyze_gitlab_ci(tmp_path)
    assert a.image_refs_pinned == []
    assert a.image_refs_unpinned == []
    assert a.image_refs_mutable_tag == [(tmp_path / ".gitlab-ci.yml", "python:latest")]


def test_analyze_classifies_mutable_tag_edge_stable_nightly_lts(tmp_path: Path) -> None:
    body = (
        "a:\n  image: alpine:edge\n  script: ['echo']\n"
        "b:\n  image: ruby:stable\n  script: ['echo']\n"
        "c:\n  image: node:nightly\n  script: ['echo']\n"
        "d:\n  image: node:lts\n  script: ['echo']\n"
    )
    _write(tmp_path, ".gitlab-ci.yml", body)
    a = analyze_gitlab_ci(tmp_path)
    refs = {ref for _, ref in a.image_refs_mutable_tag}
    assert refs == {"alpine:edge", "ruby:stable", "node:nightly", "node:lts"}
    assert a.image_refs_pinned == []


def test_analyze_specific_tag_still_pinned(tmp_path: Path) -> None:
    """Specific tags like :3.12-slim are still pinned (not mutable)."""
    _write(tmp_path, ".gitlab-ci.yml", "test:\n  image: python:3.12-slim\n  script: ['echo']\n")
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.image_refs_pinned) == 1
    assert a.image_refs_mutable_tag == []


def test_analyze_detects_image_in_dict_form(tmp_path: Path) -> None:
    _write(tmp_path, ".gitlab-ci.yml", "test:\n  image:\n    name: python:3.12\n  script: ['pytest']\n")
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.image_refs_pinned) == 1
    assert a.image_refs_pinned[0][1] == "python:3.12"


def test_analyze_detects_curl_pipe_shell(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".gitlab-ci.yml",
        "test:\n  image: alpine:3.19\n  script:\n    - curl https://get.example/install.sh | sh\n",
    )
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.script_uses_curl_pipe_shell) == 1


def test_analyze_does_not_flag_curl_alone(tmp_path: Path) -> None:
    """`curl` on its own (no pipe to shell) must NOT trip the signal."""
    _write(
        tmp_path,
        ".gitlab-ci.yml",
        "test:\n  image: alpine:3.19\n  script:\n    - curl -fsSL https://example.com -o out\n",
    )
    a = analyze_gitlab_ci(tmp_path)
    assert a.script_uses_curl_pipe_shell == []


def test_analyze_detects_inherit_secrets_true(tmp_path: Path) -> None:
    _write(
        tmp_path, ".gitlab-ci.yml", "test:\n  image: alpine:3.19\n  inherit:\n    secrets: true\n  script: ['echo']\n"
    )
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.jobs_with_inherit_secrets) == 1


def test_analyze_does_not_flag_inherit_secrets_false(tmp_path: Path) -> None:
    _write(
        tmp_path, ".gitlab-ci.yml", "test:\n  image: alpine:3.19\n  inherit:\n    secrets: false\n  script: ['echo']\n"
    )
    a = analyze_gitlab_ci(tmp_path)
    assert a.jobs_with_inherit_secrets == []


def test_analyze_detects_remote_include(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".gitlab-ci.yml",
        """
include:
  - remote: 'https://example.com/ci.yml'
  - local: '/.gitlab/local.yml'

test:
  image: alpine:3.19
  script: ['echo']
""",
    )
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.includes_remote) == 1
    assert a.includes_remote[0][1] == "https://example.com/ci.yml"


def test_analyze_bare_https_include_treated_as_remote(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".gitlab-ci.yml",
        """
include:
  - 'https://example.com/ci.yml'

test:
  image: alpine:3.19
  script: ['echo']
""",
    )
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.includes_remote) == 1


def test_analyze_template_include_not_treated_as_remote(tmp_path: Path) -> None:
    """`include: template:` fetches from GitLab built-ins; we treat as local-trust-equivalent."""
    _write(
        tmp_path,
        ".gitlab-ci.yml",
        """
include:
  - template: 'Security/SAST.gitlab-ci.yml'

test:
  image: alpine:3.19
  script: ['echo']
""",
    )
    a = analyze_gitlab_ci(tmp_path)
    assert a.includes_remote == []


def test_analyze_detects_trigger_restrictions(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".gitlab-ci.yml",
        """
test:
  image: alpine:3.19
  script: ['echo']
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
""",
    )
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.jobs_with_trigger_restrictions) == 1


def test_analyze_reports_parse_errors(tmp_path: Path) -> None:
    _write(tmp_path, ".gitlab-ci.yml", "::: not valid yaml :::\n  bad")
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.parse_errors) == 1
    # Pipeline path still recorded even if parse failed.
    assert len(a.pipeline_paths) == 1


def test_analyze_discovers_gitlab_subdir_files(tmp_path: Path) -> None:
    (tmp_path / ".gitlab").mkdir()
    _write(tmp_path / ".gitlab", ".gitlab-ci.yml", "test:\n  image: alpine:3.19\n  script: ['echo']\n")
    a = analyze_gitlab_ci(tmp_path)
    assert len(a.pipeline_paths) == 1
    assert a.pipeline_paths[0].parent.name == ".gitlab"
