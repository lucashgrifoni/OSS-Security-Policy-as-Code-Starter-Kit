"""GH-RUNNER-062: signal + evidence-backed self-hosted runner posture."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import EvalContext, eval_gh_runner_062
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis, analyze_workflows


def _ctx_with_workflows(repo: Path) -> EvalContext:
    return EvalContext(
        repo_root=repo,
        profile_id="github-level-3",
        workflows=analyze_workflows(repo),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _ctx_no_workflows(tmp_path: Path) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write_workflow(repo: Path, name: str, content: str) -> Path:
    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / name
    p.write_text(content, encoding="utf-8")
    return p


def test_gh_runner_062_not_applicable_when_no_workflows(tmp_path: Path) -> None:
    out = eval_gh_runner_062(_ctx_no_workflows(tmp_path))
    assert out.status == ControlStatus.NOT_APPLICABLE


def test_gh_runner_062_pass_when_only_github_hosted(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "ci.yml",
        "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: [{run: echo hi}]\n",
    )
    out = eval_gh_runner_062(_ctx_with_workflows(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "github-hosted" in out.reason.lower() or "no self-hosted" in out.reason.lower()


def test_gh_runner_062_fail_on_pr_self_hosted(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "pr.yml",
        "name: pr\non: pull_request\njobs:\n  build:\n    runs-on: self-hosted\n    steps: [{run: echo hi}]\n",
    )
    out = eval_gh_runner_062(_ctx_with_workflows(tmp_path))
    assert out.status == ControlStatus.FAIL
    assert "trivy-action" in out.reason.lower() or "pr-triggered" in out.reason.lower()


def test_gh_runner_062_manual_review_when_self_hosted_without_ephemeral(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "build.yml",
        "name: build\non: push\njobs:\n  build:\n    runs-on: self-hosted\n    steps: [{run: echo hi}]\n",
    )
    out = eval_gh_runner_062(_ctx_with_workflows(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "ephemeral" in out.reason.lower()


def test_gh_runner_062_pass_when_self_hosted_ephemeral_uniformly(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "build.yml",
        "name: build\non: push\njobs:\n  build:\n    runs-on: [self-hosted, ephemeral]\n    steps: [{run: echo hi}]\n",
    )
    out = eval_gh_runner_062(_ctx_with_workflows(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "ephemeral" in out.reason.lower()


def test_gh_runner_062_evidence_pass_with_runner_groups_json(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "build.yml",
        "name: build\non: push\njobs:\n  build:\n    runs-on: [self-hosted, ephemeral]\n    steps: [{run: echo hi}]\n",
    )
    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "runner-groups.json").write_text(
        json.dumps(
            {
                "schema_version": "runner-groups/v1",
                "attested_at": "2026-04-21",
                "attested_by": "test",
                "org_name": "test-org",
                "runner_groups": [
                    {
                        "name": "default",
                        "restricted_to_private_repos": True,
                        "allows_public_repositories": False,
                        "ephemeral_runners": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = eval_gh_runner_062(_ctx_with_workflows(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.confidence == "high"


def test_gh_runner_062_evidence_fail_when_runner_group_allows_public(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "build.yml",
        "name: build\non: push\njobs:\n  build:\n    runs-on: [self-hosted, ephemeral]\n    steps: [{run: echo hi}]\n",
    )
    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "runner-groups.json").write_text(
        json.dumps(
            {
                "schema_version": "runner-groups/v1",
                "attested_at": "2026-04-21",
                "attested_by": "test",
                "org_name": "test-org",
                "runner_groups": [
                    {
                        "name": "default",
                        "restricted_to_private_repos": False,
                        "allows_public_repositories": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = eval_gh_runner_062(_ctx_with_workflows(tmp_path))
    assert out.status == ControlStatus.FAIL
    assert "public" in out.reason.lower() or "private" in out.reason.lower()
