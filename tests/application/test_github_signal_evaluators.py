"""Branch coverage for GitHub workflow signal evaluators (GH-MERGEQ/WF-018/019/020/REL-021)."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.evaluators import github as gh
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, wf: WorkflowAnalysis) -> gh.EvalContext:
    return gh.EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-2",
        workflows=wf,
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _wf(tmp_path: Path, name: str = "ci.yml") -> Path:
    p = tmp_path / name
    p.write_text("on: push\n", encoding="utf-8")
    return p


def test_gh_mergeq_053(tmp_path: Path) -> None:
    p = _wf(tmp_path)
    assert gh.eval_gh_mergeq_053(_ctx(tmp_path, WorkflowAnalysis())).status == ControlStatus.NOT_APPLICABLE
    wf = WorkflowAnalysis(workflow_paths=[p], merge_queue_signal_paths=[p])
    assert gh.eval_gh_mergeq_053(_ctx(tmp_path, wf)).status == ControlStatus.PASS
    assert gh.eval_gh_mergeq_053(_ctx(tmp_path, WorkflowAnalysis(workflow_paths=[p]))).status == ControlStatus.FAIL


def test_gh_wf_018(tmp_path: Path) -> None:
    p = _wf(tmp_path)
    wf = WorkflowAnalysis(workflow_paths=[p], reusable_secrets_inherit_paths=[p])
    assert gh.eval_gh_wf_018(_ctx(tmp_path, wf)).status == ControlStatus.FAIL
    assert gh.eval_gh_wf_018(_ctx(tmp_path, WorkflowAnalysis(workflow_paths=[p]))).status == ControlStatus.PASS
    assert gh.eval_gh_wf_018(_ctx(tmp_path, WorkflowAnalysis())).status == ControlStatus.NOT_APPLICABLE


def test_gh_wf_019(tmp_path: Path) -> None:
    p = _wf(tmp_path)
    wf = WorkflowAnalysis(workflow_paths=[p], pr_self_hosted_runner_paths=[p])
    assert gh.eval_gh_wf_019(_ctx(tmp_path, wf)).status == ControlStatus.FAIL
    assert gh.eval_gh_wf_019(_ctx(tmp_path, WorkflowAnalysis(workflow_paths=[p]))).status == ControlStatus.PASS


def test_gh_wf_020(tmp_path: Path) -> None:
    p = _wf(tmp_path)
    wf = WorkflowAnalysis(workflow_paths=[p], broad_job_permissions=[(p, "deploy: write-all")])
    assert gh.eval_gh_wf_020(_ctx(tmp_path, wf)).status == ControlStatus.FAIL
    assert gh.eval_gh_wf_020(_ctx(tmp_path, WorkflowAnalysis(workflow_paths=[p]))).status == ControlStatus.PASS


def test_gh_rel_021(tmp_path: Path) -> None:
    p1 = _wf(tmp_path, "release.yml")
    p2 = _wf(tmp_path, "deploy.yml")
    # No release workflows -> NA
    assert gh.eval_gh_rel_021(_ctx(tmp_path, WorkflowAnalysis(workflow_paths=[p1]))).status == ControlStatus.NOT_APPLICABLE
    # Single missing-concurrency -> FAIL (singular phrasing)
    wf = WorkflowAnalysis(workflow_paths=[p1], release_workflow_paths=[p1], release_workflows_missing_concurrency=[p1])
    assert gh.eval_gh_rel_021(_ctx(tmp_path, wf)).status == ControlStatus.FAIL
    # Multiple missing-concurrency -> FAIL (plural phrasing, line 181-182)
    wf2 = WorkflowAnalysis(
        workflow_paths=[p1, p2], release_workflow_paths=[p1, p2],
        release_workflows_missing_concurrency=[p1, p2],
    )
    assert gh.eval_gh_rel_021(_ctx(tmp_path, wf2)).status == ControlStatus.FAIL
    # Release workflows present, concurrency declared -> PASS
    wf3 = WorkflowAnalysis(workflow_paths=[p1], release_workflow_paths=[p1])
    assert gh.eval_gh_rel_021(_ctx(tmp_path, wf3)).status == ControlStatus.PASS


def test_gh_rel_021_no_workflows(tmp_path: Path) -> None:
    assert gh.eval_gh_rel_021(_ctx(tmp_path, WorkflowAnalysis())).status == ControlStatus.NOT_APPLICABLE
