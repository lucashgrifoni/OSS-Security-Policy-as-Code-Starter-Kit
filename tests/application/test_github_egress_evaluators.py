"""Branch coverage for GitHub egress / workflow-lockfile evaluators."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.evaluators import github as gh
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, *, workflow_paths: list[Path] | None = None) -> gh.EvalContext:
    return gh.EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-3",
        workflows=WorkflowAnalysis(workflow_paths=workflow_paths or []),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _wf(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / ".github" / "workflows" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_egress_hrn_001(tmp_path: Path) -> None:
    assert gh.eval_gh_egress_hrn_001(_ctx(tmp_path)).status == ControlStatus.NOT_APPLICABLE
    bad = _wf(tmp_path, "ci.yml", "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n")
    assert gh.eval_gh_egress_hrn_001(_ctx(tmp_path, workflow_paths=[bad])).status == ControlStatus.FAIL
    good = _wf(tmp_path, "rel.yml", "steps:\n  - uses: step-security/harden-runner@abc\n")
    assert gh.eval_gh_egress_hrn_001(_ctx(tmp_path, workflow_paths=[bad, good])).status == ControlStatus.PASS


def test_egress_native_001(tmp_path: Path) -> None:
    assert gh.eval_gh_egress_native_001(_ctx(tmp_path)).status == ControlStatus.NOT_APPLICABLE
    none = _wf(tmp_path, "ci.yml", "on: push\n")
    assert (
        gh.eval_gh_egress_native_001(_ctx(tmp_path, workflow_paths=[none])).status
        == ControlStatus.MANUAL_REVIEW_REQUIRED
    )
    fw = _wf(tmp_path, "fw.yml", "firewall:\n  egress-policy: block\n")
    assert gh.eval_gh_egress_native_001(_ctx(tmp_path, workflow_paths=[fw])).status == ControlStatus.PASS


def test_wf_lockfile_001(tmp_path: Path) -> None:
    # No workflows dir -> NA
    assert gh.eval_gh_wf_lockfile_001(_ctx(tmp_path)).status == ControlStatus.NOT_APPLICABLE
    # Workflows dir present, no lockfile -> non-NA outcome
    _wf(tmp_path, "ci.yml", "on: push\n")
    out_no_lock = gh.eval_gh_wf_lockfile_001(_ctx(tmp_path))
    assert out_no_lock.status in {ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED, ControlStatus.PASS}
    # Lockfile present -> PASS
    (tmp_path / ".github" / "workflows" / "actions.lock").write_text("pins\n", encoding="utf-8")
    assert gh.eval_gh_wf_lockfile_001(_ctx(tmp_path)).status == ControlStatus.PASS
