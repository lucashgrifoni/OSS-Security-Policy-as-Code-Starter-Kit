"""Branch coverage for the AWS CodeBuild/CodePipeline signal evaluators (AWS-CI/SECRET/SEC/SCA/SBOM/PIPE/PROV)."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.evaluators import aws as awsev
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, aws: AwsCiAnalysis, *, profile_id: str = "aws-level-1") -> awsev.EvalContext:
    return awsev.EvalContext(
        repo_root=tmp_path,
        profile_id=profile_id,
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=aws,
        scorecard=None,
    )


def _p(tmp_path: Path, name: str = "buildspec.yml") -> Path:
    p = tmp_path / name
    p.write_text("version: 0.2\n", encoding="utf-8")
    return p


def test_aws_ci_037(tmp_path: Path) -> None:
    bs = _p(tmp_path)
    assert awsev.eval_aws_ci_037(_ctx(tmp_path, AwsCiAnalysis(buildspec_paths=[bs]))).status == ControlStatus.PASS
    assert awsev.eval_aws_ci_037(_ctx(tmp_path, AwsCiAnalysis())).status == ControlStatus.FAIL


def test_aws_secret_038_branches(tmp_path: Path) -> None:
    bs = _p(tmp_path)
    # inline secret risk -> FAIL
    a = AwsCiAnalysis(buildspec_paths=[bs], inline_secret_risk_paths=[bs])
    assert awsev.eval_aws_secret_038(_ctx(tmp_path, a)).status == ControlStatus.FAIL
    # managed sources -> PASS
    a = AwsCiAnalysis(buildspec_paths=[bs], parameter_store_signal_paths=[bs])
    assert awsev.eval_aws_secret_038(_ctx(tmp_path, a)).status == ControlStatus.PASS
    # no managed, non-strict -> MANUAL
    a = AwsCiAnalysis(buildspec_paths=[bs])
    assert awsev.eval_aws_secret_038(_ctx(tmp_path, a)).status == ControlStatus.MANUAL_REVIEW_REQUIRED
    # no managed, strict profile -> FAIL
    assert awsev.eval_aws_secret_038(
        _ctx(tmp_path, AwsCiAnalysis(buildspec_paths=[bs]), profile_id="aws-level-2")
    ).status == ControlStatus.FAIL
    # no buildspec -> NA
    assert awsev.eval_aws_secret_038(_ctx(tmp_path, AwsCiAnalysis())).status == ControlStatus.NOT_APPLICABLE


def test_aws_sec_039(tmp_path: Path) -> None:
    bs = _p(tmp_path)
    a = AwsCiAnalysis(buildspec_paths=[bs], security_scan_signal_paths=[bs])
    assert awsev.eval_aws_sec_039(_ctx(tmp_path, a)).status == ControlStatus.PASS
    assert awsev.eval_aws_sec_039(_ctx(tmp_path, AwsCiAnalysis(buildspec_paths=[bs]))).status == ControlStatus.FAIL
    assert awsev.eval_aws_sec_039(_ctx(tmp_path, AwsCiAnalysis())).status == ControlStatus.NOT_APPLICABLE


def test_aws_sca_040(tmp_path: Path) -> None:
    bs = _p(tmp_path)
    a = AwsCiAnalysis(buildspec_paths=[bs], dependency_audit_signal_paths=[bs])
    assert awsev.eval_aws_sca_040(_ctx(tmp_path, a)).status == ControlStatus.PASS
    assert awsev.eval_aws_sca_040(_ctx(tmp_path, AwsCiAnalysis(buildspec_paths=[bs]))).status == ControlStatus.FAIL


def test_aws_sbom_041(tmp_path: Path) -> None:
    bs = _p(tmp_path)
    a = AwsCiAnalysis(buildspec_paths=[bs], sbom_signal_paths=[bs])
    assert awsev.eval_aws_sbom_041(_ctx(tmp_path, a)).status == ControlStatus.PASS
    assert awsev.eval_aws_sbom_041(_ctx(tmp_path, AwsCiAnalysis(buildspec_paths=[bs]))).status == ControlStatus.FAIL


def test_aws_pipe_042(tmp_path: Path) -> None:
    cp = _p(tmp_path, "codepipeline.json")
    a = AwsCiAnalysis(codepipeline_paths=[cp], codepipeline_valid_export_paths=[cp])
    assert awsev.eval_aws_pipe_042(_ctx(tmp_path, a)).status == ControlStatus.PASS
    # exists but not valid structure -> FAIL
    assert awsev.eval_aws_pipe_042(_ctx(tmp_path, AwsCiAnalysis(codepipeline_paths=[cp]))).status == ControlStatus.FAIL
    # none -> FAIL
    assert awsev.eval_aws_pipe_042(_ctx(tmp_path, AwsCiAnalysis())).status == ControlStatus.FAIL


def test_aws_prov_043(tmp_path: Path) -> None:
    bs = _p(tmp_path)
    a = AwsCiAnalysis(buildspec_paths=[bs], provenance_signal_paths=[bs])
    assert awsev.eval_aws_prov_043(_ctx(tmp_path, a)).status == ControlStatus.PASS
    assert awsev.eval_aws_prov_043(_ctx(tmp_path, AwsCiAnalysis())).status == ControlStatus.NOT_APPLICABLE
