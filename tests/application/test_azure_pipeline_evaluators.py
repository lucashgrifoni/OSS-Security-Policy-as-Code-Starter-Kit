"""Branch coverage for the Azure-Pipelines signal evaluators (AZ-PIPE/SEC/SCA/SBOM)."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.evaluators import azure as az
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, azp: AzurePipelineAnalysis) -> az.EvalContext:
    return az.EvalContext(
        repo_root=tmp_path,
        profile_id="azure-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=azp,
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _pipe(tmp_path: Path, name: str = "azure-pipelines.yml", text: str = "steps: []\n") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_az_pipe_027(tmp_path: Path) -> None:
    p = _pipe(tmp_path)
    assert az.eval_az_pipe_027(_ctx(tmp_path, AzurePipelineAnalysis(pipeline_paths=[p]))).status == ControlStatus.PASS
    assert az.eval_az_pipe_027(_ctx(tmp_path, AzurePipelineAnalysis())).status == ControlStatus.FAIL


def test_az_pipe_028(tmp_path: Path) -> None:
    p = _pipe(tmp_path)
    assert az.eval_az_pipe_028(_ctx(tmp_path, AzurePipelineAnalysis())).status == ControlStatus.NOT_APPLICABLE
    azp = AzurePipelineAnalysis(pipeline_paths=[p], pr_validation_paths=[p])
    assert az.eval_az_pipe_028(_ctx(tmp_path, azp)).status == ControlStatus.PASS
    assert az.eval_az_pipe_028(_ctx(tmp_path, AzurePipelineAnalysis(pipeline_paths=[p]))).status == ControlStatus.FAIL


def test_az_pipe_029_persist_true_fail(tmp_path: Path) -> None:
    p = _pipe(tmp_path)
    azp = AzurePipelineAnalysis(pipeline_paths=[p], persist_credentials_true_paths=[p])
    assert az.eval_az_pipe_029(_ctx(tmp_path, azp)).status == ControlStatus.FAIL


def test_az_pipe_029_explicit_false_pass(tmp_path: Path) -> None:
    p = _pipe(tmp_path, text="steps:\n  - checkout: self\n    persistCredentials: false\n")
    azp = AzurePipelineAnalysis(pipeline_paths=[p])
    assert az.eval_az_pipe_029(_ctx(tmp_path, azp)).status == ControlStatus.PASS


def test_az_pipe_029_default_pass(tmp_path: Path) -> None:
    p = _pipe(tmp_path, text="steps:\n  - script: echo hi\n")
    azp = AzurePipelineAnalysis(pipeline_paths=[p])
    assert az.eval_az_pipe_029(_ctx(tmp_path, azp)).status == ControlStatus.PASS


def test_az_pipe_029_na(tmp_path: Path) -> None:
    assert az.eval_az_pipe_029(_ctx(tmp_path, AzurePipelineAnalysis())).status == ControlStatus.NOT_APPLICABLE


def test_az_pipe_030(tmp_path: Path) -> None:
    p = _pipe(tmp_path)
    assert az.eval_az_pipe_030(_ctx(tmp_path, AzurePipelineAnalysis())).status == ControlStatus.NOT_APPLICABLE
    azp = AzurePipelineAnalysis(pipeline_paths=[p], extends_template_paths=[p])
    assert az.eval_az_pipe_030(_ctx(tmp_path, azp)).status == ControlStatus.PASS
    assert az.eval_az_pipe_030(_ctx(tmp_path, AzurePipelineAnalysis(pipeline_paths=[p]))).status == ControlStatus.FAIL


def test_az_sec_031(tmp_path: Path) -> None:
    p = _pipe(tmp_path)
    assert az.eval_az_sec_031(_ctx(tmp_path, AzurePipelineAnalysis())).status == ControlStatus.NOT_APPLICABLE
    azp = AzurePipelineAnalysis(pipeline_paths=[p], security_scan_signal_paths=[p])
    assert az.eval_az_sec_031(_ctx(tmp_path, azp)).status == ControlStatus.PASS
    assert az.eval_az_sec_031(_ctx(tmp_path, AzurePipelineAnalysis(pipeline_paths=[p]))).status == ControlStatus.FAIL


def test_az_sca_032(tmp_path: Path) -> None:
    p = _pipe(tmp_path)
    azp = AzurePipelineAnalysis(pipeline_paths=[p], dependency_audit_signal_paths=[p])
    assert az.eval_az_sca_032(_ctx(tmp_path, azp)).status == ControlStatus.PASS
    assert az.eval_az_sca_032(_ctx(tmp_path, AzurePipelineAnalysis(pipeline_paths=[p]))).status == ControlStatus.FAIL
    assert az.eval_az_sca_032(_ctx(tmp_path, AzurePipelineAnalysis())).status == ControlStatus.NOT_APPLICABLE


def test_az_sbom_033(tmp_path: Path) -> None:
    p = _pipe(tmp_path)
    azp = AzurePipelineAnalysis(pipeline_paths=[p], sbom_signal_paths=[p])
    assert az.eval_az_sbom_033(_ctx(tmp_path, azp)).status == ControlStatus.PASS
    assert az.eval_az_sbom_033(_ctx(tmp_path, AzurePipelineAnalysis(pipeline_paths=[p]))).status == ControlStatus.FAIL
    assert az.eval_az_sbom_033(_ctx(tmp_path, AzurePipelineAnalysis())).status == ControlStatus.NOT_APPLICABLE
