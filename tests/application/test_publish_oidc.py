"""PUBLISH-OIDC-001..003 family coverage (PR-9, ADR-014)."""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import (
    EvalContext,
    eval_publish_oidc_001,
    eval_publish_oidc_002,
    eval_publish_oidc_003,
)
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, workflow_paths: list[Path]) -> EvalContext:
    wa = WorkflowAnalysis()
    wa.workflow_paths = workflow_paths
    return EvalContext(
        repo_root=tmp_path,
        profile_id="oss-publish-readiness-1",
        workflows=wa,
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _wf(tmp_path: Path, name: str, body: str) -> Path:
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(body, encoding="utf-8")
    return p


# --- PUBLISH-OIDC-001 ------------------------------------------------------


def test_oidc_001_not_applicable_when_no_workflows(tmp_path: Path) -> None:
    out = eval_publish_oidc_001(_ctx(tmp_path, []))
    assert out.status == ControlStatus.NOT_APPLICABLE


def test_oidc_001_not_applicable_when_no_publish_step(tmp_path: Path) -> None:
    body = (
        "name: ci\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n"
    )
    p = _wf(tmp_path, "ci.yml", body)
    out = eval_publish_oidc_001(_ctx(tmp_path, [p]))
    assert out.status == ControlStatus.NOT_APPLICABLE


def test_oidc_001_fail_when_publish_without_id_token(tmp_path: Path) -> None:
    body = (
        "name: publish\non:\n  push:\n    tags: ['v*']\n"
        "jobs:\n  pypi:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: pypa/gh-action-pypi-publish@release/v1\n"
    )
    p = _wf(tmp_path, "publish.yml", body)
    out = eval_publish_oidc_001(_ctx(tmp_path, [p]))
    assert out.status == ControlStatus.FAIL
    assert "id-token: write" in out.reason


def test_oidc_001_pass_with_id_token_write(tmp_path: Path) -> None:
    body = (
        "name: publish\non:\n  push:\n    tags: ['v*']\n"
        "jobs:\n  pypi:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      id-token: write\n      contents: read\n"
        "    steps:\n      - uses: pypa/gh-action-pypi-publish@release/v1\n"
    )
    p = _wf(tmp_path, "publish.yml", body)
    out = eval_publish_oidc_001(_ctx(tmp_path, [p]))
    assert out.status == ControlStatus.PASS


# --- PUBLISH-OIDC-002 ------------------------------------------------------


def test_oidc_002_fail_when_npm_token_referenced(tmp_path: Path) -> None:
    body = (
        "name: publish\non: push\njobs:\n  npm:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: npm publish\n"
        "        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
    )
    p = _wf(tmp_path, "publish.yml", body)
    out = eval_publish_oidc_002(_ctx(tmp_path, [p]))
    assert out.status == ControlStatus.FAIL


def test_oidc_002_fail_when_pypi_long_lived_token_referenced(tmp_path: Path) -> None:
    body = (
        "name: publish\non: push\njobs:\n  pypi:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: pypa/gh-action-pypi-publish@release/v1\n"
        "        with:\n          password: ${{ secrets.PYPI_TOKEN }}\n"
    )
    p = _wf(tmp_path, "publish.yml", body)
    out = eval_publish_oidc_002(_ctx(tmp_path, [p]))
    assert out.status == ControlStatus.FAIL


def test_oidc_002_pass_without_long_lived_token(tmp_path: Path) -> None:
    body = (
        "name: publish\non: push\njobs:\n  pypi:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      id-token: write\n"
        "    steps:\n      - uses: pypa/gh-action-pypi-publish@release/v1\n"
    )
    p = _wf(tmp_path, "publish.yml", body)
    out = eval_publish_oidc_002(_ctx(tmp_path, [p]))
    assert out.status == ControlStatus.PASS


# --- PUBLISH-OIDC-003 ------------------------------------------------------


def test_oidc_003_not_applicable_when_no_npm_publish(tmp_path: Path) -> None:
    body = (
        "name: publish\non: push\njobs:\n  pypi:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: pypa/gh-action-pypi-publish@release/v1\n"
    )
    p = _wf(tmp_path, "publish.yml", body)
    out = eval_publish_oidc_003(_ctx(tmp_path, [p]))
    assert out.status == ControlStatus.NOT_APPLICABLE


def test_oidc_003_fail_when_npm_publish_without_provenance(tmp_path: Path) -> None:
    body = (
        "name: publish\non: push\njobs:\n  npm:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      id-token: write\n"
        "    steps:\n      - run: npm publish\n"
    )
    p = _wf(tmp_path, "publish.yml", body)
    out = eval_publish_oidc_003(_ctx(tmp_path, [p]))
    assert out.status == ControlStatus.FAIL


def test_oidc_003_pass_with_provenance_flag(tmp_path: Path) -> None:
    body = (
        "name: publish\non: push\njobs:\n  npm:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      id-token: write\n"
        "    steps:\n      - run: npm publish --provenance\n"
    )
    p = _wf(tmp_path, "publish.yml", body)
    out = eval_publish_oidc_003(_ctx(tmp_path, [p]))
    assert out.status == ControlStatus.PASS


def test_oidc_003_pass_with_provenance_true_action_input(tmp_path: Path) -> None:
    body = (
        "name: publish\non: push\njobs:\n  npm:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      id-token: write\n"
        "    steps:\n      - uses: JS-DevTools/npm-publish@v3\n"
        "        with:\n          provenance: true\n"
        "          token: ${{ secrets.NPM_AUTOMATION_TOKEN }}\n"
        "      - run: npm publish\n"
    )
    p = _wf(tmp_path, "publish.yml", body)
    out = eval_publish_oidc_003(_ctx(tmp_path, [p]))
    assert out.status == ControlStatus.PASS


@pytest.mark.parametrize(
    "fn",
    [eval_publish_oidc_001, eval_publish_oidc_002, eval_publish_oidc_003],
    ids=lambda x: x.__name__,
)
def test_publish_oidc_consistent_not_applicable_without_workflows(fn, tmp_path: Path) -> None:
    out = fn(_ctx(tmp_path, []))
    assert out.status == ControlStatus.NOT_APPLICABLE
