"""Branch coverage for ``evaluators/cicd.py`` (gitignore, pinlock, wfcallsha, semgrep)."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import cicd
from oss_policy_kit.application.evaluators._shared import _SAST_SEMGREP_SCHEMA_PREFIX
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, *, workflow_paths: list[Path] | None = None) -> cicd.EvalContext:
    return cicd.EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-2",
        workflows=WorkflowAnalysis(workflow_paths=workflow_paths or []),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write(tmp_path: Path, rel: str, text: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _semgrep_evidence(tmp_path: Path, payload: dict) -> None:
    _write(tmp_path, ".oss-policy-kit/evidence/sast-semgrep.json", json.dumps(payload))


# --------------------------------------------------------------------------- #
# gitignore_051 / pinlock_052
# --------------------------------------------------------------------------- #


def test_gitignore_051_pass_and_no_patterns(tmp_path: Path) -> None:
    _write(tmp_path, ".gitignore", ".env\n*.pem\n")
    assert cicd.eval_sec_gitignore_051(_ctx(tmp_path)).status == ControlStatus.PASS
    _write(tmp_path, ".gitignore", "build/\n")
    assert cicd.eval_sec_gitignore_051(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_gitignore_051_missing(tmp_path: Path) -> None:
    assert cicd.eval_sec_gitignore_051(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_pinlock_052_go_missing_and_present(tmp_path: Path) -> None:
    _write(tmp_path, "go.mod", "module x\n")
    assert cicd.eval_sec_pinlock_052(_ctx(tmp_path)).status == ControlStatus.FAIL
    _write(tmp_path, "go.sum", "x h1:abc\n")
    assert cicd.eval_sec_pinlock_052(_ctx(tmp_path)).status == ControlStatus.PASS


def test_pinlock_052_not_applicable(tmp_path: Path) -> None:
    assert cicd.eval_sec_pinlock_052(_ctx(tmp_path)).status == ControlStatus.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# wfcallsha_055
# --------------------------------------------------------------------------- #


def test_wfcallsha_055_structured_pass(tmp_path: Path) -> None:
    sha = "a" * 40
    wf = _write(
        tmp_path,
        ".github/workflows/ci.yml",
        f"on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/reusable.yml@{sha}\n",
    )
    assert cicd.eval_ci_wfcallsha_055(_ctx(tmp_path, workflow_paths=[wf])).status == ControlStatus.PASS


def test_wfcallsha_055_structured_fail(tmp_path: Path) -> None:
    wf = _write(
        tmp_path,
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  call:\n    uses: org/repo/.github/workflows/reusable.yml@v1\n",
    )
    assert cicd.eval_ci_wfcallsha_055(_ctx(tmp_path, workflow_paths=[wf])).status == ControlStatus.FAIL


def test_wfcallsha_055_regex_fallback_on_bad_yaml(tmp_path: Path) -> None:
    # Invalid YAML forces the regex fallback path; ref is an unpinned reusable workflow.
    wf = _write(
        tmp_path,
        ".github/workflows/ci.yml",
        "uses: org/repo/.github/workflows/reusable.yml@main\n: : : not valid yaml : [\n",
    )
    out = cicd.eval_ci_wfcallsha_055(_ctx(tmp_path, workflow_paths=[wf]))
    assert out.status == ControlStatus.FAIL


def test_wfcallsha_055_no_reusable_calls(tmp_path: Path) -> None:
    wf = _write(
        tmp_path, ".github/workflows/ci.yml", "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
    )
    assert cicd.eval_ci_wfcallsha_055(_ctx(tmp_path, workflow_paths=[wf])).status == ControlStatus.NOT_APPLICABLE


def test_wfcallsha_055_no_workflows(tmp_path: Path) -> None:
    assert cicd.eval_ci_wfcallsha_055(_ctx(tmp_path)).status == ControlStatus.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# semgrep_064 (all status branches)
# --------------------------------------------------------------------------- #


def _base(**over: object) -> dict:
    d = {
        "schema_version": f"{_SAST_SEMGREP_SCHEMA_PREFIX}v1",
        "status": "ok",
        "findings_total": 0,
        "findings_by_severity": {},
    }
    d.update(over)
    return d


def test_semgrep_064_missing(tmp_path: Path) -> None:
    assert cicd.eval_sast_semgrep_064(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_semgrep_064_unparseable(tmp_path: Path) -> None:
    _write(tmp_path, ".oss-policy-kit/evidence/sast-semgrep.json", "{not json")
    assert cicd.eval_sast_semgrep_064(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_semgrep_064_bad_schema(tmp_path: Path) -> None:
    _semgrep_evidence(tmp_path, _base(schema_version="other/v9"))
    assert cicd.eval_sast_semgrep_064(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_semgrep_064_not_available(tmp_path: Path) -> None:
    _semgrep_evidence(tmp_path, _base(status="not_available"))
    assert cicd.eval_sast_semgrep_064(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_semgrep_064_timeout(tmp_path: Path) -> None:
    _semgrep_evidence(tmp_path, _base(status="timeout"))
    assert cicd.eval_sast_semgrep_064(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_semgrep_064_fail_on_high(tmp_path: Path) -> None:
    _semgrep_evidence(tmp_path, _base(findings_total=3, findings_by_severity={"ERROR": 2, "CRITICAL": 1}))
    assert cicd.eval_sast_semgrep_064(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_semgrep_064_pass(tmp_path: Path) -> None:
    _semgrep_evidence(tmp_path, _base(findings_total=1, findings_by_severity={"INFO": 1}))
    assert cicd.eval_sast_semgrep_064(_ctx(tmp_path)).status == ControlStatus.PASS
