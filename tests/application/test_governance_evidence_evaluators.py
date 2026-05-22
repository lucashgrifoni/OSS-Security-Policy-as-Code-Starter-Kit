"""Branch coverage for governance evidence/workflow evaluators (SCANNER-INTEGRITY-001, ORG-MFA-001)."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import governance as gov
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, *, workflow_paths: list[Path] | None = None) -> gov.EvalContext:
    return gov.EvalContext(
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


def _ev(tmp_path: Path, payload: dict) -> None:
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / "org-mfa-posture.json").write_text(json.dumps(payload), encoding="utf-8")


# --------------------------------------------------------------------------- #
# SCANNER-INTEGRITY-001
# --------------------------------------------------------------------------- #


def test_scanner_integrity_na_no_workflows(tmp_path: Path) -> None:
    assert gov.eval_scanner_integrity_001(_ctx(tmp_path)).status == ControlStatus.NOT_APPLICABLE


def test_scanner_integrity_na_no_scanner(tmp_path: Path) -> None:
    wf = _wf(tmp_path, "ci.yml", "steps:\n  - uses: actions/checkout@v4\n")
    assert gov.eval_scanner_integrity_001(_ctx(tmp_path, workflow_paths=[wf])).status == ControlStatus.NOT_APPLICABLE


def test_scanner_integrity_pass_pinned(tmp_path: Path) -> None:
    sha = "a" * 40
    wf = _wf(tmp_path, "scan.yml", f"steps:\n  - uses: aquasecurity/trivy-action@{sha}\n")
    assert gov.eval_scanner_integrity_001(_ctx(tmp_path, workflow_paths=[wf])).status == ControlStatus.PASS


def test_scanner_integrity_fail_unpinned(tmp_path: Path) -> None:
    wf = _wf(tmp_path, "scan.yml", "steps:\n  - uses: aquasecurity/trivy-action@v0.20.0\n")
    assert gov.eval_scanner_integrity_001(_ctx(tmp_path, workflow_paths=[wf])).status == ControlStatus.FAIL


# --------------------------------------------------------------------------- #
# ORG-MFA-001
# --------------------------------------------------------------------------- #


def _mfa(*, all_members: bool, admins: bool = True, scope: str = "all_members", api: bool = False) -> dict:
    return {
        "schema_version": "org-mfa-posture/v1",
        "attested_at": "2026-05-01",
        "attested_by": "github-api-collection" if api else "platform team",
        "org_name": "acme",
        "platform": "github",
        "mfa_required_for_all_members": all_members,
        "mfa_required_for_admins": admins,
        "sso_enforced": True,
        "enforcement_scope": scope,
    }


def test_org_mfa_missing_evidence(tmp_path: Path) -> None:
    assert gov.eval_org_mfa_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_org_mfa_fail_members_off(tmp_path: Path) -> None:
    _ev(tmp_path, _mfa(all_members=False, admins=True))
    assert gov.eval_org_mfa_001(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_org_mfa_partial_scope_manual(tmp_path: Path) -> None:
    _ev(tmp_path, _mfa(all_members=True, scope="admins_only"))
    assert gov.eval_org_mfa_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_org_mfa_api_pass(tmp_path: Path) -> None:
    _ev(tmp_path, _mfa(all_members=True, scope="all_members", api=True))
    assert gov.eval_org_mfa_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_org_mfa_self_attested(tmp_path: Path) -> None:
    _ev(tmp_path, _mfa(all_members=True, scope="all_members", api=False))
    assert gov.eval_org_mfa_001(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED
