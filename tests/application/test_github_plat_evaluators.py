"""Branch coverage for GitHub evidence-backed platform evaluators GH-PLAT-024 / GH-PLAT-026."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import github as gh
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path) -> gh.EvalContext:
    return gh.EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _ev(tmp_path: Path, name: str, payload: dict) -> None:
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


_RULESETS_ALL = {
    "require_pull_request": True,
    "require_status_checks": True,
    "restrict_force_push": True,
    "require_code_owner_review": True,
}
_SS_ALL = {"secret_scanning_enabled": True, "push_protection_enabled": True, "validity_checks_enabled": True}


def _rulesets_ev(posture: dict, *, api: bool) -> dict:
    return {
        "schema_version": "github-rulesets/v1",
        "attested_at": "2026-05-01",
        "attested_by": "github-api-collection" if api else "platform team",
        "repository": "o/r",
        "posture": posture,
    }


def _ss_ev(posture: dict, *, api: bool) -> dict:
    return {
        "schema_version": "github-secret-scanning/v1",
        "attested_at": "2026-05-01",
        "attested_by": "github-api-collection" if api else "platform team",
        "repository": "o/r",
        "posture": posture,
    }


# --------------------------------------------------------------------------- #
# GH-PLAT-024 rulesets
# --------------------------------------------------------------------------- #


def test_plat_024_not_evaluated(tmp_path: Path) -> None:
    assert gh.eval_gh_plat_024(_ctx(tmp_path)).status == ControlStatus.NOT_EVALUATED


def test_plat_024_pass_api(tmp_path: Path) -> None:
    _ev(tmp_path, "github-rulesets.json", _rulesets_ev(_RULESETS_ALL, api=True))
    assert gh.eval_gh_plat_024(_ctx(tmp_path)).status == ControlStatus.PASS


def test_plat_024_pass_manual(tmp_path: Path) -> None:
    _ev(tmp_path, "github-rulesets.json", _rulesets_ev(_RULESETS_ALL, api=False))
    assert gh.eval_gh_plat_024(_ctx(tmp_path)).status == ControlStatus.PASS


def test_plat_024_fail_missing_flag(tmp_path: Path) -> None:
    posture = dict(_RULESETS_ALL)
    posture["restrict_force_push"] = False
    _ev(tmp_path, "github-rulesets.json", _rulesets_ev(posture, api=True))
    assert gh.eval_gh_plat_024(_ctx(tmp_path)).status == ControlStatus.FAIL


# --------------------------------------------------------------------------- #
# GH-PLAT-026 secret scanning
# --------------------------------------------------------------------------- #


def test_plat_026_not_evaluated(tmp_path: Path) -> None:
    assert gh.eval_gh_plat_026(_ctx(tmp_path)).status == ControlStatus.NOT_EVALUATED


def test_plat_026_pass(tmp_path: Path) -> None:
    _ev(tmp_path, "github-secret-scanning.json", _ss_ev(_SS_ALL, api=True))
    assert gh.eval_gh_plat_026(_ctx(tmp_path)).status == ControlStatus.PASS


def test_plat_026_fail_missing_flag(tmp_path: Path) -> None:
    posture = dict(_SS_ALL)
    posture["push_protection_enabled"] = False
    _ev(tmp_path, "github-secret-scanning.json", _ss_ev(posture, api=False))
    assert gh.eval_gh_plat_026(_ctx(tmp_path)).status in {ControlStatus.FAIL, ControlStatus.SELF_ATTESTED}
