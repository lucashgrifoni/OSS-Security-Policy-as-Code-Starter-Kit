"""Branch coverage for Azure evidence-backed evaluators AZ-PLAT-034 / AZ-PLAT-035."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import azure as az
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path) -> az.EvalContext:
    return az.EvalContext(
        repo_root=tmp_path,
        profile_id="azure-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _ev(tmp_path: Path, name: str, payload: dict) -> None:
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


_BP_POSTURE_ALL = {
    "minimum_reviewers_enabled": True,
    "build_validation_enabled": True,
    "comment_resolution_required": True,
    "reset_votes_on_push": True,
    "block_last_pusher_approval": True,
    "bypass_policy_restricted": True,
}


def _bp_evidence(*, posture: dict, api: bool, support_ok: bool = True) -> dict:
    d = {
        "schema_version": "azure-branch-policies/v1",
        "attested_at": "2026-05-01",
        "attested_by": "azure-devops-api-collection" if api else "platform team",
        "project": "Proj",
        "repository": "repo",
        "branch": "main",
        "posture": posture,
    }
    if api:
        d["posture_support"] = {"policies_api_reachable": support_ok}
    return d


def test_plat_034_missing(tmp_path: Path) -> None:
    assert az.eval_az_plat_034(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_plat_034_self_attested_manual(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-branch-policies.json", _bp_evidence(posture=_BP_POSTURE_ALL, api=False))
    assert az.eval_az_plat_034(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_plat_034_missing_setting(tmp_path: Path) -> None:
    posture = dict(_BP_POSTURE_ALL)
    posture["build_validation_enabled"] = False
    _ev(tmp_path, "azure-branch-policies.json", _bp_evidence(posture=posture, api=False))
    assert az.eval_az_plat_034(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_plat_034_api_pass(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-branch-policies.json", _bp_evidence(posture=_BP_POSTURE_ALL, api=True, support_ok=True))
    assert az.eval_az_plat_034(_ctx(tmp_path)).status == ControlStatus.PASS


def test_plat_034_api_incomplete_support(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-branch-policies.json", _bp_evidence(posture=_BP_POSTURE_ALL, api=True, support_ok=False))
    assert az.eval_az_plat_034(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# AZ-PLAT-035
# --------------------------------------------------------------------------- #

_GOV_POSTURE_ALL = {
    "approvals_required": True,
    "environment_checks_enabled": True,
    "service_connection_restricted": True,
    "federated_identity_preferred": True,
}
_GOV_SUPPORT = {
    "pipelines_api_reachable": True,
    "environments_api_reachable": True,
    "service_endpoints_api_verified": True,
    "environment_approval_checks_observable": True,
}


def _gov_evidence(*, posture: dict, api: bool, support: dict | None = None) -> dict:
    d = {
        "schema_version": "azure-pipeline-governance/v1",
        "attested_at": "2026-05-01",
        "attested_by": "azure-devops-api-collection" if api else "platform team",
        "project": "Proj",
        "posture": posture,
    }
    if api:
        d["posture_support"] = support if support is not None else _GOV_SUPPORT
    return d


def test_plat_035_missing(tmp_path: Path) -> None:
    assert az.eval_az_plat_035(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_plat_035_self_attested(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-pipeline-governance.json", _gov_evidence(posture=_GOV_POSTURE_ALL, api=False))
    assert az.eval_az_plat_035(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_plat_035_missing_setting(tmp_path: Path) -> None:
    posture = dict(_GOV_POSTURE_ALL)
    posture["approvals_required"] = False
    _ev(tmp_path, "azure-pipeline-governance.json", _gov_evidence(posture=posture, api=False))
    assert az.eval_az_plat_035(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_plat_035_api_pass(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-pipeline-governance.json", _gov_evidence(posture=_GOV_POSTURE_ALL, api=True))
    assert az.eval_az_plat_035(_ctx(tmp_path)).status == ControlStatus.PASS


def test_plat_035_api_incomplete(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "azure-pipeline-governance.json",
        _gov_evidence(posture=_GOV_POSTURE_ALL, api=True, support={"pipelines_api_reachable": True}),
    )
    assert az.eval_az_plat_035(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# AZ-IDENT-036 (reads azure-pipeline-governance.json)
# --------------------------------------------------------------------------- #


def test_ident_036_api_pass(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-pipeline-governance.json", _gov_evidence(posture=_GOV_POSTURE_ALL, api=True))
    assert az.eval_az_ident_036(_ctx(tmp_path)).status == ControlStatus.PASS


def test_ident_036_self_attested_federated(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-pipeline-governance.json", _gov_evidence(posture=_GOV_POSTURE_ALL, api=False))
    assert az.eval_az_ident_036(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_ident_036_self_attested_not_federated(tmp_path: Path) -> None:
    posture = dict(_GOV_POSTURE_ALL)
    posture["federated_identity_preferred"] = False
    _ev(tmp_path, "azure-pipeline-governance.json", _gov_evidence(posture=posture, api=False))
    assert az.eval_az_ident_036(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_ident_036_api_incomplete_support(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "azure-pipeline-governance.json",
        _gov_evidence(posture=_GOV_POSTURE_ALL, api=True, support={"pipelines_api_reachable": True}),
    )
    assert az.eval_az_ident_036(_ctx(tmp_path)).status in {
        ControlStatus.MANUAL_REVIEW_REQUIRED,
        ControlStatus.NOT_APPLICABLE,
    }


def test_ident_036_not_applicable_no_evidence(tmp_path: Path) -> None:
    assert az.eval_az_ident_036(_ctx(tmp_path)).status == ControlStatus.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# AZ-SCONN-056 (service connection authentication posture)
# --------------------------------------------------------------------------- #


def _gov_with_conns(conns: list[dict], *, api: bool) -> dict:
    d = _gov_evidence(posture=_GOV_POSTURE_ALL, api=api)
    d["service_connections"] = conns
    return d


def test_sconn_056_missing(tmp_path: Path) -> None:
    assert az.eval_az_sconn_056(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_sconn_056_no_inventory(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-pipeline-governance.json", _gov_evidence(posture=_GOV_POSTURE_ALL, api=True))
    assert az.eval_az_sconn_056(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_sconn_056_unknown_auth_not_evaluated(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "azure-pipeline-governance.json",
        _gov_with_conns([{"name": "c", "authentication": "unknown"}], api=True),
    )
    assert az.eval_az_sconn_056(_ctx(tmp_path)).status == ControlStatus.NOT_EVALUATED


def test_sconn_056_secret_self_attested(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "azure-pipeline-governance.json",
        _gov_with_conns([{"name": "c", "authentication": "secret"}], api=False),
    )
    assert az.eval_az_sconn_056(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_sconn_056_api_pass(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "azure-pipeline-governance.json",
        _gov_with_conns([{"name": "c", "authentication": "managed_identity"}], api=True),
    )
    assert az.eval_az_sconn_056(_ctx(tmp_path)).status == ControlStatus.PASS


def test_sconn_056_manual_self_attested(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "azure-pipeline-governance.json",
        _gov_with_conns([{"name": "c", "authentication": "managed_identity"}], api=False),
    )
    assert az.eval_az_sconn_056(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


# --------------------------------------------------------------------------- #
# AZ-WIFEV-057 (workload identity federation evidence)
# --------------------------------------------------------------------------- #

_WIF_COMPLETE = {
    "name": "wif",
    "authentication": "workload_identity_federation",
    "federation_subject": "repo:org/repo:ref:refs/heads/main",
    "issuer_url": "https://vstoken.dev.azure.com/x",
    "audience": "api://AzureADTokenExchange",
}


def test_wifev_057_missing(tmp_path: Path) -> None:
    assert az.eval_az_wifev_057(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_wifev_057_fail_not_preferred(tmp_path: Path) -> None:
    posture = dict(_GOV_POSTURE_ALL)
    posture["federated_identity_preferred"] = False
    _ev(tmp_path, "azure-pipeline-governance.json", _gov_evidence(posture=posture, api=True))
    assert az.eval_az_wifev_057(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_wifev_057_incomplete_proof(tmp_path: Path) -> None:
    conn = {"name": "wif", "authentication": "workload_identity_federation", "federation_subject": "<TODO>"}
    _ev(tmp_path, "azure-pipeline-governance.json", _gov_with_conns([conn], api=True))
    assert az.eval_az_wifev_057(_ctx(tmp_path)).status == ControlStatus.NOT_EVALUATED


def test_wifev_057_pass_complete(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-pipeline-governance.json", _gov_with_conns([_WIF_COMPLETE], api=True))
    assert az.eval_az_wifev_057(_ctx(tmp_path)).status == ControlStatus.PASS


def test_wifev_057_pass_no_wif_conn_warns(tmp_path: Path) -> None:
    # federated preferred true but no WIF connection entry -> PASS with operational warning.
    _ev(
        tmp_path,
        "azure-pipeline-governance.json",
        _gov_with_conns([{"name": "c", "authentication": "managed_identity"}], api=False),
    )
    out = az.eval_az_wifev_057(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.operational_warnings
