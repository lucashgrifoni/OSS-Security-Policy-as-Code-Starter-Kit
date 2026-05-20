"""GH-EGRESS-HRN-001 + PROV-VERIFY-061 verification.source enum coverage (PR-7)."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import (
    EvalContext,
    eval_gh_egress_hrn_001,
    eval_prov_verify_061,
)
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, *, workflow_paths: list[Path] | None = None) -> EvalContext:
    wa = WorkflowAnalysis()
    if workflow_paths:
        wa.workflow_paths = workflow_paths
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-2",
        workflows=wa,
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _wf(tmp_path: Path, name: str, body: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / name
    p.write_text(body, encoding="utf-8")
    return p


# --- GH-EGRESS-HRN-001 -----------------------------------------------------


def test_gh_egress_not_applicable_when_no_workflows(tmp_path: Path) -> None:
    out = eval_gh_egress_hrn_001(_ctx(tmp_path))
    assert out.status == ControlStatus.NOT_APPLICABLE


def test_gh_egress_fail_when_no_harden_runner(tmp_path: Path) -> None:
    body = (
        "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n"
    )
    p = _wf(tmp_path, "ci.yml", body)
    out = eval_gh_egress_hrn_001(_ctx(tmp_path, workflow_paths=[p]))
    assert out.status == ControlStatus.FAIL
    assert "Harden-Runner" in out.reason


def test_gh_egress_pass_when_step_security_action_present(tmp_path: Path) -> None:
    p = _wf(
        tmp_path,
        "release.yml",
        (
            "name: release\non: [push]\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: step-security/harden-runner@v2.11.1\n"
            "        with:\n          egress-policy: audit\n"
            "      - uses: actions/checkout@v4\n"
        ),
    )
    out = eval_gh_egress_hrn_001(_ctx(tmp_path, workflow_paths=[p]))
    assert out.status == ControlStatus.PASS
    assert "1 of 1" in out.reason


def test_gh_egress_partial_match_pass(tmp_path: Path) -> None:
    """Even one workflow with Harden-Runner passes — the gate is presence, not coverage."""
    p1 = _wf(tmp_path, "ci.yml", "name: ci\nsteps:\n  - uses: actions/checkout@v4\n")
    p2 = _wf(
        tmp_path,
        "release.yml",
        "name: release\nsteps:\n  - uses: step-security/harden-runner@v2\n",
    )
    out = eval_gh_egress_hrn_001(_ctx(tmp_path, workflow_paths=[p1, p2]))
    assert out.status == ControlStatus.PASS
    assert "1 of 2" in out.reason


# --- PROV-VERIFY-061: verification.source surfacing -------------------------


_FRESH_TS = "2026-05-01T12:00:00Z"


def _gh_payload_with_source(source: str | None) -> dict:
    payload = {
        "schema_version": "github-provenance-artifact/v1",
        "attested_at": "2026-04-21",
        "attested_by": "release-bot",
        "artifact": {
            "uri": "https://github.com/example-org/example-repo/releases/download/v1/example.tgz",
            "digest_sha256": "e7c2a4d8f1b6c9d2e5a8b1c4d7e0f3a6b9c2d5e8f1a4b7c0d3e6f9a2b5c8d1e4",
        },
        "attestation": {
            "kind": "github-artifact-attestation",
            "digest_sha256": "b3a6c9d2e5f8a1b4c7d0e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0a3b6",
        },
        "posture": {
            "attestation_covers_release_artifact": True,
            "attestation_digest_recorded": True,
            "artifact_digest_recorded": True,
        },
        "verification": {
            "method": "gh-attestation-verify",
            "verified_at": _FRESH_TS,
            "transparency_log_inclusion": True,
        },
    }
    if source is not None:
        payload["verification"]["source"] = source
    return payload


def _write_evidence(tmp_path: Path, filename: str, payload: dict) -> Path:
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    p = d / filename
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _ctx_for_prov(tmp_path: Path) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-release-hardening-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def test_prov_verify_pass_without_source_field_is_backward_compatible(tmp_path: Path) -> None:
    """A verification block without 'source' still passes; reason omits the source suffix."""
    _write_evidence(tmp_path, "github-provenance-artifact.json", _gh_payload_with_source(None))
    out = eval_prov_verify_061(_ctx_for_prov(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "source=" not in out.reason


def test_prov_verify_pass_surfaces_source_when_present(tmp_path: Path) -> None:
    """A verification block with 'source: pypi-trusted-publishing' surfaces in the reason."""
    _write_evidence(
        tmp_path,
        "github-provenance-artifact.json",
        _gh_payload_with_source("pypi-trusted-publishing"),
    )
    out = eval_prov_verify_061(_ctx_for_prov(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "source=pypi-trusted-publishing" in out.reason


def test_prov_verify_pass_surfaces_github_attestation_source(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "github-provenance-artifact.json",
        _gh_payload_with_source("github-attestation"),
    )
    out = eval_prov_verify_061(_ctx_for_prov(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "source=github-attestation" in out.reason
