"""Branch coverage for file-based governance evaluators (DEP-UPDATE-001, GOV-DISC-013, OSS-SCORECARD-001)."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.evaluators import governance as gov
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, *, scorecard: object = None) -> gov.EvalContext:
    return gov.EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=scorecard,
    )


def _w(tmp_path: Path, rel: str, text: str = "x\n") -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# DEP-UPDATE-001
# --------------------------------------------------------------------------- #


def test_dep_update_dependabot(tmp_path: Path) -> None:
    _w(tmp_path, ".github/dependabot.yml", "version: 2\n")
    assert gov.eval_dep_update_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_dep_update_renovate(tmp_path: Path) -> None:
    _w(tmp_path, "renovate.json", "{}")
    out = gov.eval_dep_update_001(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "Renovate" in out.reason


def test_dep_update_none(tmp_path: Path) -> None:
    assert gov.eval_dep_update_001(_ctx(tmp_path)).status == ControlStatus.FAIL


# --------------------------------------------------------------------------- #
# GOV-DISC-013 (private vulnerability reporting)
# --------------------------------------------------------------------------- #


def test_gov_disc_013_pass(tmp_path: Path) -> None:
    _w(tmp_path, "SECURITY.md", "Please report privately via security@example.com.\n")
    out = gov.eval_gov_disc_013(_ctx(tmp_path))
    assert out.status in {ControlStatus.PASS, ControlStatus.SELF_ATTESTED}


def test_gov_disc_013_no_security_md(tmp_path: Path) -> None:
    out = gov.eval_gov_disc_013(_ctx(tmp_path))
    assert out.status in {ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED}


# --------------------------------------------------------------------------- #
# OSS-SCORECARD-001
# --------------------------------------------------------------------------- #


def test_scorecard_not_evaluated_without_bundle(tmp_path: Path) -> None:
    assert gov.eval_oss_scorecard_001(_ctx(tmp_path)).status == ControlStatus.NOT_EVALUATED


# --------------------------------------------------------------------------- #
# basic governance file evaluators
# --------------------------------------------------------------------------- #


def test_gov_sec_001_present_and_absent(tmp_path: Path) -> None:
    assert gov.eval_gov_sec_001(_ctx(tmp_path)).status in {ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED}
    _w(tmp_path, "SECURITY.md", "# Security Policy\nReport to security@example.com\n")
    assert gov.eval_gov_sec_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_gov_lic_004(tmp_path: Path) -> None:
    assert gov.eval_gov_lic_004(_ctx(tmp_path)).status in {ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED}
    _w(tmp_path, "LICENSE", "MIT License\n")
    assert gov.eval_gov_lic_004(_ctx(tmp_path)).status == ControlStatus.PASS
